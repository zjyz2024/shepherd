package output

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"sync"
	"time"

	"github.com/cen-ngc5139/shepherd/internal/cache"
	"github.com/cen-ngc5139/shepherd/internal/log"
	"github.com/cen-ngc5139/shepherd/internal/metadata"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
)

// allocTrackerEventRaw 与 trace.c 的 struct alloc_tracker_event_t 严格对齐
type allocTrackerEventRaw struct {
	Ts        uint64
	Pid       uint32
	Addr      uint64
	Size      uint32
	IsAlloc   uint32 // 1 = alloc, 0 = free
	Pad0      uint32
	StackId   int32
	Pad1      uint32
}

// ProcessMemLeakEvents 读取 BPF kmalloc/kfree 采样事件
// 采样率 1/32，写入内存中的 alloc_tracker 映射
func ProcessMemLeakEvents(coll *ebpf.Collection, ctx context.Context) {
	leakEvents := coll.Maps["mem_leak_events"]
	if leakEvents == nil {
		log.Warningf("mem_leak_events map not found in BPF collection")
		return
	}

	reader, err := perf.NewReader(leakEvents, os.Getpagesize())
	if err != nil {
		log.Errorf("failed to create mem_leak event reader: %v", err)
		return
	}
	defer reader.Close()

	var raw allocTrackerEventRaw

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		record, err := reader.Read()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				log.Warningf("read mem_leak_events error: %v", err)
				continue
			}
		}

		if record.LostSamples > 0 {
			log.Warningf("mem_leak_events lost %d samples", record.LostSamples)
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &raw); err != nil {
			log.Warningf("parse mem_leak_event error: %v", err)
			continue
		}

		aggregateMemLeakEvent(&raw)
	}
}

// allocInfoTracker 内存中维护的分配追踪记录
// key = addr (uint64)
// value = allocInfo
type allocInfo struct {
	size    uint32
	ts      uint64
	stackId int32
}

var (
	allocTrackerMu sync.RWMutex
	allocTracker   map[uint64]allocInfo = make(map[uint64]allocInfo)
)

// aggregateMemLeakEvent 处理单条分配/释放事件，更新内存中的追踪表
func aggregateMemLeakEvent(raw *allocTrackerEventRaw) {
	allocTrackerMu.Lock()
	defer allocTrackerMu.Unlock()

	if raw.IsAlloc == 1 {
		// alloc: 记录分配信息
		allocTracker[raw.Addr] = allocInfo{
			size:    raw.Size,
			ts:      raw.Ts,
			stackId: raw.StackId,
		}
	} else {
		// free: 删除记录
		delete(allocTracker, raw.Addr)
	}
}

// RunLeakScanner 定期扫描 allocTracker，聚合为 MemLeakSuspectMap
// interval：扫描周期，建议 60s
func RunLeakScanner(coll *ebpf.Collection, ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	stackMap := coll.Maps["stack_traces"]
	if stackMap == nil {
		log.Warningf("stack_traces map not found; leak symbol resolution disabled")
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			scanAndAggregateLeaks(stackMap)
		}
	}
}

// scanAndAggregateLeaks 扫描当前 allocTracker，按 stack_id 聚合为疑似泄漏
func scanAndAggregateLeaks(stackMap *ebpf.Map) {
	allocTrackerMu.RLock()

	now := time.Now().UnixNano()

	// 按 stack_id 分组求和
	stackAgg := make(map[int32]struct {
		totalBytes  uint64
		allocCount  uint64
		oldestTs    uint64
		newestTs    uint64
	})

	for _, info := range allocTracker {
		s := stackAgg[info.stackId]
		s.totalBytes += uint64(info.size)
		s.allocCount++
		if s.oldestTs == 0 || info.ts < s.oldestTs {
			s.oldestTs = info.ts
		}
		if info.ts > s.newestTs {
			s.newestTs = info.ts
		}
		stackAgg[info.stackId] = s
	}

	allocTrackerMu.RUnlock()

	// 评估泄漏置信度 + 获取符号
	for stackId, agg := range stackAgg {
		ageSec := float64(now-int64(agg.oldestTs)) / 1e9
		score := evaluateSuspectScore(agg.totalBytes, agg.allocCount, ageSec)

		symbolNames := ""
		if stackMap != nil {
			symbolNames = getStackSymbolNames(int32(stackId), stackMap)
		}

		suspect := metadata.MemLeakSuspect{
			StackId:        int32(stackId),
			TotalBytes:     agg.totalBytes,
			AllocCount:     agg.allocCount,
			FirstSeenTs:    agg.oldestTs,
			LastSeenTs:     agg.newestTs,
			SuspectScore:   score,
			TopSymbolNames: symbolNames,
		}

		cache.MemLeakSuspectMap.Store(int32(stackId), suspect)

		// TODO: 如果 score > 0.5，写入 ClickHouse
	}
}

// evaluateSuspectScore 计算泄漏置信度
// 评分标准：
// - 分配总字节数大 (+score)
// - 存活时间长 (+score)
// - 分配次数多 (+score)
// 返回 [0, 1]
func evaluateSuspectScore(totalBytes uint64, allocCount uint64, ageSec float64) float64 {
	score := 0.0

	// 因子 1：分配总大小（>10MB 判定为可疑）
	if totalBytes > 10*1024*1024 {
		score += 0.4
	} else if totalBytes > 1*1024*1024 {
		score += 0.2
	}

	// 因子 2：存活时间（>300s 判定为可疑）
	if ageSec > 300 {
		score += 0.4
	} else if ageSec > 60 {
		score += 0.2
	}

	// 因子 3：分配频率（每秒 >100 次判定为可疑）
	allocPerSec := float64(allocCount) / (ageSec + 1)
	if allocPerSec > 100 {
		score += 0.2
	}

	if score > 1.0 {
		score = 1.0
	}
	return score
}

// getStackSymbolNames 从 stack_traces map 读取符号，返回前 3 个用 "->" 连接
func getStackSymbolNames(stackID int32, stackMap *ebpf.Map) string {
	if stackID <= 0 || stackMap == nil {
		return "-"
	}

	var addresses [127]uint64
	if err := stackMap.Lookup(uint32(stackID), &addresses); err != nil {
		return "-"
	}

	var syms []string
	for _, addr := range addresses {
		if addr == 0 {
			break
		}
		syms = append(syms, ResolveSymbol(addr))
	}

	if len(syms) == 0 {
		return "-"
	}

	displayLen := 3
	if len(syms) < displayLen {
		displayLen = len(syms)
	}

	// 用 "->" 连接
	result := ""
	for i := 0; i < displayLen; i++ {
		if i > 0 {
			result += "->"
		}
		result += syms[i]
	}
	return result
}
