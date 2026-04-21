package output

import (
	"context"
	"os"
	"sync"

	"github.com/cen-ngc5139/shepherd/internal/binary"
	"github.com/cen-ngc5139/shepherd/internal/cache"
	"github.com/cen-ngc5139/shepherd/internal/log"
	"github.com/cen-ngc5139/shepherd/internal/metadata"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
)

// Phase 2: Off-CPU 堆栈缓存
type OffCPUStack struct {
	Pid              uint32
	KernelStackID    int32
	TotalOffCPUTimeNs uint64
	Count            uint32
	LastUpdateTs     uint64
}

var (
	// 缓存：按 PID 存储 Off-CPU 堆栈
	offCPUStackCache sync.Map // key: PID, value: OffCPUStack
	// 记录上次入场时间（用于计算 Off-CPU 时间）
	lastOffCPUTime sync.Map // key: PID, value: uint64
)

func ProcessOffCPU(coll *ebpf.Collection, ctx context.Context) {
	// 获取 Off-CPU 事件流
	offCPUEvents := coll.Maps["off_cpu_events"]
	if offCPUEvents == nil {
		log.Warnf("off_cpu_events map not found in BPF collection")
		return
	}

	perfReader, err := perf.NewReader(offCPUEvents, os.Getpagesize())
	if err != nil {
		log.Errorf("failed to create off_cpu event reader: %v", err)
		return
	}

	defer perfReader.Close()

	var event binary.ShepherdOffCpuEventT
	for {
		select {
		case <-ctx.Done():
			log.Info("停止 Off-CPU 事件处理")
			return
		default:
			// 读取 Off-CPU 事件
			record, err := perfReader.Read()
			if err != nil {
				log.Errorf("failed to read off_cpu event: %v", err)
				continue
			}

			// 解析二进制数据
			if err := event.UnmarshalBinary(record.RawSample); err != nil {
				log.Errorf("failed to unmarshal off_cpu event: %v", err)
				continue
			}

			// 记录离开 CPU 的时间
			lastOffCPUTime.Store(event.Pid, event.TsLeave)

			// 更新或创建 Off-CPU 堆栈缓存
			updateOffCPUStack(event)

			// 同步到调度指标中
			syncOffCPUToMetrics(event.Pid)
		}
	}
}

func updateOffCPUStack(event binary.ShepherdOffCpuEventT) {
	pid := event.Pid

	// 查询现有堆栈数据
	existing, exists := offCPUStackCache.Load(pid)
	if !exists {
		// 首次创建
		stack := OffCPUStack{
			Pid:            pid,
			KernelStackID:  event.KernelStackId,
			Count:          1,
			LastUpdateTs:   event.TsLeave,
		}
		offCPUStackCache.Store(pid, stack)
		return
	}

	stack := existing.(OffCPUStack)

	// 如果堆栈 ID 相同，累加计数和时间
	if stack.KernelStackID == event.KernelStackId {
		stack.Count++
		stack.LastUpdateTs = event.TsLeave
		offCPUStackCache.Store(pid, stack)
	}
	// 否则只更新（实际生产中可能需要维护多个堆栈）
}

func syncOffCPUToMetrics(pid uint32) {
	// 从缓存中查找该进程
	val, exists := cache.SchedMetricsMap.Load(pid)
	if !exists {
		return
	}

	metrics := val.(metadata.SchedMetrics)

	// 查找 Off-CPU 堆栈数据
	offCPU, stackExists := offCPUStackCache.Load(pid)
	if stackExists {
		offCPUStack := offCPU.(OffCPUStack)
		metrics.OffCPUEventCount = offCPUStack.Count
		metrics.OffCPUTimeNs += 1000000 // 粗略估算，每次采样记 1ms（实际应该通过 sched_switch 重新入场计算）
	}

	cache.SchedMetricsMap.Store(pid, metrics)
}

// 清理函数：清空 Off-CPU 缓存
func ClearOffCPUCache() {
	offCPUStackCache.Range(func(key, value interface{}) bool {
		offCPUStackCache.Delete(key)
		return true
	})
	lastOffCPUTime.Range(func(key, value interface{}) bool {
		lastOffCPUTime.Delete(key)
		return true
	})
}

// 获取进程的实际 Off-CPU 时间（从离开到现在）
func GetOffCPUDuration(pid uint32, now uint64) uint64 {
	lastLeaveVal, exists := lastOffCPUTime.Load(pid)
	if !exists {
		return 0
	}

	lastLeave := lastLeaveVal.(uint64)
	if now > lastLeave {
		return now - lastLeave
	}
	return 0
}
