package output

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"sync"

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
		log.Warningf("off_cpu_events map not found in BPF collection")
		return
	}

	perfReader, err := perf.NewReader(offCPUEvents, os.Getpagesize())
	if err != nil {
		log.Errorf("failed to create off_cpu event reader: %v", err)
		return
	}

	defer perfReader.Close()

	// 本地定义与 C 结构对应的解析结构（小端）
	type offCpuEventRaw struct {
		TsLeave       uint64
		Pid           uint32
		Tid           uint32
		Comm          [16]byte
		CpuId         uint32
		KernelStackId int32
		ReasonFlags   uint32
		Pad64         uint64
	}

	var raw offCpuEventRaw

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
			// 解析二进制数据（按小端）
			buf := bytes.NewReader(record.RawSample)
			if err := binary.Read(buf, binary.LittleEndian, &raw); err != nil {
				log.Errorf("failed to parse off_cpu raw event: %v", err)
				continue
			}

			// 构造简化事件对象并处理
			pid := raw.Pid
			tsLeave := raw.TsLeave

			// 记录离开 CPU 的时间
			lastOffCPUTime.Store(pid, tsLeave)

			// 使用解析结果更新或创建 Off-CPU 堆栈缓存
			ev := struct{
				Pid uint32
				TsLeave uint64
				KernelStackId int32
			}{
				Pid: pid,
				TsLeave: tsLeave,
				KernelStackId: raw.KernelStackId,
			}
			updateOffCPUStackParsed(ev)

			// 同步到调度指标中
			syncOffCPUToMetrics(pid)
		}
	}
}

func updateOffCPUStackParsed(event struct{Pid uint32; TsLeave uint64; KernelStackId int32}) {
	pid := event.Pid

	existing, exists := offCPUStackCache.Load(pid)
	if !exists {
		stack := OffCPUStack{
			Pid:           pid,
			KernelStackID: event.KernelStackId,
			Count:         1,
			LastUpdateTs:  event.TsLeave,
		}
		offCPUStackCache.Store(pid, stack)
		return
	}

	stack := existing.(OffCPUStack)
	if stack.KernelStackID == event.KernelStackId {
		stack.Count++
		stack.LastUpdateTs = event.TsLeave
		offCPUStackCache.Store(pid, stack)
	} else {
		// 不同堆栈：简单策略为覆盖为最新堆栈
		stack.KernelStackID = event.KernelStackId
		stack.Count = 1
		stack.LastUpdateTs = event.TsLeave
		offCPUStackCache.Store(pid, stack)
	}
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
