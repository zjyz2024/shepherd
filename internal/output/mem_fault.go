package output

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"

	"github.com/cen-ngc5139/shepherd/internal/cache"
	"github.com/cen-ngc5139/shepherd/internal/log"
	"github.com/cen-ngc5139/shepherd/internal/metadata"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
)

// memFaultEventRaw 与 trace.c 的 struct mem_fault_event_t 严格对齐
type memFaultEventRaw struct {
	Ts           uint64
	DurationNs   uint64
	Pid          uint32
	Tgid         uint32
	FaultAddr    uint64
	IsMajor      uint32
	IsUser       uint32
	IsWrite      uint8
	Pad0         [3]uint8
	Comm         [16]byte
	StackId      int32
	Pad1         uint32
}

// ProcessMemFault 读取 BPF mem_fault_events perf buffer，聚合进 cache.MemFaultMap
func ProcessMemFault(coll *ebpf.Collection, ctx context.Context) {
	faultEvents := coll.Maps["mem_fault_events"]
	if faultEvents == nil {
		log.Warningf("mem_fault_events map not found in BPF collection")
		return
	}

	reader, err := perf.NewReader(faultEvents, os.Getpagesize())
	if err != nil {
		log.Errorf("failed to create mem_fault event reader: %v", err)
		return
	}
	defer reader.Close()

	var raw memFaultEventRaw

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
				log.Warningf("read mem_fault_events error: %v", err)
				continue
			}
		}

		if record.LostSamples > 0 {
			log.Warningf("mem_fault_events lost %d samples", record.LostSamples)
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &raw); err != nil {
			log.Warningf("parse mem_fault_event error: %v", err)
			continue
		}

		aggregateMemFault(&raw)
	}
}

// aggregateMemFault 将单个 fault 事件聚合到 cache.MemFaultMap
func aggregateMemFault(raw *memFaultEventRaw) {
	val, ok := cache.MemFaultMap.Load(raw.Tgid)
	var m metadata.MemFaultMetrics

	if ok {
		m = val.(metadata.MemFaultMetrics)
	} else {
		m = metadata.MemFaultMetrics{
			Pid:  raw.Tgid,
			Comm: bytesString(raw.Comm[:]),
		}
	}

	// 更新统计
	if raw.IsMajor == 1 {
		m.MajorFaultCount++
		m.TotalMajorFaultNs += raw.DurationNs
		if raw.DurationNs > m.MaxMajorFaultNs {
			m.MaxMajorFaultNs = raw.DurationNs
		}
		if raw.StackId >= 0 {
			m.LastStackId = raw.StackId
		}
	} else {
		m.MinorFaultCount++
		m.TotalMinorFaultNs += raw.DurationNs
	}

	m.LastTs = raw.Ts

	cache.MemFaultMap.Store(raw.Tgid, m)
}

// bytesString 将 [16]byte 转为字符串（截至 null terminator）
func bytesString(b []byte) string {
	for i, v := range b {
		if v == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
