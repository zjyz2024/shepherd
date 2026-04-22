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

// memAllocEventRaw 与 trace.c 的 struct mem_alloc_event_t 严格对齐
// 字段顺序/大小/pad 必须 1:1
type memAllocEventRaw struct {
	Ts         uint64
	DurationNs uint64
	Pid        uint32
	Tgid       uint32
	Order      uint32
	GfpFlags   uint32
	StackId    int32
	PathType   uint8
	Pad0       [3]uint8
	Comm       [16]byte
	Pad1       uint64
}

// ProcessMemAlloc 读取 BPF mem_alloc_events perf buffer，聚合进 cache.MemAllocMap，
// 并把 slow path 事件推入 cache.MemAllocSlowPath ring buffer。
// 仿 internal/output/migrate.go:ProcessMigrate 的结构。
func ProcessMemAlloc(coll *ebpf.Collection, ctx context.Context) {
	allocEvents := coll.Maps["mem_alloc_events"]
	if allocEvents == nil {
		log.Warningf("mem_alloc_events map not found in BPF collection")
		return
	}

	reader, err := perf.NewReader(allocEvents, os.Getpagesize())
	if err != nil {
		log.Errorf("failed to create mem_alloc event reader: %v", err)
		return
	}
	defer reader.Close()

	var raw memAllocEventRaw

	for {
		select {
		case <-ctx.Done():
			log.Info("停止内存分配事件处理")
			return
		default:
			rec, err := reader.Read()
			if err != nil {
				log.Errorf("failed to read mem_alloc event: %v", err)
				continue
			}
			if rec.LostSamples > 0 {
				log.Warningf("mem_alloc perf reader lost %d samples", rec.LostSamples)
			}

			buf := bytes.NewReader(rec.RawSample)
			if err := binary.Read(buf, binary.LittleEndian, &raw); err != nil {
				log.Errorf("failed to parse mem_alloc raw event: %v", err)
				continue
			}

			aggregateMemAlloc(&raw)

			// slow path (path_type==2) 额外入环形缓冲
			if raw.PathType == 2 {
				ev := metadata.MemAllocSlowPathEvent{
					Ts:         raw.Ts,
					Pid:        raw.Tgid,
					Comm:       sanitizeString(convertByteToString(raw.Comm[:])),
					DurationNs: raw.DurationNs,
					Order:      raw.Order,
					GfpFlags:   raw.GfpFlags,
					StackId:    raw.StackId,
				}
				cache.MemAllocSlowPath.Push(ev)
			}
		}
	}
}

func aggregateMemAlloc(raw *memAllocEventRaw) {
	pid := raw.Tgid
	comm := sanitizeString(convertByteToString(raw.Comm[:]))

	val, exists := cache.MemAllocMap.Load(pid)
	var m metadata.MemAllocMetrics
	if exists {
		m = val.(metadata.MemAllocMetrics)
	} else {
		m = metadata.MemAllocMetrics{Pid: pid, Comm: comm}
	}
	if m.Comm == "" {
		m.Comm = comm
	}

	m.AllocCount++
	m.TotalAllocNs += raw.DurationNs
	if raw.DurationNs > m.MaxAllocNs {
		m.MaxAllocNs = raw.DurationNs
	}
	switch raw.PathType {
	case 2:
		m.SlowPathCount++
		m.LastStackId = raw.StackId
	case 1:
		m.MidPathCount++
	}
	if raw.Order < uint32(len(m.OrderHistogram)) {
		m.OrderHistogram[raw.Order]++
	}
	m.LastTs = raw.Ts

	cache.MemAllocMap.Store(pid, m)
}

// convertByteToString 复用 utils.go:convertInt8ToString 的思路，但源是 [16]byte 而非 [16]int8
func convertByteToString(data []byte) string {
	for i, b := range data {
		if b == 0 {
			return string(data[:i])
		}
	}
	return string(data)
}
