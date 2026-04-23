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

// memReclaimEventRaw 与 trace.c 的 struct mem_reclaim_event_t 严格对齐
type memReclaimEventRaw struct {
	Ts          uint64
	DurationNs  uint64
	Pid         uint32
	Tgid        uint32
	NrScanned   uint32
	NrReclaimed uint32
	Order       uint32
	Nid         int32
	IsDirect    uint8
	IsKswapd    uint8
	LruType     uint8
	Pad0        uint8
	Comm        [16]byte
	Pad1        uint32
}

// ProcessMemReclaim 读取 BPF mem_reclaim_events perf buffer，按事件类型聚合进 cache.MemReclaimMap。
// direct reclaim / lru_shrink → 按 tgid 归属；kswapd_wake → 累加到 Pid=MemReclaimGlobalKey(=0) 这一条全局 entry。
func ProcessMemReclaim(coll *ebpf.Collection, ctx context.Context) {
	events := coll.Maps["mem_reclaim_events"]
	if events == nil {
		log.Warningf("mem_reclaim_events map not found in BPF collection")
		return
	}

	reader, err := perf.NewReader(events, os.Getpagesize())
	if err != nil {
		log.Errorf("failed to create mem_reclaim event reader: %v", err)
		return
	}
	defer reader.Close()

	var raw memReclaimEventRaw

	for {
		select {
		case <-ctx.Done():
			log.Info("停止内存回收事件处理")
			return
		default:
			rec, err := reader.Read()
			if err != nil {
				log.Errorf("failed to read mem_reclaim event: %v", err)
				continue
			}
			if rec.LostSamples > 0 {
				log.Warningf("mem_reclaim perf reader lost %d samples", rec.LostSamples)
			}

			buf := bytes.NewReader(rec.RawSample)
			if err := binary.Read(buf, binary.LittleEndian, &raw); err != nil {
				log.Errorf("failed to parse mem_reclaim raw event: %v", err)
				continue
			}

			aggregateReclaim(&raw)
		}
	}
}

func aggregateReclaim(raw *memReclaimEventRaw) {
	// kswapd_wake 是全局事件，聚合到 Pid=0 这一条
	var key uint32
	var comm string
	if raw.IsKswapd == 1 {
		key = metadata.MemReclaimGlobalKey
		comm = "kswapd"
	} else {
		key = raw.Tgid
		comm = sanitizeString(convertByteToString(raw.Comm[:]))
	}

	val, exists := cache.MemReclaimMap.Load(key)
	var m metadata.MemReclaimMetrics
	if exists {
		m = val.(metadata.MemReclaimMetrics)
	} else {
		m = metadata.MemReclaimMetrics{Pid: key, Comm: comm}
	}
	if m.Comm == "" {
		m.Comm = comm
	}

	switch {
	case raw.IsKswapd == 1:
		m.KswapdWakeCount++
	case raw.IsDirect == 1:
		m.DirectReclaimCount++
		m.DirectReclaimNs += raw.DurationNs
		if raw.DurationNs > m.MaxDirectReclaimNs {
			m.MaxDirectReclaimNs = raw.DurationNs
		}
		m.NrReclaimedTotal += uint64(raw.NrReclaimed)
	case raw.LruType == 1:
		m.LRUInactiveCount++
		m.NrScannedTotal += uint64(raw.NrScanned)
		m.NrReclaimedTotal += uint64(raw.NrReclaimed)
	case raw.LruType == 2:
		m.LRUActiveCount++
		m.NrScannedTotal += uint64(raw.NrScanned)
		m.NrReclaimedTotal += uint64(raw.NrReclaimed)
	}

	m.LastTs = raw.Ts
	cache.MemReclaimMap.Store(key, m)
}
