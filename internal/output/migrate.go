package output

import (
	"bytes"
	"context"
	"encoding/binary"
	"math"
	"os"

	"github.com/cen-ngc5139/shepherd/internal/cache"
	"github.com/cen-ngc5139/shepherd/internal/log"
	"github.com/cen-ngc5139/shepherd/internal/metadata"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
)

// ProcessMigrate 读取 BPF 发送的迁移事件并更新缓存中的迁移统计
func ProcessMigrate(coll *ebpf.Collection, ctx context.Context) {
	migrateEvents := coll.Maps["migrate_events"]
	if migrateEvents == nil {
		log.Warningf("migrate_events map not found in BPF collection")
		return
	}

	reader, err := perf.NewReader(migrateEvents, os.Getpagesize())
	if err != nil {
		log.Errorf("failed to create migrate event reader: %v", err)
		return
	}
	defer reader.Close()

	// 与 C 结构对应的本地解析结构
	type migrateEventRaw struct {
		Ts      uint64
		Pid     uint32
		Tgid    uint32
		OrigCpu int32
		DestCpu int32
		Comm    [16]byte
		Pad     uint64
	}

	var raw migrateEventRaw

	for {
		select {
		case <-ctx.Done():
			log.Info("停止迁移事件处理")
			return
		default:
			rec, err := reader.Read()
			if err != nil {
				log.Errorf("failed to read migrate event: %v", err)
				continue
			}

			buf := bytes.NewReader(rec.RawSample)
			if err := binary.Read(buf, binary.LittleEndian, &raw); err != nil {
				log.Errorf("failed to parse migrate raw event: %v", err)
				continue
			}

			pid := raw.Pid
			// 计算迁移距离
			distance := int(math.Abs(float64(raw.DestCpu - raw.OrigCpu)))

			// 更新缓存中的 SchedMetrics
			val, exists := cache.SchedMetricsMap.Load(pid)
			if !exists {
				// 如果不存在则创建一个新的基础条目
				m := metadata.SchedMetrics{
					Pid:          pid,
					Comm:         sanitizeString(convertInt8ToString(raw.Comm[:])),
					MigrationCount: 0,
					AvgMigrationDist: 0,
				}
				val = m
			}

			metrics := val.(metadata.SchedMetrics)
			// 计算新的平均迁移距离
			if metrics.MigrationCount == 0 {
				metrics.AvgMigrationDist = float64(distance)
			} else {
				metrics.AvgMigrationDist = (metrics.AvgMigrationDist*float64(metrics.MigrationCount) + float64(distance)) / float64(metrics.MigrationCount+1)
			}
			metrics.MigrationCount++

			cache.SchedMetricsMap.Store(pid, metrics)
		}
	}
}
