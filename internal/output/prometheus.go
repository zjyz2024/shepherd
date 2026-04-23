package output

import (
	"fmt"
	"os"
	"sync"

	"github.com/cen-ngc5139/shepherd/internal/cache"
	"github.com/cen-ngc5139/shepherd/internal/metadata"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	SchedLatencies = "sched_latencies"
	SchedPreempted = "sched_preempted"
	SchedPreempte  = "sched_preempte"
)

type TraceMetrics struct {
	SchedMetrics *SchedMetrics
	MemMetrics   *MemMetrics
}

func NewTraceMetrics(schedMetrics *SchedMetrics, memMetrics *MemMetrics) *TraceMetrics {
	return &TraceMetrics{
		SchedMetrics: schedMetrics,
		MemMetrics:   memMetrics,
	}
}

type SchedMetrics struct {
	SchedLatencies    *prometheus.GaugeVec // 调度延迟
	SchedPreempted    *prometheus.GaugeVec // 被抢占的进程
	SchedPreempte     *prometheus.GaugeVec // 抢占的进程
	VoluntaryCtxtSwitches   *prometheus.GaugeVec // 自愿上下文切换
	InvoluntaryCtxtSwitches *prometheus.GaugeVec // 非自愿上下文切换
	MigrationCount    *prometheus.GaugeVec // CPU 迁移次数
	AvgMigrationDist  *prometheus.GaugeVec // 平均迁移距离
	PriorityInversion *prometheus.GaugeVec // 优先级反转次数
	MaxInversionBlockTime *prometheus.GaugeVec // 最大反转阻塞时间
	SchedMetricsMap   *sync.Map
	SchedPreemptedMap *sync.Map
}

func createGaugeVec(name, help string, labels []string) *prometheus.GaugeVec {
	return promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: name,
			Help: help,
		},
		labels,
	)
}

func NewSchedMetrics(schedMetricsMap, schedPreemptedMap *sync.Map) *SchedMetrics {
	return &SchedMetrics{
		SchedLatencies:    createGaugeVec(SchedLatencies, "task cpu scheduling latency", []string{"pid", "comm"}),
		SchedPreempted:    createGaugeVec(SchedPreempted, "task cpu preempted", []string{"pid", "comm"}),
		SchedPreempte:     createGaugeVec(SchedPreempte, "task cpu preempted", []string{"pid", "comm"}),
		VoluntaryCtxtSwitches:   createGaugeVec("voluntary_context_switches", "voluntary context switches per task", []string{"pid", "comm"}),
		InvoluntaryCtxtSwitches: createGaugeVec("involuntary_context_switches", "involuntary context switches per task", []string{"pid", "comm"}),
		MigrationCount:    createGaugeVec("migration_count", "CPU migration count per task", []string{"pid", "comm"}),
		AvgMigrationDist:  createGaugeVec("avg_migration_distance", "average CPU migration distance per task", []string{"pid", "comm"}),
		PriorityInversion: createGaugeVec("priority_inversion_count", "priority inversion count per task", []string{"pid", "comm"}),
		MaxInversionBlockTime: createGaugeVec("max_inversion_block_time_ns", "max priority inversion blocking time per task (ns)", []string{"pid", "comm"}),
		SchedMetricsMap:   schedMetricsMap,
		SchedPreemptedMap: schedPreemptedMap,
	}
}

func (m *SchedMetrics) UpdateMetricsFromCache(nodeName string) {
	m.SchedMetricsMap.Range(func(key, value interface{}) bool {
		schedMetrics := value.(metadata.SchedMetrics)
		m.SchedLatencies.WithLabelValues(fmt.Sprintf("%d", schedMetrics.Pid), schedMetrics.Comm).Set(float64(schedMetrics.DelayNs))
		if schedMetrics.PreempteCount > 0 {
			m.SchedPreempte.WithLabelValues(fmt.Sprintf("%d", schedMetrics.Pid), schedMetrics.Comm).Set(float64(schedMetrics.PreempteCount))
		}
		if schedMetrics.VoluntaryCtxtSwitches > 0 {
			m.VoluntaryCtxtSwitches.WithLabelValues(fmt.Sprintf("%d", schedMetrics.Pid), schedMetrics.Comm).Set(float64(schedMetrics.VoluntaryCtxtSwitches))
		}
		if schedMetrics.InvoluntaryCtxtSwitches > 0 {
			m.InvoluntaryCtxtSwitches.WithLabelValues(fmt.Sprintf("%d", schedMetrics.Pid), schedMetrics.Comm).Set(float64(schedMetrics.InvoluntaryCtxtSwitches))
		}
		if schedMetrics.MigrationCount > 0 {
			m.MigrationCount.WithLabelValues(fmt.Sprintf("%d", schedMetrics.Pid), schedMetrics.Comm).Set(float64(schedMetrics.MigrationCount))
			m.AvgMigrationDist.WithLabelValues(fmt.Sprintf("%d", schedMetrics.Pid), schedMetrics.Comm).Set(schedMetrics.AvgMigrationDist)
		}
		if schedMetrics.PriorityInversionCount > 0 {
			m.PriorityInversion.WithLabelValues(fmt.Sprintf("%d", schedMetrics.Pid), schedMetrics.Comm).Set(float64(schedMetrics.PriorityInversionCount))
			m.MaxInversionBlockTime.WithLabelValues(fmt.Sprintf("%d", schedMetrics.Pid), schedMetrics.Comm).Set(float64(schedMetrics.MaxInversionBlockTimeNs))
		}
		return true
	})

	m.SchedPreemptedMap.Range(func(key, value interface{}) bool {
		schedPreempted := value.(metadata.SchedPreempted)
		m.SchedPreempted.WithLabelValues(fmt.Sprintf("%d", schedPreempted.Pid), schedPreempted.Comm).Set(float64(schedPreempted.Count))
		return true
	})
}

func (m *TraceMetrics) MetricsHandler() gin.HandlerFunc {
	h := promhttp.Handler()

	nodeName, err := os.Hostname()
	if err != nil {
		nodeName = "default_node"
	}

	return func(c *gin.Context) {
		m.SchedMetrics.UpdateMetricsFromCache(nodeName)
		if m.MemMetrics != nil {
			m.MemMetrics.UpdateMemMetricsFromCache(nodeName)
		}
		h.ServeHTTP(c.Writer, c.Request)
	}
}

// =========================================================================
// Memory Dimension - Phase M1: Allocation Latency
// =========================================================================

// MemMetrics 聚合内存维度的 Prometheus gauge
type MemMetrics struct {
	// Phase M1: Allocation Latency
	AllocCount         *prometheus.GaugeVec // 累计分配次数
	AllocSlowPathCount *prometheus.GaugeVec // 慢路径次数 (>=1ms)
	AllocMidPathCount  *prometheus.GaugeVec // 中速路径次数 (>=100µs)
	AllocAvgNs         *prometheus.GaugeVec // 平均分配耗时
	AllocMaxNs         *prometheus.GaugeVec // 单次最大耗时

	// Phase M2: Reclaim Pressure
	ReclaimDirectCount   *prometheus.GaugeVec // direct reclaim 次数
	ReclaimDirectNs      *prometheus.GaugeVec // 累积 direct reclaim 耗时
	ReclaimMaxDirectNs   *prometheus.GaugeVec // 单次最大 direct reclaim 耗时
	ReclaimKswapdWakeCnt *prometheus.GaugeVec // kswapd 唤醒次数（pid=0 全局）
	ReclaimLRUInactive   *prometheus.GaugeVec // lru_shrink_inactive 次数
	ReclaimLRUActive     *prometheus.GaugeVec // lru_shrink_active 次数
	ReclaimPagesTotal    *prometheus.GaugeVec // 累积回收页数

	// Phase M5: OOM Killer
	OOMEventCount *prometheus.CounterVec // OOM 事件计数（Counter，单调递增）

	MemAllocMap   *sync.Map
	MemReclaimMap *sync.Map
}

func NewMemMetrics(memAllocMap, memReclaimMap *sync.Map) *MemMetrics {
	return &MemMetrics{
		AllocCount:         createGaugeVec("mem_alloc_count", "total page allocation count per task (sampled)", []string{"pid", "comm"}),
		AllocSlowPathCount: createGaugeVec("mem_alloc_slow_path_count", "page allocation slow path count (>=1ms) per task", []string{"pid", "comm"}),
		AllocMidPathCount:  createGaugeVec("mem_alloc_mid_path_count", "page allocation mid path count (>=100us) per task", []string{"pid", "comm"}),
		AllocAvgNs:         createGaugeVec("mem_alloc_avg_duration_ns", "average page allocation duration (ns) per task", []string{"pid", "comm"}),
		AllocMaxNs:         createGaugeVec("mem_alloc_max_duration_ns", "max page allocation duration (ns) per task", []string{"pid", "comm"}),

		ReclaimDirectCount:   createGaugeVec("mem_reclaim_direct_count", "direct reclaim event count per task", []string{"pid", "comm"}),
		ReclaimDirectNs:      createGaugeVec("mem_reclaim_direct_duration_ns", "cumulative direct reclaim duration (ns) per task", []string{"pid", "comm"}),
		ReclaimMaxDirectNs:   createGaugeVec("mem_reclaim_max_direct_duration_ns", "max single direct reclaim duration (ns) per task", []string{"pid", "comm"}),
		ReclaimKswapdWakeCnt: createGaugeVec("mem_reclaim_kswapd_wake_count", "kswapd wake count (global aggregate)", []string{"pid", "comm"}),
		ReclaimLRUInactive:   createGaugeVec("mem_reclaim_lru_inactive_count", "mm_vmscan_lru_shrink_inactive event count per task", []string{"pid", "comm"}),
		ReclaimLRUActive:     createGaugeVec("mem_reclaim_lru_active_count", "mm_vmscan_lru_shrink_active event count per task", []string{"pid", "comm"}),
		ReclaimPagesTotal:    createGaugeVec("mem_reclaim_pages_total", "total pages reclaimed per task", []string{"pid", "comm"}),

		OOMEventCount: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "mem_oom_kill_events_total",
				Help: "total OOM kill events",
			},
			[]string{"node"},
		),

		MemAllocMap:   memAllocMap,
		MemReclaimMap: memReclaimMap,
	}
}

func (m *MemMetrics) UpdateMemMetricsFromCache(nodeName string) {
	m.MemAllocMap.Range(func(key, value interface{}) bool {
		mm := value.(metadata.MemAllocMetrics)
		pidStr := fmt.Sprintf("%d", mm.Pid)
		m.AllocCount.WithLabelValues(pidStr, mm.Comm).Set(float64(mm.AllocCount))
		if mm.SlowPathCount > 0 {
			m.AllocSlowPathCount.WithLabelValues(pidStr, mm.Comm).Set(float64(mm.SlowPathCount))
		}
		if mm.MidPathCount > 0 {
			m.AllocMidPathCount.WithLabelValues(pidStr, mm.Comm).Set(float64(mm.MidPathCount))
		}
		if mm.AllocCount > 0 {
			avg := mm.TotalAllocNs / mm.AllocCount
			m.AllocAvgNs.WithLabelValues(pidStr, mm.Comm).Set(float64(avg))
		}
		m.AllocMaxNs.WithLabelValues(pidStr, mm.Comm).Set(float64(mm.MaxAllocNs))
		return true
	})

	if m.MemReclaimMap != nil {
		m.MemReclaimMap.Range(func(key, value interface{}) bool {
			rm := value.(metadata.MemReclaimMetrics)
			pidStr := fmt.Sprintf("%d", rm.Pid)
			if rm.KswapdWakeCount > 0 {
				m.ReclaimKswapdWakeCnt.WithLabelValues(pidStr, rm.Comm).Set(float64(rm.KswapdWakeCount))
			}
			if rm.DirectReclaimCount > 0 {
				m.ReclaimDirectCount.WithLabelValues(pidStr, rm.Comm).Set(float64(rm.DirectReclaimCount))
				m.ReclaimDirectNs.WithLabelValues(pidStr, rm.Comm).Set(float64(rm.DirectReclaimNs))
				m.ReclaimMaxDirectNs.WithLabelValues(pidStr, rm.Comm).Set(float64(rm.MaxDirectReclaimNs))
			}
			if rm.LRUInactiveCount > 0 {
				m.ReclaimLRUInactive.WithLabelValues(pidStr, rm.Comm).Set(float64(rm.LRUInactiveCount))
			}
			if rm.LRUActiveCount > 0 {
				m.ReclaimLRUActive.WithLabelValues(pidStr, rm.Comm).Set(float64(rm.LRUActiveCount))
			}
			if rm.NrReclaimedTotal > 0 {
				m.ReclaimPagesTotal.WithLabelValues(pidStr, rm.Comm).Set(float64(rm.NrReclaimedTotal))
			}
			return true
		})
	}

	// Phase M5: 统计 OOM 事件数
	if cache.OOMEventRing != nil {
		oomEvents := cache.OOMEventRing.Snapshot()
		if len(oomEvents) > 0 {
			m.OOMEventCount.WithLabelValues(nodeName).Add(float64(len(oomEvents)))
		}
	}
}
