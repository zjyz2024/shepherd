package output

import (
	"fmt"
	"os"
	"sync"

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
	AllocCount         *prometheus.GaugeVec // 累计分配次数
	AllocSlowPathCount *prometheus.GaugeVec // 慢路径次数 (>=1ms)
	AllocMidPathCount  *prometheus.GaugeVec // 中速路径次数 (>=100µs)
	AllocAvgNs         *prometheus.GaugeVec // 平均分配耗时
	AllocMaxNs         *prometheus.GaugeVec // 单次最大耗时
	MemAllocMap        *sync.Map
}

func NewMemMetrics(memAllocMap *sync.Map) *MemMetrics {
	return &MemMetrics{
		AllocCount:         createGaugeVec("mem_alloc_count", "total page allocation count per task (sampled)", []string{"pid", "comm"}),
		AllocSlowPathCount: createGaugeVec("mem_alloc_slow_path_count", "page allocation slow path count (>=1ms) per task", []string{"pid", "comm"}),
		AllocMidPathCount:  createGaugeVec("mem_alloc_mid_path_count", "page allocation mid path count (>=100us) per task", []string{"pid", "comm"}),
		AllocAvgNs:         createGaugeVec("mem_alloc_avg_duration_ns", "average page allocation duration (ns) per task", []string{"pid", "comm"}),
		AllocMaxNs:         createGaugeVec("mem_alloc_max_duration_ns", "max page allocation duration (ns) per task", []string{"pid", "comm"}),
		MemAllocMap:        memAllocMap,
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
}
