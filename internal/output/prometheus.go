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
}

func NewTraceMetrics(schedMetrics *SchedMetrics) *TraceMetrics {
	return &TraceMetrics{
		SchedMetrics: schedMetrics,
	}
}

type SchedMetrics struct {
	SchedLatencies    *prometheus.GaugeVec // 调度延迟
	SchedPreempted    *prometheus.GaugeVec // 被抢占的进程
	SchedPreempte     *prometheus.GaugeVec // 抢占的进程
	VoluntaryCtxtSwitches   *prometheus.GaugeVec // 自愿上下文切换
	InvoluntaryCtxtSwitches *prometheus.GaugeVec // 非自愿上下文切换
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
		h.ServeHTTP(c.Writer, c.Request)
	}
}
