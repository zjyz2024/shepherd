package server

import (
	"github.com/cen-ngc5139/shepherd/internal/cache"
	"github.com/cen-ngc5139/shepherd/internal/output"
	"github.com/gin-gonic/gin"
)

func InitPrometheusMetrics(r *gin.Engine) {
	schedMetrics := output.NewSchedMetrics(cache.SchedMetricsMap, cache.SchedPreemptedMap)
	memMetrics := output.NewMemMetrics(cache.MemAllocMap)
	traceMetrics := output.NewTraceMetrics(schedMetrics, memMetrics)
	r.GET("/metrics", traceMetrics.MetricsHandler())
}
