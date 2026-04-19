package output

import (
	"fmt"
	"os"
	"os/exec"
	"sort"
	"time"

	"github.com/cen-ngc5139/shepherd/internal/cache"
	"github.com/cen-ngc5139/shepherd/internal/metadata"
)

func StartDiagnosticCLI() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		renderCLI()
	}
}

func renderCLI() {
	// 清屏 (Linux/macOS)
	cmd := exec.Command("clear")
	cmd.Stdout = os.Stdout
	cmd.Run()

	fmt.Println("Shepherd Diagnostic Top - " + time.Now().Format("15:04:05"))
	fmt.Println("----------------------------------------------------------------------------------------------------------------------")
	fmt.Printf("%-8s %-16s %-12s %-10s %-10s %-10s %-8s\n", "PID", "COMM", "LATENCY(ms)", "IRQ(us)", "SOFTIRQ(us)", "RECLAIM(us)", "STACK_ID")
	fmt.Println("----------------------------------------------------------------------------------------------------------------------")

	var metrics []metadata.SchedMetrics
	cache.SchedMetricsMap.Range(func(key, value interface{}) bool {
		m := value.(metadata.SchedMetrics)
		metrics = append(metrics, m)
		return true
	})

	// 按延迟排序
	sort.Slice(metrics, func(i, j int) bool {
		return metrics[i].DelayNs > metrics[j].DelayNs
	})

	// 只展示前 20 条
	displayCount := 20
	if len(metrics) < displayCount {
		displayCount = len(metrics)
	}

	for i := 0; i < displayCount; i++ {
		m := metrics[i]
		fmt.Printf("%-8d %-16s %-12.2f %-10.2f %-10.2f %-10.2f %-8d\n",
			m.Pid,
			m.Comm,
			float64(m.DelayNs)/1e6,
			float64(m.IrqDurationNs)/1e3,
			float64(m.SoftirqDurationNs)/1e3,
			float64(m.MemReclaimNs)/1e3,
			m.StackId,
		)
	}

	fmt.Println("----------------------------------------------------------------------------------------------------------------------")
	fmt.Println("Preemption Stats:")
	count := 0
	cache.SchedPreemptedMap.Range(func(key, value interface{}) bool {
		p := value.(metadata.SchedPreempted)
		if count < 5 {
			fmt.Printf(" [PID: %d, COMM: %s, COUNT: %d]", p.Pid, p.Comm, p.Count)
		}
		count++
		return true
	})
	fmt.Println()
}
