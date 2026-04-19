package output

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"time"

	"github.com/cen-ngc5139/shepherd/internal/cache"
	"github.com/cen-ngc5139/shepherd/internal/metadata"
)

type ViewMode int

const (
	ViewScheduling ViewMode = iota
	ViewMemory
	ViewInterrupt
	ViewMax
)

var currentView = ViewScheduling

func StartDiagnosticCLI() {
	// 启动按键监听协程
	go listenKeyboard()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		renderCLI()
	}
}

func listenKeyboard() {
	reader := bufio.NewReader(os.Stdin)
	for {
		char, _, err := reader.ReadRune()
		if err != nil {
			return
		}
		if char == 'n' || char == 'N' {
			currentView = (currentView + 1) % ViewMax
		}
	}
}

func renderCLI() {
	// 清屏
	cmd := exec.Command("clear")
	cmd.Stdout = os.Stdout
	cmd.Run()

	header := "Shepherd Diagnostic Top"
	switch currentView {
	case ViewScheduling:
		header += " [VIEW: SCHEDULING]"
	case ViewMemory:
		header += " [VIEW: MEMORY]"
	case ViewInterrupt:
		header += " [VIEW: INTERRUPT]"
	}

	fmt.Println(header + " - " + time.Now().Format("15:04:05") + " (Press 'n' to switch)")

	var metrics []metadata.SchedMetrics
	cache.SchedMetricsMap.Range(func(key, value interface{}) bool {
		m := value.(metadata.SchedMetrics)
		metrics = append(metrics, m)
		return true
	})

	// 按视图核心指标排序
	sort.Slice(metrics, func(i, j int) bool {
		switch currentView {
		case ViewScheduling:
			return metrics[i].DelayNs > metrics[j].DelayNs
		case ViewMemory:
			return metrics[i].MemReclaimNs > metrics[j].MemReclaimNs
		case ViewInterrupt:
			return (metrics[i].IrqDurationNs + metrics[i].SoftirqDurationNs) > (metrics[j].IrqDurationNs + metrics[j].SoftirqDurationNs)
		default:
			return metrics[i].DelayNs > metrics[j].DelayNs
		}
	})

	displayCount := 20
	if len(metrics) < displayCount {
		displayCount = len(metrics)
	}

	switch currentView {
	case ViewScheduling:
		fmt.Printf("%-8s %-20s %-15s %-15s %-10s\n", "PID", "COMM", "LATENCY(ms)", "PREEMPT_CNT", "STACK_ID")
		for i := 0; i < displayCount; i++ {
			m := metrics[i]
			fmt.Printf("%-8d %-20s %-15.3f %-15d %-10d\n",
				m.Pid, m.Comm, float64(m.DelayNs)/1e6, m.PreempteCount, m.StackId)
		}
	case ViewMemory:
		fmt.Printf("%-8s %-20s %-15s %-15s %-10s\n", "PID", "COMM", "RECLAIM(ms)", "LATENCY(ms)", "STACK_ID")
		for i := 0; i < displayCount; i++ {
			m := metrics[i]
			fmt.Printf("%-8d %-20s %-15.3f %-15.3f %-10d\n",
				m.Pid, m.Comm, float64(m.MemReclaimNs)/1e6, float64(m.DelayNs)/1e6, m.StackId)
		}
	case ViewInterrupt:
		fmt.Printf("%-8s %-20s %-15s %-15s %-15s\n", "PID", "COMM", "IRQ(ms)", "SOFTIRQ(ms)", "LATENCY(ms)")
		for i := 0; i < displayCount; i++ {
			m := metrics[i]
			fmt.Printf("%-8d %-20s %-15.3f %-15.3f %-15.3f\n",
				m.Pid, m.Comm, float64(m.IrqDurationNs)/1e6, float64(m.SoftirqDurationNs)/1e6, float64(m.DelayNs)/1e6)
		}
	}

	if currentView == ViewScheduling {
		fmt.Println()
		fmt.Println("Top Preemptors:")
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
}
