package output

import (
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/cen-ngc5139/shepherd/internal/cache"
	"github.com/cen-ngc5139/shepherd/internal/metadata"
	"golang.org/x/term"
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
	// 保存终端状态并在退出时恢复
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err == nil {
		defer term.Restore(int(os.Stdin.Fd()), oldState)
	}

	// 启动按键监听协程
	go listenKeyboard()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		renderCLI()
	}
}

func listenKeyboard() {
	// 在 Raw 模式下读取字节
	b := make([]byte, 1)
	for {
		_, err := os.Stdin.Read(b)
		if err != nil {
			return
		}
		char := b[0]
		// 按 'n' 或 'N' 切换视图
		if char == 'n' || char == 'N' {
			currentView = (currentView + 1) % ViewMax
		}
		// 按 'q' 或 Ctrl+C (in raw mode) 退出可以通过 signal 处理，这里也可以识别
		if char == 'q' || char == 'Q' || char == 3 {
			// 如果是 MakeRaw 模式，Ctrl+C 会变成字节 3
			// 这里简单处理，具体退出逻辑由主进程 signal 协调更好
			// os.Exit(0)
		}
	}
}

func renderCLI() {
	// 清屏 (使用 ANSI 转义序列在 Raw 模式下更稳定)
	fmt.Print("\033[H\033[2J")

	header := "Shepherd Diagnostic Top"
	switch currentView {
	case ViewScheduling:
		header += " [VIEW: SCHEDULING]"
	case ViewMemory:
		header += " [VIEW: MEMORY]"
	case ViewInterrupt:
		header += " [VIEW: INTERRUPT]"
	}

	// 使用 \r\n 确保在 Raw 模式下换行正确
	fmt.Printf("%s - %s (Press 'n' to switch, 'q' to exit)\r\n", header, time.Now().Format("15:04:05"))

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
		fmt.Printf("%-8s %-20s %-15s %-15s %-10s\r\n", "PID", "COMM", "LATENCY(ms)", "PREEMPT_CNT", "STACK_ID")
		for i := 0; i < displayCount; i++ {
			m := metrics[i]
			fmt.Printf("%-8d %-20s %-15.3f %-15d %-10d\r\n",
				m.Pid, m.Comm, float64(m.DelayNs)/1e6, m.PreempteCount, m.StackId)
		}
	case ViewMemory:
		fmt.Printf("%-8s %-20s %-15s %-15s %-10s\r\n", "PID", "COMM", "RECLAIM(ms)", "LATENCY(ms)", "STACK_ID")
		for i := 0; i < displayCount; i++ {
			m := metrics[i]
			fmt.Printf("%-8d %-20s %-15.3f %-15.3f %-10d\r\n",
				m.Pid, m.Comm, float64(m.MemReclaimNs)/1e6, float64(m.DelayNs)/1e6, m.StackId)
		}
	case ViewInterrupt:
		fmt.Printf("%-8s %-20s %-15s %-15s %-15s\r\n", "PID", "COMM", "IRQ(ms)", "SOFTIRQ(ms)", "LATENCY(ms)")
		for i := 0; i < displayCount; i++ {
			m := metrics[i]
			fmt.Printf("%-8d %-20s %-15.3f %-15.3f %-15.3f\r\n",
				m.Pid, m.Comm, float64(m.IrqDurationNs)/1e6, float64(m.SoftirqDurationNs)/1e6, float64(m.DelayNs)/1e6)
		}
	}

	if currentView == ViewScheduling {
		fmt.Print("\r\nTop Preemptors:\r\n")
		count := 0
		cache.SchedPreemptedMap.Range(func(key, value interface{}) bool {
			p := value.(metadata.SchedPreempted)
			if count < 5 {
				fmt.Printf(" [PID: %d, COMM: %s, COUNT: %d]", p.Pid, p.Comm, p.Count)
			}
			count++
			return true
		})
		fmt.Print("\r\n")
	}
}
