package output

import (
	"context"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/cen-ngc5139/shepherd/internal/cache"
	"github.com/cen-ngc5139/shepherd/internal/metadata"
	"github.com/cilium/ebpf"
	"golang.org/x/term"
)

type ViewMode int

const (
	ViewScheduling ViewMode = iota
	ViewMemory
	ViewInterrupt
	ViewMax
)

var (
	currentView       = ViewScheduling
	EnableStackSymbol = true // 符号还原功能开关
	ebpfCollection    *ebpf.Collection
)

func StartDiagnosticCLI(ctx context.Context, cancel context.CancelFunc, coll *ebpf.Collection) {
	ebpfCollection = coll

	// 初始化内核符号表
	if EnableStackSymbol {
		_ = LoadKallsyms()
	}

	// 保存终端状态并在退出时恢复
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err == nil {
		defer term.Restore(int(os.Stdin.Fd()), oldState)
	}

	// 启动按键监听协程
	go listenKeyboard(cancel)

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// 清屏并退出
			fmt.Print("\033[H\033[2J")
			fmt.Println("Exiting Shepherd...")
			return
		case <-ticker.C:
			renderCLI()
		}
	}
}

func listenKeyboard(cancel context.CancelFunc) {
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
		// 按 's' 或 'S' 切换符号开关
		if char == 's' || char == 'S' {
			EnableStackSymbol = !EnableStackSymbol
		}
		// 按 'q' 或 'Q' 或 Ctrl+C (字节 3) 退出
		if char == 'q' || char == 'Q' || char == 3 {
			cancel()
			return
		}
	}
}

func getStackSymbols(stackID int32) string {
	if stackID <= 0 || ebpfCollection == nil {
		return "-"
	}

	stackMap := ebpfCollection.Maps["stack_traces"]
	if stackMap == nil {
		return "no map"
	}

	var addresses [127]uint64
	if err := stackMap.Lookup(uint32(stackID), &addresses); err != nil {
		return fmt.Sprintf("ID:%d", stackID)
	}

	var syms []string
	for _, addr := range addresses {
		if addr == 0 {
			break
		}
		syms = append(syms, ResolveSymbol(addr))
	}

	if len(syms) == 0 {
		return fmt.Sprintf("ID:%d", stackID)
	}

	// 只返回最顶层的 3 个符号以防显示太长
	displayLen := 3
	if len(syms) < displayLen {
		displayLen = len(syms)
	}
	return strings.Join(syms[:displayLen], "->")
}

// 补丁：由于 import 循环或位置，这里直接处理 symbols 的 string 拼接
func formatStack(stackID int32) string {
	if !EnableStackSymbol {
		return fmt.Sprintf("%d", stackID)
	}
	return getStackSymbols(stackID)
}

func renderCLI() {
	// 清屏
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

	symStatus := "OFF"
	if EnableStackSymbol {
		symStatus = "ON"
	}

	fmt.Printf("%s - %s (n:switch, s:sym[%s], q:exit)\r\n", header, time.Now().Format("15:04:05"), symStatus)

	var metrics []metadata.SchedMetrics
	cache.SchedMetricsMap.Range(func(key, value interface{}) bool {
		m := value.(metadata.SchedMetrics)
		metrics = append(metrics, m)
		return true
	})

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
		fmt.Printf("%-8s %-20s %-15s %-10s %-25s\r\n", "PID", "COMM", "LATENCY(ms)", "PREEMPT", "STACK_TRACE")
		for i := 0; i < displayCount; i++ {
			m := metrics[i]
			fmt.Printf("%-8d %-20s %-15.3f %-10d %-25s\r\n",
				m.Pid, m.Comm, float64(m.DelayNs)/1e6, m.PreempteCount, formatStack(m.StackId))
		}
	case ViewMemory:
		fmt.Printf("%-8s %-20s %-15s %-15s %-25s\r\n", "PID", "COMM", "RECLAIM(ms)", "LATENCY(ms)", "STACK_TRACE")
		for i := 0; i < displayCount; i++ {
			m := metrics[i]
			fmt.Printf("%-8d %-20s %-15.3f %-15.3f %-25s\r\n",
				m.Pid, m.Comm, float64(m.MemReclaimNs)/1e6, float64(m.DelayNs)/1e6, formatStack(m.StackId))
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
