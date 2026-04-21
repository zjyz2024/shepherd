package output

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
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

// Phase 6: 列组的定义（用于多列布局）
type ColumnSet int

const (
	ColSetBasic ColumnSet = iota
	ColSetCtxtSwitch
	ColSetMigration
	ColSetOffCPU
	ColSetFull
	ColSetMax
)

type Column struct {
	name      string
	label     string
	width     int
	alignLeft bool
}

// 列组定义：每个 ColumnSet 对应一组列
var columnDefinitions = map[ColumnSet][]Column{
	ColSetBasic: {
		{name: "pid", label: "PID", width: 8, alignLeft: false},
		{name: "comm", label: "COMM", width: 20, alignLeft: true},
		{name: "latency", label: "LATENCY(ms)", width: 15, alignLeft: false},
		{name: "preempt", label: "PREEMPT", width: 10, alignLeft: false},
		{name: "stack", label: "STACK_TRACE", width: 30, alignLeft: true},
	},
	ColSetCtxtSwitch: {
		{name: "pid", label: "PID", width: 8, alignLeft: false},
		{name: "comm", label: "COMM", width: 20, alignLeft: true},
		{name: "vol_ctx", label: "VOL_CTX", width: 12, alignLeft: false},
		{name: "invol_ctx", label: "INVOL_CTX", width: 12, alignLeft: false},
		{name: "ctx_total", label: "CTX_TOTAL", width: 12, alignLeft: false},
	},
	ColSetMigration: {
		{name: "pid", label: "PID", width: 8, alignLeft: false},
		{name: "comm", label: "COMM", width: 20, alignLeft: true},
		{name: "migrations", label: "MIGRATIONS", width: 12, alignLeft: false},
		{name: "avg_dist", label: "AVG_DIST", width: 12, alignLeft: false},
	},
	ColSetOffCPU: {
		{name: "pid", label: "PID", width: 8, alignLeft: false},
		{name: "comm", label: "COMM", width: 20, alignLeft: true},
		{name: "offcpu_time", label: "OFF_CPU(ms)", width: 15, alignLeft: false},
		{name: "offcpu_count", label: "COUNT", width: 10, alignLeft: false},
	},
	ColSetFull: {
		{name: "pid", label: "PID", width: 8, alignLeft: false},
		{name: "comm", label: "COMM", width: 20, alignLeft: true},
		{name: "latency", label: "LATENCY(ms)", width: 15, alignLeft: false},
		{name: "vol_ctx", label: "VOL_CTX", width: 12, alignLeft: false},
		{name: "invol_ctx", label: "INVOL_CTX", width: 12, alignLeft: false},
		{name: "preempt", label: "PREEMPT", width: 10, alignLeft: false},
		{name: "migrations", label: "MIGRATIONS", width: 12, alignLeft: false},
		{name: "avg_dist", label: "AVG_DIST", width: 10, alignLeft: false},
		{name: "offcpu_time", label: "OFF_CPU(ms)", width: 15, alignLeft: false},
	},
}

// 列布局管理
type ColumnLayout struct {
	columnSet      ColumnSet
	sortField      string
	sortDescending bool
	scrollOffset   int
}

var (
	currentView       = ViewScheduling
	currentLayout     = ColumnLayout{columnSet: ColSetBasic, sortField: "latency", sortDescending: true, scrollOffset: 0}
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

		// 按 'n' 或 'N' 切换视图（内存/中断等）
		if char == 'n' || char == 'N' {
			currentView = (currentView + 1) % ViewMax
			// 切换视图时重置列组为 Basic
			if currentView == ViewScheduling {
				currentLayout.columnSet = ColSetBasic
				currentLayout.scrollOffset = 0
			}
		}

		// 按 'd' 或 'D' 回到调度视图
		if char == 'd' || char == 'D' {
			currentView = ViewScheduling
			currentLayout.columnSet = ColSetBasic
			currentLayout.scrollOffset = 0
		}

		// 按 'l' 或 'L' 循环切换列组（仅在调度视图有效）
		if (char == 'l' || char == 'L') && currentView == ViewScheduling {
			currentLayout.columnSet = (currentLayout.columnSet + 1) % ColSetMax
			currentLayout.scrollOffset = 0
		}

		// 按 't' 或 'T' 切换排序方式
		if char == 't' || char == 'T' {
			switch currentLayout.sortField {
			case "latency":
				currentLayout.sortField = "preempt"
				currentLayout.sortDescending = true
			case "preempt":
				currentLayout.sortField = "vol_ctx"
				currentLayout.sortDescending = true
			case "vol_ctx":
				currentLayout.sortField = "invol_ctx"
				currentLayout.sortDescending = true
			case "invol_ctx":
				currentLayout.sortField = "migrations"
				currentLayout.sortDescending = true
			default:
				currentLayout.sortField = "latency"
				currentLayout.sortDescending = true
			}
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

		// 按 'r' 或 'R' 重置为默认视图
		if char == 'r' || char == 'R' {
			currentView = ViewScheduling
			currentLayout = ColumnLayout{columnSet: ColSetBasic, sortField: "latency", sortDescending: true, scrollOffset: 0}
		}

		// 按 '/' 打开列选择菜单（快速选择）
		if char == '/' {
			showColumnMenu()
		}
	}
}

func showColumnMenu() {
	// 清屏并显示菜单
	fmt.Print("\033[H\033[2J")
	fmt.Println("Select Column Group (press number 1-5 or q to cancel):")
	fmt.Println("[1] BASIC (PID, COMM, LATENCY, PREEMPT, STACK)")
	fmt.Println("[2] CTXT_SWITCH (VOL_CTX, INVOL_CTX, CTX_TOTAL)")
	fmt.Println("[3] MIGRATION (MIGRATIONS, AVG_DIST)")
	fmt.Println("[4] OFF_CPU (OFF_CPU_TIME, COUNT)")
	fmt.Println("[5] FULL (All columns)")

	// 读取用户选择
	b := make([]byte, 1)
	_, _ = os.Stdin.Read(b)
	char := b[0]

	switch char {
	case '1':
		currentLayout.columnSet = ColSetBasic
	case '2':
		currentLayout.columnSet = ColSetCtxtSwitch
	case '3':
		currentLayout.columnSet = ColSetMigration
	case '4':
		currentLayout.columnSet = ColSetOffCPU
	case '5':
		currentLayout.columnSet = ColSetFull
	}
	currentLayout.scrollOffset = 0
}

func getStackSymbols(stackID int32) string {
	// 1. 基础校验：如果 ID 非法（<=0）或者没有加载 eBPF 集合，直接返回横杠
	if stackID <= 0 || ebpfCollection == nil {
		return "-"
	}

	// 2. 从加载好的 eBPF 集合中获取名为 "stack_traces" 的 Map
	// 这个 Map 是由内核填充的，Key 是 StackID，Value 是内核指令指针（地址）数组
	stackMap := ebpfCollection.Maps["stack_traces"]
	if stackMap == nil {
		return "no map"
	}

	// 3. 准备接收容器：内核堆栈深度通常最大为 127 层，存储的是 64 位内存地址
	var addresses [127]uint64

	// 4. 从内核 Map 中查询数据：根据 stackID 找到对应的地址数组
	if err := stackMap.Lookup(uint32(stackID), &addresses); err != nil {
		// 如果查不到（可能已被内核自动清理），则退而求其次只返回 ID 本身
		return fmt.Sprintf("ID:%d", stackID)
	}

	// 5. 符号化逻辑：将内存地址“翻译”为函数名
	var syms []string
	for _, addr := range addresses {
		// 地址 0 表示堆栈结束
		if addr == 0 {
			break
		}
		// ResolveSymbol 是关键函数：它去查之前加载好的内核符号表（/proc/kallsyms）
		// 将地址（如 0xffffffff81234abc）转换为函数名（如 "vfs_read"）
		syms = append(syms, ResolveSymbol(addr))
	}

	// 6. 如果查到了地址但翻译不出任何函数名，返回 ID
	if len(syms) == 0 {
		return fmt.Sprintf("ID:%d", stackID)
	}

	// 7. 界面优化：为了防止屏幕被长达 100 多层的调用栈刷屏，只取最顶层的 3 层函数
	// 最顶层通常是导致延迟最直接的代码逻辑位置
	displayLen := 3
	if len(syms) < displayLen {
		displayLen = len(syms)
	}

	// 8. 格式化输出：用 "->" 箭头连接函数名，例如 "vfs_write->do_iter_write->ext4_file_write"
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
	// --- 第一部分：清屏与头部信息渲染 ---
	// 使用 ANSI 转义字符：\033[H (光标复位到左上角), \033[2J (清空屏幕)
	// 这样可以实现原地刷新的效果，而不是不断向下滚动
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

	// --- 第二部分：数据快照提取 ---
	// 将并发安全的 sync.Map 中的数据拷贝到切片 metrics 中，方便后续排序
	var metrics []metadata.SchedMetrics
	cache.SchedMetricsMap.Range(func(key, value interface{}) bool {
		m := value.(metadata.SchedMetrics)
		metrics = append(metrics, m)
		return true
	})

	// --- 第三部分：动态排序逻辑 ---
	// 这是看板的灵魂：根据当前不同的视图，按不同的权重进行倒序排列（大的在前）
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

	// 限制显示数量，只展示前 20 名（Top 20）
	displayCount := 20
	if len(metrics) < displayCount {
		displayCount = len(metrics)
	}

	// --- 第四部分：表格内容渲染 ---
	// 根据视图类型，打印不同的表头和格式化行
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

	// --- 第五部分：底部辅助信息渲染 ---
	// 如果在调度视图下，额外展示“谁在抢占别人”的排行榜
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
