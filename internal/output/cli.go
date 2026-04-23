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
	ColSetPriorityInversion
	ColSetFull
	// === Phase M1+: Memory 视图的列组 ===
	ColSetMemAlloc
	ColSetMemReclaim
	ColSetMemLeak
	ColSetMemFault
	ColSetMemOOM
	ColSetMemFull
	ColSetMax
)

// 调度视图 ColumnSet 的边界（[SchedBegin, SchedEnd]），供 'l' 键循环使用
const (
	schedColSetBegin = ColSetBasic
	schedColSetEnd   = ColSetFull
	memColSetBegin   = ColSetMemAlloc
	memColSetEnd     = ColSetMemOOM
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
	ColSetPriorityInversion: {
		{name: "pid", label: "PID", width: 8, alignLeft: false},
		{name: "comm", label: "COMM", width: 20, alignLeft: true},
		{name: "pi_count", label: "PI_COUNT", width: 12, alignLeft: false},
		{name: "max_block_time", label: "MAX_BLOCK_TIME(ms)", width: 18, alignLeft: false},
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
		{name: "pi_count", label: "PI_COUNT", width: 12, alignLeft: false},
		{name: "max_block_time", label: "MAX_BLOCK(ms)", width: 15, alignLeft: false},
	},
	// === Phase M1: Memory 视图列组 ===
	ColSetMemAlloc: {
		{name: "pid", label: "PID", width: 8, alignLeft: false},
		{name: "comm", label: "COMM", width: 20, alignLeft: true},
		{name: "alloc_cnt", label: "ALLOC_CNT", width: 12, alignLeft: false},
		{name: "slow_cnt", label: "SLOW_CNT", width: 10, alignLeft: false},
		{name: "mid_cnt", label: "MID_CNT", width: 10, alignLeft: false},
		{name: "avg_us", label: "AVG(us)", width: 12, alignLeft: false},
		{name: "max_us", label: "MAX(us)", width: 12, alignLeft: false},
		{name: "order_hist", label: "ORDER_HIST", width: 13, alignLeft: true},
		{name: "stack", label: "SLOW_STACK", width: 30, alignLeft: true},
	},
	// === Phase M2: Reclaim Pressure ===
	ColSetMemReclaim: {
		{name: "pid", label: "PID", width: 8, alignLeft: false},
		{name: "comm", label: "COMM", width: 20, alignLeft: true},
		{name: "direct_cnt", label: "DIRECT_CNT", width: 12, alignLeft: false},
		{name: "direct_ms", label: "DIRECT(ms)", width: 12, alignLeft: false},
		{name: "max_direct_ms", label: "MAX_DIRECT(ms)", width: 16, alignLeft: false},
		{name: "kswapd_cnt", label: "KSWAPD_WAKE", width: 12, alignLeft: false},
		{name: "lru_inactive", label: "LRU_INACT", width: 12, alignLeft: false},
		{name: "lru_active", label: "LRU_ACT", width: 10, alignLeft: false},
		{name: "nr_reclaimed", label: "PAGES_RCLMD", width: 13, alignLeft: false},
	},
	ColSetMemFull: {
		{name: "pid", label: "PID", width: 8, alignLeft: false},
		{name: "comm", label: "COMM", width: 20, alignLeft: true},
		{name: "alloc_cnt", label: "ALLOC_CNT", width: 12, alignLeft: false},
		{name: "slow_cnt", label: "SLOW_CNT", width: 10, alignLeft: false},
		{name: "avg_us", label: "AVG(us)", width: 12, alignLeft: false},
		{name: "max_us", label: "MAX(us)", width: 12, alignLeft: false},
		{name: "order_hist", label: "ORDER_HIST", width: 13, alignLeft: true},
		{name: "stack", label: "SLOW_STACK", width: 30, alignLeft: true},
	},
	// === Phase M5: OOM Killer ===
	ColSetMemOOM: {
		{name: "ts", label: "TIME", width: 10, alignLeft: false},
		{name: "victim_pid", label: "V_PID", width: 8, alignLeft: false},
		{name: "victim_comm", label: "VICTIM", width: 20, alignLeft: true},
		{name: "rss_mb", label: "RSS(MB)", width: 10, alignLeft: false},
		{name: "trigger_pid", label: "T_PID", width: 8, alignLeft: false},
		{name: "trigger_comm", label: "TRIGGER", width: 20, alignLeft: true},
		{name: "oom_score", label: "SCORE", width: 8, alignLeft: false},
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
	EnableStackSymbol = true
	ebpfCollection    *ebpf.Collection
)

func StartDiagnosticCLI(ctx context.Context, cancel context.CancelFunc, coll *ebpf.Collection) {
	ebpfCollection = coll

	if EnableStackSymbol {
		_ = LoadKallsyms()
	}

	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err == nil {
		defer term.Restore(int(os.Stdin.Fd()), oldState)
	}

	go listenKeyboard(cancel)

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			fmt.Print("\033[H\033[2J")
			fmt.Println("Exiting Shepherd...")
			return
		case <-ticker.C:
			renderCLI()
		}
	}
}

func listenKeyboard(cancel context.CancelFunc) {
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
			// 视图切换时，根据目标视图重置 ColumnSet
			switch currentView {
			case ViewScheduling:
				currentLayout.columnSet = ColSetBasic
				currentLayout.sortField = "latency"
			case ViewMemory:
				currentLayout.columnSet = ColSetMemAlloc
				currentLayout.sortField = "alloc_ns"
			}
			currentLayout.scrollOffset = 0
		}

		// 按 'd' 或 'D' 回到调度视图
		if char == 'd' || char == 'D' {
			currentView = ViewScheduling
			currentLayout.columnSet = ColSetBasic
			currentLayout.sortField = "latency"
			currentLayout.scrollOffset = 0
		}

		// 按 'm' 或 'M' 直跳内存视图
		if char == 'm' || char == 'M' {
			currentView = ViewMemory
			currentLayout.columnSet = ColSetMemAlloc
			currentLayout.sortField = "alloc_ns"
			currentLayout.scrollOffset = 0
		}

		// 按 'l' 或 'L' 循环切换列组（按视图隔离范围）
		if char == 'l' || char == 'L' {
			switch currentView {
			case ViewScheduling:
				next := currentLayout.columnSet + 1
				if next > schedColSetEnd {
					next = schedColSetBegin
				}
				currentLayout.columnSet = next
			case ViewMemory:
				next := currentLayout.columnSet + 1
				if next > memColSetEnd {
					next = memColSetBegin
				}
				currentLayout.columnSet = next
			}
			currentLayout.scrollOffset = 0
		}

		// 按 't' 或 'T' 切换排序字段（按视图隔离序列）
		if char == 't' || char == 'T' {
			if currentView == ViewMemory {
				switch currentLayout.sortField {
				case "alloc_ns":
					currentLayout.sortField = "slow_count"
				case "slow_count":
					currentLayout.sortField = "alloc_cnt"
				case "alloc_cnt":
					currentLayout.sortField = "max_ns"
				case "max_ns":
					currentLayout.sortField = "reclaim_ns"
				case "reclaim_ns":
					currentLayout.sortField = "kswapd_wake"
				case "kswapd_wake":
					currentLayout.sortField = "direct_cnt"
				default:
					currentLayout.sortField = "alloc_ns"
				}
			} else {
				switch currentLayout.sortField {
				case "latency":
					currentLayout.sortField = "preempt"
				case "preempt":
					currentLayout.sortField = "vol_ctx"
				case "vol_ctx":
					currentLayout.sortField = "invol_ctx"
				case "invol_ctx":
					currentLayout.sortField = "migrations"
				case "migrations":
					currentLayout.sortField = "pi_count"
				default:
					currentLayout.sortField = "latency"
				}
			}
			currentLayout.sortDescending = true
		}

		// 按 's' 或 'S' 切换符号开关
		if char == 's' || char == 'S' {
			EnableStackSymbol = !EnableStackSymbol
		}

		// 按 'q' 或 'Q' 或 Ctrl+C 退出
		if char == 'q' || char == 'Q' || char == 3 {
			cancel()
			return
		}

		// 按 'r' 或 'R' 重置为默认视图
		if char == 'r' || char == 'R' {
			currentView = ViewScheduling
			currentLayout = ColumnLayout{columnSet: ColSetBasic, sortField: "latency", sortDescending: true, scrollOffset: 0}
		}

		// 按 '/' 打开列选择菜单
		if char == '/' {
			showColumnMenu()
		}
	}
}

func showColumnMenu() {
	fmt.Print("\033[H\033[2J")
	fmt.Println("Select Column Group (press number 1-6 or q to cancel):")
	fmt.Println("[1] BASIC (PID, COMM, LATENCY, PREEMPT, STACK)")
	fmt.Println("[2] CTXT_SWITCH (VOL_CTX, INVOL_CTX, CTX_TOTAL)")
	fmt.Println("[3] MIGRATION (MIGRATIONS, AVG_DIST)")
	fmt.Println("[4] OFF_CPU (OFF_CPU_TIME, COUNT)")
	fmt.Println("[5] PRIORITY_INVERSION (PI_COUNT, MAX_BLOCK_TIME)")
	fmt.Println("[6] FULL (All columns)")

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
		currentLayout.columnSet = ColSetPriorityInversion
	case '6':
		currentLayout.columnSet = ColSetFull
	}
	currentLayout.scrollOffset = 0
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

	displayLen := 3
	if len(syms) < displayLen {
		displayLen = len(syms)
	}

	return strings.Join(syms[:displayLen], "->")
}

func formatStack(stackID int32) string {
	if !EnableStackSymbol {
		return fmt.Sprintf("%d", stackID)
	}
	return getStackSymbols(stackID)
}

// 新的 renderCLI 实现：支持多列布局
func renderCLI() {
	if currentView == ViewMemory {
		renderMemCLI()
		return
	}
	if currentView != ViewScheduling {
		renderCLILegacy()
		return
	}

	fmt.Print("\033[H\033[2J")

	colSetName := getColumnSetName(currentLayout.columnSet)
	fmt.Printf("Shepherd Diagnostic Top [SCHEDULING] - %s\r\n", time.Now().Format("15:04:05"))
	fmt.Printf("ColumnSet: %s | Sort: %s %s | Symbols: %s\r\n",
		colSetName,
		currentLayout.sortField,
		map[bool]string{true: "DESC", false: "ASC"}[currentLayout.sortDescending],
		map[bool]string{true: "ON", false: "OFF"}[EnableStackSymbol])
	fmt.Print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\r\n")

	var metrics []metadata.SchedMetrics
	cache.SchedMetricsMap.Range(func(key, value interface{}) bool {
		m := value.(metadata.SchedMetrics)
		metrics = append(metrics, m)
		return true
	})

	sortMetrics(metrics, currentLayout.sortField, currentLayout.sortDescending)

	columns := columnDefinitions[currentLayout.columnSet]

	displayCount := 20
	if len(metrics) < displayCount {
		displayCount = len(metrics)
	}

	renderTableHeader(columns)

	for i := 0; i < displayCount; i++ {
		renderTableRow(&metrics[i], columns)
	}

	renderHints()
}

// 旧的渲染逻辑（用于内存/中断视图）
func renderCLILegacy() {
	fmt.Print("\033[H\033[2J")

	header := "Shepherd Diagnostic Top"
	switch currentView {
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
}

func getColumnSetName(cs ColumnSet) string {
	names := map[ColumnSet]string{
		ColSetBasic:      "BASIC",
		ColSetCtxtSwitch: "CTXT_SWITCH",
		ColSetMigration:  "MIGRATION",
		ColSetOffCPU:     "OFF_CPU",
		ColSetFull:       "FULL",
	}
	return names[cs]
}

func sortMetrics(metrics []metadata.SchedMetrics, field string, descending bool) {
	sort.Slice(metrics, func(i, j int) bool {
		var cmpI, cmpJ uint64
		switch field {
		case "latency":
			cmpI, cmpJ = metrics[i].DelayNs, metrics[j].DelayNs
		case "preempt":
			cmpI, cmpJ = metrics[i].PreempteCount, metrics[j].PreempteCount
		case "vol_ctx":
			cmpI, cmpJ = metrics[i].VoluntaryCtxtSwitches, metrics[j].VoluntaryCtxtSwitches
		case "invol_ctx":
			cmpI, cmpJ = metrics[i].InvoluntaryCtxtSwitches, metrics[j].InvoluntaryCtxtSwitches
		case "migrations":
			cmpI, cmpJ = metrics[i].MigrationCount, metrics[j].MigrationCount
		case "pi_count":
			cmpI, cmpJ = metrics[i].PriorityInversionCount, metrics[j].PriorityInversionCount
		default:
			cmpI, cmpJ = metrics[i].DelayNs, metrics[j].DelayNs
		}

		if descending {
			return cmpI > cmpJ
		}
		return cmpI < cmpJ
	})
}

func renderTableHeader(columns []Column) {
	for _, col := range columns {
		fmt.Printf("%-*s ", col.width, col.label)
	}
	fmt.Print("\r\n")
	for _, col := range columns {
		for k := 0; k < col.width; k++ {
			fmt.Print("─")
		}
		fmt.Print(" ")
	}
	fmt.Print("\r\n")
}

func renderTableRow(m *metadata.SchedMetrics, columns []Column) {
	for _, col := range columns {
		var cellValue string
		switch col.name {
		case "pid":
			cellValue = fmt.Sprintf("%d", m.Pid)
		case "comm":
			cellValue = m.Comm
		case "latency":
			cellValue = fmt.Sprintf("%.3f", float64(m.DelayNs)/1e6)
		case "preempt":
			cellValue = fmt.Sprintf("%d", m.PreempteCount)
		case "vol_ctx":
			cellValue = fmt.Sprintf("%d", m.VoluntaryCtxtSwitches)
		case "invol_ctx":
			cellValue = fmt.Sprintf("%d", m.InvoluntaryCtxtSwitches)
		case "ctx_total":
			cellValue = fmt.Sprintf("%d", m.VoluntaryCtxtSwitches+m.InvoluntaryCtxtSwitches)
		case "migrations":
			cellValue = fmt.Sprintf("%d", m.MigrationCount)
		case "avg_dist":
			cellValue = fmt.Sprintf("%.2f", m.AvgMigrationDist)
		case "offcpu_time":
			cellValue = fmt.Sprintf("%.3f", float64(m.OffCPUTimeNs)/1e6)
		case "offcpu_count":
			cellValue = fmt.Sprintf("%d", m.OffCPUEventCount)
		case "pi_count":
			cellValue = fmt.Sprintf("%d", m.PriorityInversionCount)
		case "max_block_time":
			cellValue = fmt.Sprintf("%.3f", float64(m.MaxInversionBlockTimeNs)/1e6)
		case "stack":
			cellValue = formatStack(m.StackId)
		default:
			cellValue = "-"
		}

		if col.alignLeft {
			fmt.Printf("%-*s ", col.width, cellValue)
		} else {
			fmt.Printf("%*s ", col.width, cellValue)
		}
	}
	fmt.Print("\r\n")
}

func renderHints() {
	fmt.Print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\r\n")
	fmt.Printf("Hints: l=列切换  t=排序  d=调度  n=其他视图  s=符号  /=菜单  r=重置  q=退出\r\n")
}
