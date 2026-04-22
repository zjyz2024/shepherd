package output

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/cen-ngc5139/shepherd/internal/cache"
	"github.com/cen-ngc5139/shepherd/internal/metadata"
)

// renderMemCLI 是 ViewMemory 的主入口，由 cli.go:renderCLI 分发过来。
// Phase M1 仅实现 ColSetMemAlloc（其余 ColSetMem* 在后续 phase 逐步补齐）
func renderMemCLI() {
	fmt.Print("\033[H\033[2J")

	colSetName := getMemColumnSetName(currentLayout.columnSet)
	fmt.Printf("Shepherd Diagnostic Top [MEMORY] - %s\r\n", time.Now().Format("15:04:05"))
	fmt.Printf("ColumnSet: %s | Sort: %s %s | Symbols: %s\r\n",
		colSetName,
		currentLayout.sortField,
		map[bool]string{true: "DESC", false: "ASC"}[currentLayout.sortDescending],
		map[bool]string{true: "ON", false: "OFF"}[EnableStackSymbol])
	fmt.Print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\r\n")

	switch currentLayout.columnSet {
	case ColSetMemAlloc, ColSetMemFull:
		renderMemAllocTable()
	default:
		// M2-M5 未实现时占位
		fmt.Printf("\r\n  [ColumnSet %s] 尚未实现（后续 Phase 补齐）\r\n", colSetName)
	}

	renderMemHints()
}

func renderMemAllocTable() {
	columns := columnDefinitions[ColSetMemAlloc]
	if currentLayout.columnSet == ColSetMemFull {
		columns = columnDefinitions[ColSetMemFull]
	}

	var metrics []metadata.MemAllocMetrics
	cache.MemAllocMap.Range(func(key, value interface{}) bool {
		m := value.(metadata.MemAllocMetrics)
		metrics = append(metrics, m)
		return true
	})

	sortMemAllocMetrics(metrics, currentLayout.sortField, currentLayout.sortDescending)

	displayCount := 20
	if len(metrics) < displayCount {
		displayCount = len(metrics)
	}

	renderTableHeader(columns)
	for i := 0; i < displayCount; i++ {
		renderMemAllocRow(&metrics[i], columns)
	}
}

func renderMemAllocRow(m *metadata.MemAllocMetrics, columns []Column) {
	avgNs := uint64(0)
	if m.AllocCount > 0 {
		avgNs = m.TotalAllocNs / m.AllocCount
	}
	for _, col := range columns {
		var cell string
		switch col.name {
		case "pid":
			cell = fmt.Sprintf("%d", m.Pid)
		case "comm":
			cell = m.Comm
		case "alloc_cnt":
			cell = fmt.Sprintf("%d", m.AllocCount)
		case "slow_cnt":
			cell = fmt.Sprintf("%d", m.SlowPathCount)
		case "mid_cnt":
			cell = fmt.Sprintf("%d", m.MidPathCount)
		case "avg_us":
			cell = fmt.Sprintf("%.2f", float64(avgNs)/1e3)
		case "max_us":
			cell = fmt.Sprintf("%.2f", float64(m.MaxAllocNs)/1e3)
		case "order_hist":
			cell = renderHistogram(m.OrderHistogram[:])
		case "stack":
			cell = formatStack(m.LastStackId)
		default:
			cell = "-"
		}
		if col.alignLeft {
			fmt.Printf("%-*s ", col.width, truncate(cell, col.width))
		} else {
			fmt.Printf("%*s ", col.width, truncate(cell, col.width))
		}
	}
	fmt.Print("\r\n")
}

// renderHistogram 用 unicode block glyph 画单行直方图。
// 桶数 = len(buckets)；单个字符一个桶。
func renderHistogram(buckets []uint64) string {
	glyphs := []rune{'▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'}

	var maxVal uint64
	for _, v := range buckets {
		if v > maxVal {
			maxVal = v
		}
	}

	var sb strings.Builder
	for _, v := range buckets {
		if maxVal == 0 || v == 0 {
			sb.WriteRune(' ')
			continue
		}
		idx := int(float64(v) / float64(maxVal) * float64(len(glyphs)-1))
		if idx >= len(glyphs) {
			idx = len(glyphs) - 1
		}
		sb.WriteRune(glyphs[idx])
	}
	return sb.String()
}

func truncate(s string, width int) string {
	if len(s) <= width {
		return s
	}
	if width <= 3 {
		return s[:width]
	}
	return s[:width-3] + "..."
}

func sortMemAllocMetrics(metrics []metadata.MemAllocMetrics, field string, descending bool) {
	sort.Slice(metrics, func(i, j int) bool {
		var a, b uint64
		switch field {
		case "slow_count":
			a, b = metrics[i].SlowPathCount, metrics[j].SlowPathCount
		case "alloc_cnt":
			a, b = metrics[i].AllocCount, metrics[j].AllocCount
		case "max_ns":
			a, b = metrics[i].MaxAllocNs, metrics[j].MaxAllocNs
		case "alloc_ns":
			fallthrough
		default:
			a, b = metrics[i].TotalAllocNs, metrics[j].TotalAllocNs
		}
		if descending {
			return a > b
		}
		return a < b
	})
}

func getMemColumnSetName(cs ColumnSet) string {
	names := map[ColumnSet]string{
		ColSetMemAlloc:   "MEM_ALLOC",
		ColSetMemReclaim: "MEM_RECLAIM",
		ColSetMemLeak:    "MEM_LEAK",
		ColSetMemFault:   "MEM_FAULT",
		ColSetMemOOM:     "MEM_OOM",
		ColSetMemFull:    "MEM_FULL",
	}
	if n, ok := names[cs]; ok {
		return n
	}
	return "UNKNOWN"
}

func renderMemHints() {
	fmt.Print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\r\n")
	fmt.Printf("Hints: l=列切换  t=排序(alloc_ns/slow_count/alloc_cnt/max_ns)  d=调度  n=其他视图  s=符号  r=重置  q=退出\r\n")
}
