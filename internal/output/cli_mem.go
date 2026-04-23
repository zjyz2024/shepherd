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
func renderMemCLI() {
	fmt.Print("\033[H\033[2J")

	// 顶部渲染 OOM 告警横幅（如果有最近的 OOM 事件）
	renderOOMAlertBanner()

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
	case ColSetMemReclaim:
		renderMemReclaimTable()
	case ColSetMemOOM:
		renderMemOOMTable()
	default:
		// M3-M4 未实现时占位
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

// renderOOMAlertBanner 在页面顶部渲染 OOM 告警（红色粗体）
// 仅显示最近 5 分钟内的 OOM 事件
func renderOOMAlertBanner() {
	if cache.OOMEventRing == nil || cache.OOMEventRing.Len() == 0 {
		return
	}

	events := cache.OOMEventRing.Snapshot()
	now := time.Now().Unix()
	const fiveMinInSeconds = 5 * 60
	recentOOMs := make([]metadata.OOMEvent, 0)

	for _, ev := range events {
		oomEv := ev.(metadata.OOMEvent)
		if int64(oomEv.Ts/1e9) > now-fiveMinInSeconds {
			recentOOMs = append(recentOOMs, oomEv)
		}
	}

	if len(recentOOMs) == 0 {
		return
	}

	// 显示最后一条 OOM（最新事件）
	lastOOM := recentOOMs[len(recentOOMs)-1]
	oomTime := time.Unix(0, int64(lastOOM.Ts)).Format("15:04:05")
	rss := lastOOM.VictimRssBytes / 1024 / 1024

	// ANSI 红色粗体：\033[41;1;37m（红底、粗体、白字）
	fmt.Printf("\033[41;1;37m !!! OOM DETECTED at %s !!! \033[0m\r\n", oomTime)
	fmt.Printf("\033[41;1;37m victim=%s(pid=%d) rss=%d MB | trigger=%s(pid=%d) | score=%d \033[0m\r\n",
		lastOOM.VictimComm, lastOOM.VictimPid, rss,
		lastOOM.TriggerComm, lastOOM.TriggerPid, lastOOM.OomScore)

	// 显示 top 进程列表（如果有）
	if len(lastOOM.TopProcesses) > 0 {
		fmt.Print("\033[41;1;37m TOP PROCESSES at OOM time: \033[0m\r\n")
		for i, proc := range lastOOM.TopProcesses {
			if i >= 5 { // 只显示前 5
				break
			}
			procRss := proc.RssBytes / 1024 / 1024
			fmt.Printf("  %2d. %-16s (pid=%d) rss=%4d MB\r\n",
				i+1, proc.Comm, proc.Pid, procRss)
		}
	}

	fmt.Print("\r\n")
}

// renderMemOOMTable 渲染 OOM 事件表
func renderMemOOMTable() {
	if cache.OOMEventRing == nil || cache.OOMEventRing.Len() == 0 {
		fmt.Printf("  (无 OOM 事件)\r\n")
		return
	}

	events := cache.OOMEventRing.Snapshot()
	oomEvents := make([]metadata.OOMEvent, 0, len(events))
	for _, ev := range events {
		oomEvents = append(oomEvents, ev.(metadata.OOMEvent))
	}

	// 按时间降序
	sort.Slice(oomEvents, func(i, j int) bool {
		return oomEvents[i].Ts > oomEvents[j].Ts
	})

	columns := columnDefinitions[ColSetMemOOM]
	renderTableHeader(columns)

	displayCount := 20
	if len(oomEvents) < displayCount {
		displayCount = len(oomEvents)
	}

	for i := 0; i < displayCount; i++ {
		renderMemOOMRow(&oomEvents[i], columns)
	}
}

// renderMemOOMRow 渲染一行 OOM 事件
func renderMemOOMRow(ev *metadata.OOMEvent, columns []Column) {
	for _, col := range columns {
		var cell string
		switch col.name {
		case "ts":
			t := time.Unix(0, int64(ev.Ts))
			cell = t.Format("15:04:05")
		case "victim_pid":
			cell = fmt.Sprintf("%d", ev.VictimPid)
		case "victim_comm":
			cell = ev.VictimComm
		case "rss_mb":
			cell = fmt.Sprintf("%d", ev.VictimRssBytes/1024/1024)
		case "trigger_pid":
			cell = fmt.Sprintf("%d", ev.TriggerPid)
		case "trigger_comm":
			cell = ev.TriggerComm
		case "oom_score":
			cell = fmt.Sprintf("%d", ev.OomScore)
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
	fmt.Printf("Hints: l=列切换  t=排序(alloc_ns/slow_count/alloc_cnt/max_ns/reclaim_ns/kswapd_wake)  d=调度  n=其他视图  s=符号  r=重置  q=退出\r\n")
}

// Phase M2: Reclaim Pressure 表格渲染
func renderMemReclaimTable() {
	columns := columnDefinitions[ColSetMemReclaim]

	var metrics []metadata.MemReclaimMetrics
	cache.MemReclaimMap.Range(func(key, value interface{}) bool {
		m := value.(metadata.MemReclaimMetrics)
		metrics = append(metrics, m)
		return true
	})

	sortMemReclaimMetrics(metrics, currentLayout.sortField, currentLayout.sortDescending)

	displayCount := 20
	if len(metrics) < displayCount {
		displayCount = len(metrics)
	}

	renderTableHeader(columns)
	for i := 0; i < displayCount; i++ {
		renderMemReclaimRow(&metrics[i], columns)
	}
}

func renderMemReclaimRow(m *metadata.MemReclaimMetrics, columns []Column) {
	for _, col := range columns {
		var cell string
		switch col.name {
		case "pid":
			if m.Pid == metadata.MemReclaimGlobalKey {
				cell = "-"
			} else {
				cell = fmt.Sprintf("%d", m.Pid)
			}
		case "comm":
			cell = m.Comm
		case "direct_cnt":
			cell = fmt.Sprintf("%d", m.DirectReclaimCount)
		case "direct_ms":
			cell = fmt.Sprintf("%.3f", float64(m.DirectReclaimNs)/1e6)
		case "max_direct_ms":
			cell = fmt.Sprintf("%.3f", float64(m.MaxDirectReclaimNs)/1e6)
		case "kswapd_cnt":
			cell = fmt.Sprintf("%d", m.KswapdWakeCount)
		case "lru_inactive":
			cell = fmt.Sprintf("%d", m.LRUInactiveCount)
		case "lru_active":
			cell = fmt.Sprintf("%d", m.LRUActiveCount)
		case "nr_reclaimed":
			cell = fmt.Sprintf("%d", m.NrReclaimedTotal)
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

func sortMemReclaimMetrics(metrics []metadata.MemReclaimMetrics, field string, descending bool) {
	sort.Slice(metrics, func(i, j int) bool {
		var a, b uint64
		switch field {
		case "kswapd_wake":
			a, b = metrics[i].KswapdWakeCount, metrics[j].KswapdWakeCount
		case "direct_cnt":
			a, b = metrics[i].DirectReclaimCount, metrics[j].DirectReclaimCount
		case "max_ns":
			a, b = metrics[i].MaxDirectReclaimNs, metrics[j].MaxDirectReclaimNs
		case "reclaim_ns":
			fallthrough
		default:
			a, b = metrics[i].DirectReclaimNs, metrics[j].DirectReclaimNs
		}
		if descending {
			return a > b
		}
		return a < b
	})
}

// renderOOMAlertBanner 在页面顶部渲染 OOM 告警（红色粗体）
// 仅显示最近 5 分钟内的 OOM 事件
func renderOOMAlertBanner() {
	if cache.OOMEventRing == nil || cache.OOMEventRing.Len() == 0 {
		return
	}

	events := cache.OOMEventRing.Snapshot()
	now := time.Now().Unix()
	const fiveMinInSeconds = 5 * 60
	recentOOMs := make([]metadata.OOMEvent, 0)

	for _, ev := range events {
		oomEv := ev.(metadata.OOMEvent)
		if int64(oomEv.Ts/1e9) > now-fiveMinInSeconds {
			recentOOMs = append(recentOOMs, oomEv)
		}
	}

	if len(recentOOMs) == 0 {
		return
	}

	// 显示最后一条 OOM（最新事件）
	lastOOM := recentOOMs[len(recentOOMs)-1]
	oomTime := time.Unix(0, int64(lastOOM.Ts)).Format("15:04:05")
	rss := lastOOM.VictimRssBytes / 1024 / 1024

	// ANSI 红色粗体：\033[41;1;37m（红底、粗体、白字）
	fmt.Printf("\033[41;1;37m !!! OOM DETECTED at %s !!! \033[0m\r\n", oomTime)
	fmt.Printf("\033[41;1;37m victim=%s(pid=%d) rss=%d MB | trigger=%s(pid=%d) | score=%d \033[0m\r\n",
		lastOOM.VictimComm, lastOOM.VictimPid, rss,
		lastOOM.TriggerComm, lastOOM.TriggerPid, lastOOM.OomScore)

	// 显示 top 进程列表（如果有）
	if len(lastOOM.TopProcesses) > 0 {
		fmt.Print("\033[41;1;37m TOP PROCESSES at OOM time: \033[0m\r\n")
		for i, proc := range lastOOM.TopProcesses {
			if i >= 5 { // 只显示前 5
				break
			}
			procRss := proc.RssBytes / 1024 / 1024
			fmt.Printf("  %2d. %-16s (pid=%d) rss=%4d MB\r\n",
				i+1, proc.Comm, proc.Pid, procRss)
		}
	}

	fmt.Print("\r\n")
}

// renderMemOOMTable 渲染 OOM 事件表
func renderMemOOMTable() {
	if cache.OOMEventRing == nil || cache.OOMEventRing.Len() == 0 {
		fmt.Printf("  (无 OOM 事件)\r\n")
		return
	}

	events := cache.OOMEventRing.Snapshot()
	oomEvents := make([]metadata.OOMEvent, 0, len(events))
	for _, ev := range events {
		oomEvents = append(oomEvents, ev.(metadata.OOMEvent))
	}

	// 按时间降序
	sort.Slice(oomEvents, func(i, j int) bool {
		return oomEvents[i].Ts > oomEvents[j].Ts
	})

	columns := columnDefinitions[ColSetMemOOM]
	renderTableHeader(columns)

	displayCount := 20
	if len(oomEvents) < displayCount {
		displayCount = len(oomEvents)
	}

	for i := 0; i < displayCount; i++ {
		renderMemOOMRow(&oomEvents[i], columns)
	}
}

// renderMemOOMRow 渲染一行 OOM 事件
func renderMemOOMRow(ev *metadata.OOMEvent, columns []Column) {
	for _, col := range columns {
		var cell string
		switch col.name {
		case "ts":
			t := time.Unix(0, int64(ev.Ts))
			cell = t.Format("15:04:05")
		case "victim_pid":
			cell = fmt.Sprintf("%d", ev.VictimPid)
		case "victim_comm":
			cell = ev.VictimComm
		case "rss_mb":
			cell = fmt.Sprintf("%d", ev.VictimRssBytes/1024/1024)
		case "trigger_pid":
			cell = fmt.Sprintf("%d", ev.TriggerPid)
		case "trigger_comm":
			cell = ev.TriggerComm
		case "oom_score":
			cell = fmt.Sprintf("%d", ev.OomScore)
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
