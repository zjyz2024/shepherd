package output

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	ckdriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/cen-ngc5139/shepherd/internal/cache"
	"github.com/cen-ngc5139/shepherd/internal/log"
	"github.com/cen-ngc5139/shepherd/internal/metadata"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
)

// oomBatch 和 cliSink 是全局变量，由 output.go 初始化
var (
	oomBatch ckdriver.Batch
	cliSink  *SinkCli
)

// ProcessOOM 从 eBPF perf buffer 读取 OOM 事件
func ProcessOOM(coll *ebpf.Collection, ctx context.Context) error {
	oomEvents := coll.Maps["mem_oom_events"]
	if oomEvents == nil {
		log.Warningf("mem_oom_events map not found in BPF collection")
		return nil
	}

	reader, err := perf.NewReader(oomEvents, os.Getpagesize())
	if err != nil {
		return fmt.Errorf("failed to create mem_oom event reader: %w", err)
	}
	defer reader.Close()

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		record, err := reader.Read()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				log.Warningf("read mem_oom_events error: %v", err)
				continue
			}
		}

		if record.LostSamples > 0 {
			log.Warningf("mem_oom_events lost %d samples", record.LostSamples)
		}

		// 解析 BPF 事件
		ev := parseOOMEvent(record.RawSample)
		if ev == nil {
			continue
		}

		// 补充 RSS 和 oom_score_adj：从 /proc 读取
		supplementOOMSnapshot(ev)

		// 推送到环形缓冲（用于 CLI 显示告警）
		cache.OOMEventRing.Push(*ev)

		// 异步发送到 ClickHouse（如果配置）
		if cliSink != nil {
			go insertOOMEvent(ev)
		}

		// 写日志
		log.Infof("OOM KILLED: victim=%s(pid=%d) rss=%d MB, trigger=%s(pid=%d), score=%d",
			ev.VictimComm, ev.VictimPid, ev.VictimRssBytes/1024/1024,
			ev.TriggerComm, ev.TriggerPid, ev.OomScore)
	}
}

// parseOOMEvent 从原始样本解析 OOM 事件
func parseOOMEvent(rawSample []byte) *metadata.OOMEvent {
	if len(rawSample) < 80 {
		return nil
	}

	// mem_oom_event_t 结构体：
	// ts(8) + victim_pid(4) + victim_tgid(4) + victim_rss_bytes(8) +
	// trigger_pid(4) + trigger_tgid(4) + oom_score(4) + is_cgroup(1) + pad0(3) +
	// victim_comm(16) + trigger_comm(16) + pad1(8) = 80 字节

	ts := bytesToU64(rawSample[0:8])
	victimPid := bytesToU32(rawSample[8:12])
	// victimTgid := bytesToU32(rawSample[12:16])
	victimRss := bytesToU64(rawSample[16:24])
	triggerPid := bytesToU32(rawSample[24:28])
	// triggerTgid := bytesToU32(rawSample[28:32])
	oomScore := bytesToI32(rawSample[32:36])
	// isCgroup := rawSample[36] != 0

	victimComm := cString(rawSample[40:56])
	triggerComm := cString(rawSample[56:72])

	ev := &metadata.OOMEvent{
		Ts:             ts,
		VictimPid:      victimPid,
		VictimComm:     victimComm,
		VictimRssBytes: victimRss,
		TriggerPid:     triggerPid,
		TriggerComm:    triggerComm,
		OomScore:       oomScore,
	}

	return ev
}

// supplementOOMSnapshot 从 /proc 补充 RSS、oom_score_adj、top processes
func supplementOOMSnapshot(ev *metadata.OOMEvent) {
	// 读取 /proc/[pid]/status 补充 RSS
	statusPath := fmt.Sprintf("/proc/%d/status", ev.VictimPid)
	if data, err := os.ReadFile(statusPath); err == nil {
		if rss := extractRssFromStatus(string(data)); rss > 0 {
			ev.VictimRssBytes = rss
		}
		if score := extractOomScoreFromStatus(string(data)); score != 0 {
			ev.OomScore = int32(score)
		}
	}

	// 采集其他 top 进程快照
	ev.TopProcesses = takeTopProcessSnapshot()
}

// takeTopProcessSnapshot 从 /proc 采集所有进程的 RSS 快照（top 10）
func takeTopProcessSnapshot() []metadata.ProcessSnapshot {
	procDir, err := os.Open("/proc")
	if err != nil {
		return nil
	}
	defer procDir.Close()

	entries, err := procDir.Readdirnames(-1)
	if err != nil {
		return nil
	}

	var procs []metadata.ProcessSnapshot
	for _, entry := range entries {
		pid, err := strconv.ParseUint(entry, 10, 32)
		if err != nil {
			continue
		}

		statusPath := fmt.Sprintf("/proc/%s/status", entry)
		data, err := os.ReadFile(statusPath)
		if err != nil {
			continue
		}

		statusStr := string(data)
		comm := extractCommFromStatus(statusStr)
		rss := extractRssFromStatus(statusStr)
		state := extractStateFromStatus(statusStr)

		procs = append(procs, metadata.ProcessSnapshot{
			Pid:      uint32(pid),
			Comm:     comm,
			RssBytes: rss,
			State:    state,
		})
	}

	// 按 RSS 降序排列，只取前 10
	sortByRssDesc(procs)
	if len(procs) > 10 {
		procs = procs[:10]
	}

	return procs
}

// insertOOMEvent 写入 ClickHouse mem_oom_events 表
// 注意：OOM 是低频事件，需要立即发送（不等 batch 攒满）
func insertOOMEvent(ev *metadata.OOMEvent) {
	if cliSink == nil || oomBatch == nil {
		return
	}

	// 序列化 top_processes 为 JSON
	topProcessesJson := ""
	if len(ev.TopProcesses) > 0 {
		if data, err := json.Marshal(ev.TopProcesses); err == nil {
			topProcessesJson = string(data)
		}
	}

	// 按照 mem_oom_events 表的列顺序插入
	// 表结构：ts, victim_pid, victim_comm, victim_rss_bytes, trigger_pid, trigger_comm, oom_score, is_cgroup, top_processes
	if err := oomBatch.Append(
		ev.Ts,                 // ts
		ev.VictimPid,          // victim_pid
		ev.VictimComm,         // victim_comm
		ev.VictimRssBytes,     // victim_rss_bytes
		ev.TriggerPid,         // trigger_pid
		ev.TriggerComm,        // trigger_comm
		ev.OomScore,           // oom_score
		ev.IsCgroup,           // is_cgroup
		topProcessesJson,      // top_processes (String/JSON)
	); err != nil {
		log.Errorf("oomBatch.Append error: %v", err)
		return
	}

	// OOM 是低频事件，立即发送不等 batch 满
	if err := oomBatch.Send(); err != nil {
		log.Errorf("oomBatch.Send error: %v", err)
	}
}

// ===== 辅助函数 =====

func extractRssFromStatus(status string) uint64 {
	scanner := bufio.NewScanner(strings.NewReader(status))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "VmRSS:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				if rss, err := strconv.ParseUint(parts[1], 10, 64); err == nil {
					return rss * 1024 // kB -> bytes
				}
			}
		}
	}
	return 0
}

func extractOomScoreFromStatus(status string) int64 {
	scanner := bufio.NewScanner(strings.NewReader(status))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "OomScoreAdj:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				if score, err := strconv.ParseInt(parts[1], 10, 32); err == nil {
					return score
				}
			}
		}
	}
	return 0
}

func extractCommFromStatus(status string) string {
	scanner := bufio.NewScanner(strings.NewReader(status))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Name:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				return parts[1]
			}
		}
	}
	return "unknown"
}

func extractStateFromStatus(status string) string {
	scanner := bufio.NewScanner(strings.NewReader(status))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "State:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				return parts[1]
			}
		}
	}
	return "?"
}

func sortByRssDesc(procs []metadata.ProcessSnapshot) {
	for i := 0; i < len(procs); i++ {
		for j := i + 1; j < len(procs); j++ {
			if procs[j].RssBytes > procs[i].RssBytes {
				procs[i], procs[j] = procs[j], procs[i]
			}
		}
	}
}

// ===== 字节转换辅助函数 =====

func bytesToU64(b []byte) uint64 {
	if len(b) < 8 {
		return 0
	}
	return uint64(b[0]) | (uint64(b[1]) << 8) | (uint64(b[2]) << 16) | (uint64(b[3]) << 24) |
		(uint64(b[4]) << 32) | (uint64(b[5]) << 40) | (uint64(b[6]) << 48) | (uint64(b[7]) << 56)
}

func bytesToU32(b []byte) uint32 {
	if len(b) < 4 {
		return 0
	}
	return uint32(b[0]) | (uint32(b[1]) << 8) | (uint32(b[2]) << 16) | (uint32(b[3]) << 24)
}

func bytesToI32(b []byte) int32 {
	return int32(bytesToU32(b))
}

func cString(b []byte) string {
	for i, v := range b {
		if v == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

