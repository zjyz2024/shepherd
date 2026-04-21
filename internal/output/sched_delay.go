package output

import (
	"context"
	"os"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/cen-ngc5139/shepherd/internal/binary"
	"github.com/cen-ngc5139/shepherd/internal/cache"
	"github.com/cen-ngc5139/shepherd/internal/config"
	"github.com/cen-ngc5139/shepherd/internal/log"
	"github.com/cen-ngc5139/shepherd/internal/metadata"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
)

func ProcessSchedDelay(coll *ebpf.Collection, ctx context.Context, cfg config.Configuration) {
	// 获取内核 BPF Map 的引用
	// 创建 Perf Event 读取器
	schedEvents := coll.Maps["sched_events"]
	perfReader, err := perf.NewReader(schedEvents, os.Getpagesize())
	if err != nil {
		log.Errorf("failed to create ringbuf reader: %v", err)
		return
	}

	// 确保退出时关闭读取器
	defer perfReader.Close()

	// 初始化后端输出模块
	output, err := NewOutput(cfg, ctx)
	if err != nil {
		log.Fatalf("failed to init output: %v", err)
	}

	// 确保退出时冲刷缓存并关闭连接
	defer output.Close()

	// Phase 2: 启动 Off-CPU 事件处理 goroutine
	go ProcessOffCPU(coll, ctx)

	var event binary.ShepherdSchedLatencyT
	for {
		// 在循环开始时就检查 context
		select {
		// 响应来自 main 的取消信号 (如 Ctrl+C)
		case <-ctx.Done():
			log.Info("退出事件处理")
			return
		default:
			// 1. 从 RingBuffer 中读取原始字节并反序列化为 event 结构体
			if err := parseEvent(perfReader, &event); err != nil {
				log.Errorf("failed to parse perf event: %v", err)
				continue
			}

			// 2. 将原始事件推送到后端输出（如 ClickHouse 批量写入队列）
			if err := output.Push(event); err != nil {
				log.Errorf("failed to push event: %v", err)
				continue
			}

			// 3. 将 C 风格的数据转换为 Go 风格的可视化元数据对象
			schedMetrics := metadata.SchedMetrics{
				Pid:               event.Pid,
				DelayNs:           event.DelayNs,
				Ts:                event.Ts,
				Comm:              sanitizeString(convertInt8ToString(event.Comm[:])),
				IrqDurationNs:     event.IrqDurationNs,
				SoftirqDurationNs: event.SoftirqDurationNs,
				MemReclaimNs:      event.MemReclaimNs,
				StackId:           event.StackId,
			}

			// Phase 1: 初始化上下文切换计数
			if event.IsVoluntary == 1 {
				schedMetrics.VoluntaryCtxtSwitches = 1
			} else {
				schedMetrics.InvoluntaryCtxtSwitches = 1
			}

			// 1. 尝试从缓存中查找该进程已有的统计数据
			current, isExist := cache.SchedMetricsMap.Load(event.Pid)
			if !isExist {
				cache.SchedMetricsMap.Store(event.Pid, schedMetrics)
				continue
			}

			// 2. 累加逻辑：将本次捕获的延迟加到该进程的总延迟中
			currentSchedMetrics, ok := current.(metadata.SchedMetrics)
			if !ok {
				log.Errorf("failed to convert current to metadata.SchedMetrics: %v", current)
				continue
			}

			currentSchedMetrics.DelayNs = event.DelayNs + currentSchedMetrics.DelayNs

			// Phase 1: 累加上下文切换计数
			if event.IsVoluntary == 1 {
				currentSchedMetrics.VoluntaryCtxtSwitches++
			} else {
				currentSchedMetrics.InvoluntaryCtxtSwitches++
			}

			// 1. 判断是否发生了“强行抢占”
			if event.IsPreempt != 1 {
				cache.SchedMetricsMap.Store(event.Pid, currentSchedMetrics)
				continue
			}

			// 2. 如果是抢占，增加该“进攻者”进程的抢占计数
			currentSchedMetrics.PreempteCount++

			// 3. 追踪“受害者”信息：谁被抢占了？
			schedPreempted := metadata.SchedPreempted{

				Pid:   event.PreemptedPid,
				Count: 1,
				Comm:  sanitizeString(convertInt8ToString(event.PreemptedComm[:])),
			}

			// 4. 更新受害者统计表，记录被抢占的频率
			preempted, isExist := cache.SchedPreemptedMap.Load(event.PreemptedPid)
			if !isExist {
				cache.SchedPreemptedMap.Store(event.PreemptedPid, schedPreempted)
				continue
			}

			preemptedSchedMetrics, ok := preempted.(metadata.SchedPreempted)
			if !ok {
				log.Errorf("failed to convert preempted to metadata.SchedPreempted: %v", preempted)
				continue
			}

			preemptedSchedMetrics.Count++
			cache.SchedPreemptedMap.Store(event.PreemptedPid, preemptedSchedMetrics)

			// 5. 将最终更新后的数据同步回缓存
			cache.SchedMetricsMap.Store(event.Pid, currentSchedMetrics)
		}
	}

}

func insertSchedMetrics(ctx context.Context, conn clickhouse.Conn, batch driver.Batch, event binary.ShepherdSchedLatencyT, count int) (driver.Batch, int, error) {
	err := batch.Append(
		event.Pid,
		event.Tid,
		event.DelayNs,
		event.Ts,
		event.PreemptedPid,
		sanitizeString(convertInt8ToString(event.PreemptedComm[:])),
		event.IsPreempt,
		sanitizeString(convertInt8ToString(event.Comm[:])),
		event.PreemptedPidState,
		event.IrqDurationNs,
		event.SoftirqDurationNs,
		event.MemReclaimNs,
		event.StackId,
	)
	if err != nil {
		log.Errorf("failed to append to batch: %v", err)
		return batch, count, err
	}

	count++
	// 使用计数器替代 RowsWritten()
	if count >= 10 {
		if err := batch.Send(); err != nil {
			log.Errorf("failed to send batch: %v", err)
			return batch, count, err
		}
		count = 0 // 重置计数器
		// 创建新的批次
		batch, err = conn.PrepareBatch(ctx, `
			INSERT INTO sched_latency (
				pid, tid, delay_ns, ts,
				preempted_pid, preempted_comm,
				is_preempt, comm,
				preempted_pid_state,
				irq_duration_ns, softirq_duration_ns, mem_reclaim_ns,
				stack_id
			)
		`)
		if err != nil {
			log.Errorf("failed to prepare new batch: %v", err)
			return batch, count, err
		}
	}

	return batch, count, nil
}
