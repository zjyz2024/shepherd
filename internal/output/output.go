package output

import (
	"context"
	"encoding/json"

	"github.com/ClickHouse/clickhouse-go/v2"
	ckdriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/cen-ngc5139/shepherd/internal/binary"
	"github.com/cen-ngc5139/shepherd/internal/config"
	"github.com/cen-ngc5139/shepherd/internal/log"
	"github.com/cen-ngc5139/shepherd/pkg/client"
	"github.com/cen-ngc5139/shepherd/pkg/kafka"
	"github.com/pkg/errors"
)

type SinkCli struct {
	CKCli    CKCli
	KafkaCli *kafka.Producer
}

type CKCli struct {
	conn    clickhouse.Conn
	batch   ckdriver.Batch    // sched_latency batch
	counter int
	// Phase M5: OOM 独立 batch（低频事件，立即发送）
	oomBatch ckdriver.Batch
}

type Output struct {
	SinkType config.OutputType
	SinkCli  SinkCli
	ctx      context.Context
}

func NewOutput(cfg config.Configuration, ctx context.Context) (*Output, error) {
	o := &Output{SinkType: cfg.Output.Type, ctx: ctx}
	if err := o.InitSinkCli(cfg.Output); err != nil {
		return nil, errors.Wrapf(err, "failed to init sink %s client", o.SinkType)
	}

	return o, nil
}

func (o *Output) Close() {
	if o.SinkType == config.OutputTypeClickhouse {
		log.Info("close clickhouse client")
		o.SinkCli.CKCli.conn.Close()
	}
}

func (o *Output) InitSinkCli(cfg config.OutputConfig) (err error) {
	if o.SinkType == config.OutputTypeClickhouse {
		conn, err := client.NewClickHouseConn(cfg.Clickhouse)
		if err != nil {
			return errors.Wrap(err, "failed to init clickhouse client")
		}

		o.SinkCli.CKCli.batch, err = conn.PrepareBatch(o.ctx, `
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
			return errors.Wrap(err, "failed to prepare sched_latency batch")
		}

		// Phase M5: 准备 OOM batch
		o.SinkCli.CKCli.oomBatch, err = conn.PrepareBatch(o.ctx, `
			INSERT INTO mem_oom_events (
				ts, victim_pid, victim_comm, victim_rss_bytes,
				trigger_pid, trigger_comm, oom_score, is_cgroup, top_processes
			)
		`)
		if err != nil {
			return errors.Wrap(err, "failed to prepare oom_events batch")
		}

		o.SinkCli.CKCli.conn = conn
		// 在 mem_oom.go 中引用全局 oomBatch
		oomBatch = o.SinkCli.CKCli.oomBatch
		cliSink = &o.SinkCli
	}

	if o.SinkType == config.OutputTypeKafka {
		o.SinkCli.KafkaCli, err = kafka.NewSyncProducer(config.Config.Output.Kafka.Brokers, config.Config.Output.Kafka.Topic, true, true)
		if err != nil {
			return errors.Wrap(err, "failed to init kafka client")
		}
	}

	return nil
}

func (o *Output) Push(event binary.ShepherdSchedLatencyT) error {
	if o.SinkType == config.OutputTypeClickhouse {
		batch, count, err := insertSchedMetrics(o.ctx, o.SinkCli.CKCli.conn, o.SinkCli.CKCli.batch, event, o.SinkCli.CKCli.counter)
		if err != nil {
			return errors.Wrap(err, "failed to insert sched metrics")
		}
		o.SinkCli.CKCli.batch = batch
		o.SinkCli.CKCli.counter = count
	}

	if o.SinkType == config.OutputTypeKafka {
		raw, err := json.Marshal(event)
		if err != nil {
			return errors.Wrap(err, "failed to marshal event")
		}

		_, _, err = o.SinkCli.KafkaCli.SyncSendMessage(raw)
		if err != nil {
			return errors.Wrap(err, "fail to push kafka data")
		}
	}

	log.StdoutOrFile("file", event)

	return nil
}
