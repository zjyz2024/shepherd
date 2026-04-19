CREATE DATABASE IF NOT EXISTS shepherd;
CREATE TABLE shepherd.sched_latency
(

    `pid` UInt32,

    `tid` UInt32,

    `delay_ns` UInt64,

    `ts` UInt64,

    `preempted_pid` UInt32,

    `preempted_comm` String,

    `is_preempt` UInt8,

    `comm` String,

    `date` Date DEFAULT today(),

    `preempted_pid_state` UInt32,

    `irq_duration_ns` UInt64,

    `softirq_duration_ns` UInt64,

    `datetime` DateTime64(9) DEFAULT now64(9)
)
ENGINE = MergeTree
ORDER BY (date,
 ts)
SETTINGS index_granularity = 8192;