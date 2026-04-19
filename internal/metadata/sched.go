package metadata

type SchedMetrics struct {
	Pid                uint32 // 进程ID
	DelayNs            uint64 // 调度延迟
	Ts                 uint64 // 时间戳
	PreempteCount      uint64 // 被抢占的次数
	Comm               string // 进程名
	IrqDurationNs      uint64 // 调度延迟期间的中断耗时
	SoftirqDurationNs  uint64 // 调度延迟期间的软中断耗时
	MemReclaimNs       uint64 // 调度延迟期间的内存直接回收耗时
}

type SchedPreempted struct {
	Pid   uint32 // 被抢占的进程
	Count uint64 // 被抢占的次数
	Comm  string // 被抢占的进程名
}
