package metadata

type SchedMetrics struct {
	Pid                        uint32 // 进程ID
	DelayNs                    uint64 // 调度延迟
	Ts                         uint64 // 时间戳
	PreempteCount              uint64 // 被抢占的次数
	Comm                       string // 进程名
	IrqDurationNs              uint64 // 调度延迟期间的中断耗时
	SoftirqDurationNs          uint64 // 调度延迟期间的软中断耗时
	MemReclaimNs               uint64 // 调度延迟期间的内存直接回收耗时
	StackId                    int32  // 内核调用栈ID
	
	// Phase 1: 上下文切换统计
	VoluntaryCtxtSwitches      uint64 // 自愿上下文切换计数
	InvoluntaryCtxtSwitches    uint64 // 非自愿上下文切换计数
	
	// Phase 2: Off-CPU 分析
	OffCPUTimeNs               uint64 // 累积离开 CPU 时间（纳秒）
	OffCPUEventCount           uint32 // Off-CPU 事件计数
	
	// Phase 4: CPU 迁移
	MigrationCount             uint64 // CPU 迁移次数
	AvgMigrationDist           float64 // 平均迁移距离
	
	// Phase 5: 优先级反转检测
	PriorityInversionCount     uint64 // 优先级反转发生次数
	MaxInversionBlockTimeNs    uint64 // 最大反转阻塞时间（纳秒）
}

type SchedPreempted struct {
	Pid   uint32 // 被抢占的进程
	Count uint64 // 被抢占的次数
	Comm  string // 被抢占的进程名
}
