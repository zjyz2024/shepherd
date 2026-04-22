package metadata

// MemAllocMetrics 按 PID 聚合的页分配统计
// Phase M1: 仅 Allocation Latency；后续 phase 扩展
type MemAllocMetrics struct {
	Pid            uint32    // 进程 ID (tgid)
	Comm           string    // 进程名
	AllocCount     uint64    // 分配总次数（采样后）
	SlowPathCount  uint64    // 慢路径次数 (>=1ms)
	MidPathCount   uint64    // 中等路径次数 (>=100µs && <1ms)
	TotalAllocNs   uint64    // 累计分配耗时
	MaxAllocNs     uint64    // 单次最大耗时
	OrderHistogram [11]uint64 // order 0..10 的次数分布
	LastStackId    int32     // 最近一次 slow path 的栈 ID
	LastTs         uint64    // 最近一次事件时间戳
}

// MemAllocSlowPathEvent 用于 CLI "慢分配红榜"（RingBuffer）
type MemAllocSlowPathEvent struct {
	Ts         uint64
	Pid        uint32
	Comm       string
	DurationNs uint64
	Order      uint32
	GfpFlags   uint32
	StackId    int32
}
