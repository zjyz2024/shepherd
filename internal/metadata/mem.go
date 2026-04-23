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

// =========================================================================
// Phase M2: Reclaim Pressure
// =========================================================================

// MemReclaimMetrics 按 PID 聚合的回收压力统计
// kswapd_wake 是全局事件，用 Pid=0 这一条特殊 entry 累计
type MemReclaimMetrics struct {
	Pid                uint32 // 进程 ID (tgid)；0 表示 kswapd 全局事件
	Comm               string
	DirectReclaimCount uint64 // direct reclaim 次数（事件计数）
	DirectReclaimNs    uint64 // 累积 direct reclaim 耗时
	MaxDirectReclaimNs uint64 // 单次最大 direct reclaim 耗时
	NrReclaimedTotal   uint64 // 累积回收页数
	NrScannedTotal     uint64 // 累积扫描页数
	LRUInactiveCount   uint64 // lru_shrink_inactive 触发次数
	LRUActiveCount     uint64 // lru_shrink_active 触发次数
	KswapdWakeCount    uint64 // kswapd 唤醒次数（仅 Pid=0 entry 有效）
	LastTs             uint64
}

// MemReclaimGlobalKey 用于 cache.MemReclaimMap 的 kswapd 全局聚合 entry 的特殊 key
const MemReclaimGlobalKey uint32 = 0

