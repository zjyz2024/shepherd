package cache

import "sync"

// SchedMetricsMap 保存pid和调度延迟的映射关系
// key: pid
// value: metadata.SchedMetrics
var SchedMetricsMap *sync.Map

// SchedPreemptedMap 保存pid和调度延迟的映射关系
// key: pid
// value: metadata.SchedPreempted
var SchedPreemptedMap *sync.Map

// MemAllocMap 按 PID 聚合的内存分配统计（Phase M1）
// key: pid (uint32, tgid)
// value: metadata.MemAllocMetrics
var MemAllocMap *sync.Map

// MemAllocSlowPath 最近 N 条慢分配事件的环形缓冲（用于 CLI "慢分配红榜"）
var MemAllocSlowPath *RingBuffer

// MemReclaimMap 按 PID 聚合的内存回收压力统计（Phase M2）
// key: pid (uint32, tgid)；0 表示 kswapd 全局事件聚合
// value: metadata.MemReclaimMetrics
var MemReclaimMap *sync.Map

// MemFaultMap 按 PID 聚合的缺页异常统计（Phase M3）
// key: pid (uint32, tgid)
// value: metadata.MemFaultMetrics
var MemFaultMap *sync.Map

// OOMEventRing 最近 N 条 OOM 事件的环形缓冲（用于 CLI 显示告警）
// value: metadata.OOMEvent
var OOMEventRing *RingBuffer

// MemLeakSuspectMap 按 stack_id 聚合的泄漏嫌疑（Phase M4）
// key: stack_id (int32)
// value: metadata.MemLeakSuspect
var MemLeakSuspectMap *sync.Map

func init() {
	SchedMetricsMap = new(sync.Map)
	SchedPreemptedMap = new(sync.Map)
	MemAllocMap = new(sync.Map)
	MemAllocSlowPath = NewRingBuffer(64)
	MemReclaimMap = new(sync.Map)
	MemFaultMap = new(sync.Map)
	OOMEventRing = NewRingBuffer(32)
	MemLeakSuspectMap = new(sync.Map)
}

// RingBuffer 定长环形缓冲，按时间顺序保留最近 N 条事件。
// 并发安全。泛型使用 interface{} 以兼容 Go 1.22 之前的代码惯例。
type RingBuffer struct {
	mu   sync.RWMutex
	data []interface{}
	size int
	next int // 下一个写入位置
	full bool
}

func NewRingBuffer(size int) *RingBuffer {
	if size <= 0 {
		size = 1
	}
	return &RingBuffer{
		data: make([]interface{}, size),
		size: size,
	}
}

// Push 写入一条事件，超过容量时覆盖最旧的一条。
func (r *RingBuffer) Push(v interface{}) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.data[r.next] = v
	r.next = (r.next + 1) % r.size
	if r.next == 0 {
		r.full = true
	}
}

// Snapshot 返回时间从旧到新的事件副本。
func (r *RingBuffer) Snapshot() []interface{} {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var length int
	if r.full {
		length = r.size
	} else {
		length = r.next
	}
	if length == 0 {
		return nil
	}

	out := make([]interface{}, 0, length)
	if r.full {
		for i := 0; i < r.size; i++ {
			idx := (r.next + i) % r.size
			out = append(out, r.data[idx])
		}
	} else {
		for i := 0; i < r.next; i++ {
			out = append(out, r.data[i])
		}
	}
	return out
}

// Len 返回当前元素数。
func (r *RingBuffer) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.full {
		return r.size
	}
	return r.next
}
