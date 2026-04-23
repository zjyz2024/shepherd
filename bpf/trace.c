// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Martynas Pumputis */
/* Copyright Authors of Cilium */

#include "vmlinux.h"
#include "vmlinux-x86.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_core_read.h"
#include "bpf/bpf_tracing.h"
#include "bpf/bpf_endian.h"
#include "bpf/bpf_ipv6.h"

extern int LINUX_KERNEL_VERSION __kconfig;

// 定义数据结构来存储调度延迟信息
struct sched_latency_t
{
    __u32 pid;                 // 进程ID
    __u32 tid;                 // 线程ID
    __u64 delay_ns;            // 调度延迟(纳秒)
    __u64 ts;                  // 时间戳
    __u32 preempted_pid;       // 被抢占的进程ID
    char preempted_comm[16];   // 被抢占的进程名
    __u64 is_preempt;          // 是否抢占(0: 否, 1: 是)
    char comm[16];             // 进程名
    __u32 preempted_pid_state; // 被抢占的进程状态
    __u64 irq_duration_ns;     // 调度延迟期间的中断耗时
    __u64 softirq_duration_ns; // 调度延迟期间的软中断耗时
    __u64 mem_reclaim_ns;      // 调度延迟期间的内存直接回收耗时
    __s32 stack_id;            // 内核调用栈ID
    // Phase 1: 上下文切换统计
    __u8 is_voluntary;         // 1: 自愿切换, 0: 非自愿（被抢占）
    __u8 prev_state_raw;       // 原始的 prev_state 值（用于诊断）
    // Phase 5: 优先级反转检测
    __u8 is_priority_inversion; // 1: 高优先级被低优先级抢占, 0: 否
    __u8 prev_prio;            // 被抢占进程的优先级
    __u8 next_prio;            // 抢占进程的优先级
} __attribute__((packed));

struct sched_latency_t *unused_sched_latency_t __attribute__((unused));

// Phase 2: Off-CPU 事件采样
struct off_cpu_event_t
{
    __u64 ts_leave;            // 离开 CPU 的时间戳
    __u32 pid;                 // 进程ID
    __u32 tid;                 // 线程ID
    char comm[16];             // 进程名
    __u32 cpu_id;              // CPU 核心 ID
    __s32 kernel_stack_id;     // 内核调用栈 ID
    __u32 reason_flags;        // 预留字段：离开原因
    __u64 pad64;               // 对齐填充
} __attribute__((packed));

struct off_cpu_event_t *unused_off_cpu_event_t __attribute__((unused));

// 定义 ring buffer 用于传输数据到用户空间
struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 256 * 1024);
} sched_events SEC(".maps");

// Phase 2: Off-CPU 事件输出
struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 256 * 1024);
} off_cpu_events SEC(".maps");

// Phase 4: CPU 迁移事件输出
struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 256 * 1024);
} migrate_events SEC(".maps");

// Phase 4: 迁移事件结构体
struct migrate_event_t {
    __u64 ts;
    __u32 pid;
    __u32 tgid;
    __s32 orig_cpu;
    __s32 dest_cpu;
    char comm[16];
    __u64 pad;
} __attribute__((packed));

struct migrate_event_t *unused_migrate_event_t __attribute__((unused));

// 用于临时存储唤醒时间的 hash map
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u64);
} wakeup_times SEC(".maps");

// Phase 5: 存储前一个进程的优先级用于反转检测
struct priority_info {
    __u16 prio;     // 优先级
    __u64 ts;       // 时间戳
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct priority_info);
} priority_map SEC(".maps");

// 记录中断开始时间
struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} irq_start SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} softirq_start SEC(".maps");

// 累积中断耗时
struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} irq_cumulative_duration SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} softirq_cumulative_duration SEC(".maps");

// 记录直接内存回收开始时间
struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} mem_reclaim_start SEC(".maps");

// 累积内存回收耗时
struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} mem_reclaim_cumulative_duration SEC(".maps");

// 存储内核调用栈
struct
{
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, 10240);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, 127 * sizeof(__u64)); // 最大 127 层深度
} stack_traces SEC(".maps");

struct trace_event_raw_sched_wakeup
{
    /* common fields */
    __u16 common_type;         /* offset: 0, size: 2 */
    __u8 common_flags;         /* offset: 2, size: 1 */
    __u8 common_preempt_count; /* offset: 3, size: 1 */
    __s32 common_pid;          /* offset: 4, size: 4 */

    /* event specific fields */
    char comm[16];         /* offset: 8, size: 16 */
    __s32 pid;             /* offset: 24, size: 4 */
    __s32 prio;            /* offset: 28, size: 4 */
    __s32 target_cpu;      /* offset: 32, size: 4 */
} __attribute__((packed)); /* 确保结构体紧凑，没有额外的填充字节 */

// 添加 tracepoint 事件结构体定义
struct trace_event_raw_sched_wakeup_new
{
    /* common fields */
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    __s32 common_pid;

    /* event specific fields */
    char comm[16];
    __s32 pid;
    __s32 prio;
    __s32 target_cpu;
} __attribute__((packed));

// 中断处理逻辑
SEC("tp_btf/irq_handler_entry")
int irq_handler_entry(u64 *ctx)
{
    u32 key = 0;
    u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&irq_start, &key, &ts, BPF_ANY);
    return 0;
}

SEC("tp_btf/irq_handler_exit")
int irq_handler_exit(u64 *ctx)
{
    u32 key = 0;
    u64 *start_ts = bpf_map_lookup_elem(&irq_start, &key);
    if (start_ts && *start_ts > 0)
    {
        u64 duration = bpf_ktime_get_ns() - *start_ts;
        u64 *cum_duration = bpf_map_lookup_elem(&irq_cumulative_duration, &key);
        if (cum_duration)
        {
            *cum_duration += duration;
        }
        else
        {
            bpf_map_update_elem(&irq_cumulative_duration, &key, &duration, BPF_ANY);
        }
        *start_ts = 0;
    }
    return 0;
}

SEC("tp_btf/softirq_entry")
int softirq_entry(u64 *ctx)
{
    u32 key = 0;
    u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&softirq_start, &key, &ts, BPF_ANY);
    return 0;
}

SEC("tp_btf/softirq_exit")
int softirq_exit(u64 *ctx)
{
    u32 key = 0;
    u64 *start_ts = bpf_map_lookup_elem(&softirq_start, &key);
    if (start_ts && *start_ts > 0)
    {
        u64 duration = bpf_ktime_get_ns() - *start_ts;
        u64 *cum_duration = bpf_map_lookup_elem(&softirq_cumulative_duration, &key);
        if (cum_duration)
        {
            *cum_duration += duration;
        }
        else
        {
            bpf_map_update_elem(&softirq_cumulative_duration, &key, &duration, BPF_ANY);
        }
        *start_ts = 0;
    }
    return 0;
}

// Phase M2: Memory Reclaim 事件结构体与 map（前置定义，供 direct_reclaim handlers 使用）
struct mem_reclaim_event_t {
    __u64 ts;
    __u64 duration_ns;    // direct reclaim 整段耗时；lru_shrink 不填
    __u32 pid;            // tid
    __u32 tgid;           // process id；kswapd_wake 时为 0
    __u32 nr_scanned;
    __u32 nr_reclaimed;
    __u32 order;          // kswapd_wake 用；其余 0
    __s32 nid;            // NUMA node；非全节点事件填 -1
    __u8  is_direct;      // 1: direct reclaim 事件
    __u8  is_kswapd;      // 1: kswapd_wake 事件
    __u8  lru_type;       // 0: 不适用 1: lru_shrink_inactive 2: lru_shrink_active
    __u8  pad0;
    char  comm[16];
    __u32 pad1;
} __attribute__((packed));

struct mem_reclaim_event_t *unused_mem_reclaim_event_t __attribute__((unused));

// 按 tid 记录 direct_reclaim begin ts（与现有 PERCPU mem_reclaim_start 并存）
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u64);
} reclaim_start_by_pid SEC(".maps");

// Phase M2 事件输出
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 256 * 1024);
} mem_reclaim_events SEC(".maps");

SEC("tp_btf/mm_vmscan_direct_reclaim_begin")
int direct_reclaim_begin(u64 *ctx)
{
    u32 key = 0;
    u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&mem_reclaim_start, &key, &ts, BPF_ANY);

    // Phase M2: 同时按 tid 记录 begin ts，用于 perf 事件输出
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = (u32)pid_tgid;
    bpf_map_update_elem(&reclaim_start_by_pid, &tid, &ts, BPF_ANY);
    return 0;
}

SEC("tp_btf/mm_vmscan_direct_reclaim_end")
int direct_reclaim_end(u64 *ctx)
{
    u32 key = 0;
    u64 now = bpf_ktime_get_ns();
    u64 *start_ts = bpf_map_lookup_elem(&mem_reclaim_start, &key);
    if (start_ts && *start_ts > 0)
    {
        u64 duration = now - *start_ts;
        u64 *cum_duration = bpf_map_lookup_elem(&mem_reclaim_cumulative_duration, &key);
        if (cum_duration)
        {
            *cum_duration += duration;
        }
        else
        {
            bpf_map_update_elem(&mem_reclaim_cumulative_duration, &key, &duration, BPF_ANY);
        }
        *start_ts = 0;
    }

    // Phase M2: 从 tp_btf ctx 读取 nr_reclaimed（direct_reclaim_end_template 第 1 个参数）
    // ctx[0] 是 struct trace_event_raw_mm_vmscan_direct_reclaim_end_template *
    // 但在 tp_btf 模式下 ctx 的语义是 BTF 参数数组；第一个参数是 nr_reclaimed (unsigned long)
    u64 nr_reclaimed = ctx[0];

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = (u32)pid_tgid;
    u32 tgid = pid_tgid >> 32;

    u64 *pid_start = bpf_map_lookup_elem(&reclaim_start_by_pid, &tid);
    if (pid_start && *pid_start > 0)
    {
        struct mem_reclaim_event_t ev = {};
        ev.ts = now;
        ev.duration_ns = now - *pid_start;
        ev.pid = tid;
        ev.tgid = tgid ? tgid : tid;
        ev.nr_reclaimed = (u32)nr_reclaimed;
        ev.is_direct = 1;
        ev.is_kswapd = 0;
        ev.lru_type = 0;
        bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
        bpf_perf_event_output(ctx, &mem_reclaim_events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));

        bpf_map_delete_elem(&reclaim_start_by_pid, &tid);
    }
    return 0;
}

// 公共函数：处理进程唤醒
static __always_inline void handle_wakeup(u32 pid)
{
    if (pid == 0)
    {
        return;
    }

    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&wakeup_times, &pid, &ts, BPF_ANY);
}

#if LINUX_KERNEL_VERSION >= KERNEL_VERSION(5, 10, 0)
SEC("tp_btf/sched_wakeup")
int sched_wakeup(u64 *ctx)
{
    struct task_struct *task = (void *)ctx[0];
    handle_wakeup(task->pid);
    return 0;
}

SEC("tp_btf/sched_wakeup_new")
int sched_wakeup_new(u64 *ctx)
{
    struct task_struct *task = (void *)ctx[0];
    handle_wakeup(task->pid);
    return 0;
}
#else
SEC("tp/sched/sched_wakeup")
int sched_wakeup(struct trace_event_raw_sched_wakeup *ctx)
{
    handle_wakeup(ctx->pid);
    return 0;
}

SEC("tp/sched/sched_wakeup_new")
int sched_wakeup_new(struct trace_event_raw_sched_wakeup_new *ctx)
{
    handle_wakeup(ctx->pid);
    return 0;
}
#endif

// 定义流控相关的常量和map
#define SAMPLING_RATIO 100   // 采样率 1/100
#define THRESHOLD_NS 1000000 // 延迟阈值 1ms

// 用于记录每个 CPU 的最后一次采样时间
struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} last_sample SEC(".maps");

#define TASK_RUNNING 0

u64 get_task_cgroup_id(struct task_struct *task)
{
    u64 cgroup_id = 0;
    struct css_set *cgroups;

    // 使用 BPF_CORE_READ 安全地读取
    cgroups = BPF_CORE_READ(task, cgroups);
    if (cgroups)
    {
        cgroup_id = BPF_CORE_READ(cgroups, dfl_cgrp, kn, id);
    }

    return cgroup_id;
}

// 公共函数：处理调度切换事件
static __always_inline void handle_sched_switch(u32 prev_pid, u32 prev_tgid,
                                                u32 next_pid, u32 next_tgid, __u32 prev_state,
                                                const char *prev_comm, const char *next_comm, 
                                                __u16 prev_prio, __u16 next_prio, void *ctx)
{
    __u64 *wakeup_ts;
    __u64 now = bpf_ktime_get_ns();
    u32 key = 0;

    // Phase 2: 采样离开 CPU 的进程（Off-CPU）
    // 这与调度延迟计算并行，不影响既有逻辑
    if (prev_pid != 0)
    {
        struct off_cpu_event_t off_cpu = {
            .ts_leave = now,
            .pid = prev_tgid ? prev_tgid : prev_pid,
            .tid = prev_pid,
            .cpu_id = bpf_get_smp_processor_id(),
        };
        
        bpf_probe_read_kernel_str(&off_cpu.comm, sizeof(off_cpu.comm), prev_comm);
        
        // 采样内核堆栈
        off_cpu.kernel_stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_FAST_STACK_CMP);
        
        // 采样率控制：1/100 概率采样 Off-CPU 事件
        if (bpf_get_prandom_u32() % 100 == 0)
        {
            bpf_perf_event_output(ctx, &off_cpu_events, BPF_F_CURRENT_CPU, &off_cpu, sizeof(off_cpu));
        }
    }

    if (prev_pid == 0 || next_pid == 0)
    {
        return;
    }

    // 查找进程的唤醒时间
    wakeup_ts = bpf_map_lookup_elem(&wakeup_times, &next_pid);
    if (!wakeup_ts)
        return;

    // 计算调度延迟
    __u64 delay = now - *wakeup_ts;

    // 流控逻辑开始
    __u64 *last_ts = bpf_map_lookup_elem(&last_sample, &key);
    if (!last_ts)
        return;

    // 基于时间的流控
    if ((now - *last_ts) < THRESHOLD_NS)
    {
        if (bpf_get_prandom_u32() % SAMPLING_RATIO != 0)
        {
            bpf_map_delete_elem(&wakeup_times, &next_pid);
            return;
        }
    }

    // 更新最后采样时间
    bpf_map_update_elem(&last_sample, &key, &now, BPF_ANY);

    // 延迟阈值过滤
    if (delay < THRESHOLD_NS)
    {
        bpf_map_delete_elem(&wakeup_times, &next_pid);
        return;
    }

    // 准备输出数据
    struct sched_latency_t latency = {
        .pid = next_tgid ? next_tgid : next_pid, // 如果有 tgid 则使用 tgid，否则使用 pid
        .tid = next_pid,
        .delay_ns = delay,
        .ts = now,
        .preempted_pid_state = prev_state,
    };

    u64 *irq_dur = bpf_map_lookup_elem(&irq_cumulative_duration, &key);
    if (irq_dur)
    {
        latency.irq_duration_ns = *irq_dur;
        *irq_dur = 0; // 重置累积值
    }

    u64 *softirq_dur = bpf_map_lookup_elem(&softirq_cumulative_duration, &key);
    if (softirq_dur)
    {
        latency.softirq_duration_ns = *softirq_dur;
        *softirq_dur = 0; // 重置累积值
    }

    u64 *mem_reclaim_dur = bpf_map_lookup_elem(&mem_reclaim_cumulative_duration, &key);
    if (mem_reclaim_dur)
    {
        latency.mem_reclaim_ns = *mem_reclaim_dur;
        *mem_reclaim_dur = 0; // 重置累积值
    }

    // 抓取当前内核调用栈
    latency.stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_FAST_STACK_CMP);

    bpf_probe_read_kernel_str(&latency.comm, sizeof(latency.comm), next_comm);

    // 如果前一个状态是 TASK_RUNNING，则认为是抢占（非自愿切换）
    if (prev_state == TASK_RUNNING)
    {
        latency.is_preempt = 1;
        latency.is_voluntary = 0;  // 非自愿切换
        latency.preempted_pid = prev_tgid ? prev_tgid : prev_pid;
        bpf_probe_read_kernel_str(&latency.preempted_comm, sizeof(latency.preempted_comm), prev_comm);
        
        // Phase 5: 检测优先级反转
        // 在 Linux 内核中，prio 越小表示优先级越高
        // 如果被抢占的进程优先级高于抢占者（prio 更小），则发生优先级反转
        latency.prev_prio = (__u8)(prev_prio & 0xFF);
        latency.next_prio = (__u8)(next_prio & 0xFF);
        
        if (prev_prio < next_prio) {
            latency.is_priority_inversion = 1;
        }
    }
    else
    {
        latency.is_voluntary = 1;  // 自愿切换
    }
    
    // Phase 5: 存储当前进程的优先级用于下一次比较
    struct priority_info pinfo = {
        .prio = next_prio,
        .ts = now,
    };
    bpf_map_update_elem(&priority_map, &next_pid, &pinfo, BPF_ANY);

    latency.prev_state_raw = (__u8)prev_state;

    bpf_printk("pid: %d, delay: %llu ns, is_preempt: %d\n",
               latency.pid, latency.delay_ns, latency.is_preempt);

    // 输出到 perf event
    bpf_perf_event_output(ctx, &sched_events, BPF_F_CURRENT_CPU, &latency, sizeof(latency));

    // 删除已处理的唤醒时间记录
    bpf_map_delete_elem(&wakeup_times, &next_pid);
}

#if LINUX_KERNEL_VERSION >= KERNEL_VERSION(5, 10, 0)
SEC("tp_btf/sched_switch")
int sched_switch(u64 *ctx)
{
    struct task_struct *prev = (struct task_struct *)ctx[1];
    struct task_struct *next = (struct task_struct *)ctx[2];

    u32 prev_pid = BPF_CORE_READ(prev, pid);
    u32 prev_tgid = BPF_CORE_READ(prev, tgid);
    u32 next_pid = BPF_CORE_READ(next, pid);
    u32 next_tgid = BPF_CORE_READ(next, tgid);
    
    // Phase 5: 读取优先级用于优先级反转检测
    u16 prev_prio = BPF_CORE_READ(prev, prio);
    u16 next_prio = BPF_CORE_READ(next, prio);

#if defined(__TARGET_ARCH_x86)
    __u32 state = BPF_CORE_READ(prev, __state);
#elif defined(__TARGET_ARCH_arm64)
    __u32 state = BPF_CORE_READ(prev, state);
#else
    __u32 state = BPF_CORE_READ(prev, __state);
#endif

    handle_sched_switch(prev_pid, prev_tgid, next_pid, next_tgid,
                        state, prev->comm, next->comm, prev_prio, next_prio, ctx);
    return 0;
}
#else
SEC("tp/sched/sched_switch")
int sched_switch(struct trace_event_raw_sched_switch *ctx)
{
    handle_sched_switch(ctx->prev_pid, 0, ctx->next_pid, 0,
                        ctx->prev_state, ctx->prev_comm, ctx->next_comm, 0, 0, ctx);
    return 0;
}
#endif

// Phase 4: sched_migrate_task tracepoint handler
#if LINUX_KERNEL_VERSION >= KERNEL_VERSION(5, 10, 0)
SEC("tp_btf/sched_migrate_task")
int sched_migrate_task_tp(void *ctx)
{
    struct task_struct *task = (struct task_struct *)ctx[1];
    int dest_cpu = (int)ctx[2];

    u32 pid = BPF_CORE_READ(task, pid);
    u32 tgid = BPF_CORE_READ(task, tgid);
    int orig_cpu = bpf_get_smp_processor_id();

    struct migrate_event_t ev = {};
    ev.ts = bpf_ktime_get_ns();
    ev.pid = pid;
    ev.tgid = tgid;
    ev.orig_cpu = orig_cpu;
    ev.dest_cpu = dest_cpu;
    bpf_probe_read_kernel_str(&ev.comm, sizeof(ev.comm), task->comm);

    bpf_perf_event_output(ctx, &migrate_events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
    return 0;
}
#else
SEC("tp/sched/sched_migrate_task")
int sched_migrate_task_raw(struct trace_event_raw_sched_migrate_task *ctx)
{
    struct migrate_event_t ev = {};
    ev.ts = bpf_ktime_get_ns();
    ev.pid = ctx->pid;
    ev.tgid = ctx->pid;
    ev.orig_cpu = ctx->orig_cpu;
    ev.dest_cpu = ctx->dest_cpu;
    bpf_probe_read_kernel_str(&ev.comm, sizeof(ev.comm), ctx->comm);

    bpf_perf_event_output(ctx, &migrate_events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
    return 0;
}
#endif

// =========================================================================
// Memory Dimension - Phase M1: Allocation Latency
// =========================================================================
// 挂载点：
//   kprobe/__alloc_pages (5.12+) 或 __alloc_pages_nodemask (< 5.12)
//   kretprobe 对应函数，用于计算 duration
// 采样策略：
//   fast path (duration < ALLOC_SLOW_THRESHOLD_NS)    1/1000
//   mid  path (>= 100µs && < slow)                    强制输出（不采栈）
//   slow path (>= ALLOC_SLOW_THRESHOLD_NS)            100% 输出 + 内核栈

#define ALLOC_SLOW_THRESHOLD_NS 1000000   // 1ms
#define ALLOC_MID_THRESHOLD_NS  100000    // 100µs
#define ALLOC_FAST_SAMPLE       1000      // 1/1000

struct mem_alloc_event_t {
    __u64 ts;                // 事件时间戳（kretprobe 返回时刻）
    __u64 duration_ns;       // 本次分配耗时
    __u32 pid;               // 线程 ID
    __u32 tgid;              // 进程 ID
    __u32 order;             // 分配页的 order
    __u32 gfp_flags;         // GFP 标志
    __s32 stack_id;          // 内核栈 ID（仅 slow path 采集）
    __u8  path_type;         // 0=fast, 1=mid, 2=slow
    __u8  pad0[3];
    char  comm[16];
    __u64 pad1;
} __attribute__((packed));

struct mem_alloc_event_t *unused_mem_alloc_event_t __attribute__((unused));

// kprobe entry 上下文：保存本次分配的入口信息
struct alloc_ctx_t {
    __u64 ts;
    __u32 order;
    __u32 gfp_flags;
};

// 记录每个 tid 的分配开始信息（kprobe → kretprobe 之间）
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct alloc_ctx_t);
} alloc_start SEC(".maps");

// 输出事件
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 256 * 1024);
} mem_alloc_events SEC(".maps");

static __always_inline int handle_alloc_enter(struct pt_regs *ctx, __u32 order, __u32 gfp_flags)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;

    struct alloc_ctx_t actx = {};
    actx.ts = bpf_ktime_get_ns();
    actx.order = order;
    actx.gfp_flags = gfp_flags;

    bpf_map_update_elem(&alloc_start, &tid, &actx, BPF_ANY);
    return 0;
}

static __always_inline int handle_alloc_exit(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    __u32 tgid = pid_tgid >> 32;

    struct alloc_ctx_t *actx = bpf_map_lookup_elem(&alloc_start, &tid);
    if (!actx)
        return 0;

    __u64 now = bpf_ktime_get_ns();
    __u64 duration = now - actx->ts;

    __u8 path_type;
    if (duration >= ALLOC_SLOW_THRESHOLD_NS) {
        path_type = 2; // slow
    } else if (duration >= ALLOC_MID_THRESHOLD_NS) {
        path_type = 1; // mid
    } else {
        // fast path: 采样 1/ALLOC_FAST_SAMPLE
        if (bpf_get_prandom_u32() % ALLOC_FAST_SAMPLE != 0) {
            bpf_map_delete_elem(&alloc_start, &tid);
            return 0;
        }
        path_type = 0;
    }

    struct mem_alloc_event_t ev = {};
    ev.ts = now;
    ev.duration_ns = duration;
    ev.pid = tid;
    ev.tgid = tgid ? tgid : tid;
    ev.order = actx->order;
    ev.gfp_flags = actx->gfp_flags;
    ev.path_type = path_type;
    ev.stack_id = -1;

    // 仅 slow path 采集栈（频率低，开销可控）
    if (path_type == 2) {
        ev.stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_FAST_STACK_CMP);
    }

    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));

    bpf_perf_event_output(ctx, &mem_alloc_events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));

    bpf_map_delete_elem(&alloc_start, &tid);
    return 0;
}

// 5.12+ 使用 __alloc_pages(gfp_t gfp, unsigned int order, int preferred_nid, nodemask_t *nodemask)
// 旧内核使用 __alloc_pages_nodemask(gfp_t gfp, unsigned int order, int preferred_nid, nodemask_t *nodemask)
// 两者参数布局一致，统一读 PT_REGS_PARM1/PARM2
#if LINUX_KERNEL_VERSION >= KERNEL_VERSION(5, 12, 0)
SEC("kprobe/__alloc_pages")
int BPF_KPROBE(alloc_pages_enter, unsigned int gfp, unsigned int order)
{
    return handle_alloc_enter(ctx, order, gfp);
}

SEC("kretprobe/__alloc_pages")
int BPF_KRETPROBE(alloc_pages_exit)
{
    return handle_alloc_exit(ctx);
}
#else
SEC("kprobe/__alloc_pages_nodemask")
int BPF_KPROBE(alloc_pages_enter, unsigned int gfp, unsigned int order)
{
    return handle_alloc_enter(ctx, order, gfp);
}

SEC("kretprobe/__alloc_pages_nodemask")
int BPF_KRETPROBE(alloc_pages_exit)
{
    return handle_alloc_exit(ctx);
}
#endif

// Memory Dimension - Phase M2: Reclaim Pressure
// =========================================================================
// 挂载点：
//   已有 mm_vmscan_direct_reclaim_begin/end（扩展，见上方）
//   新增：mm_vmscan_kswapd_wake
//         mm_vmscan_lru_shrink_inactive
//         mm_vmscan_lru_shrink_active
//
// 设计：
//   - direct_reclaim 事件归属 PID（谁触发的 direct reclaim）
//   - kswapd_wake 是全局事件（pid=0，只记 nid/order）
//   - lru_shrink 在 kswapd/direct reclaim 流程中都会触发；按 current pid 归属

// kswapd_wake: 全局唤醒事件
// trace_event_raw_mm_vmscan_kswapd_wake: { ent; int nid; int zid; int order; }
SEC("tp_btf/mm_vmscan_kswapd_wake")
int kswapd_wake(u64 *ctx)
{
    struct mem_reclaim_event_t ev = {};
    ev.ts = bpf_ktime_get_ns();
    ev.pid = 0;
    ev.tgid = 0;
    ev.is_kswapd = 1;
    ev.is_direct = 0;
    ev.lru_type = 0;
    ev.nid = (__s32)ctx[0];
    ev.order = (__u32)ctx[2];
    bpf_perf_event_output(ctx, &mem_reclaim_events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
    return 0;
}

// lru_shrink_inactive: { ent; int nid; ulong nr_scanned; ulong nr_reclaimed; ... }
SEC("tp_btf/mm_vmscan_lru_shrink_inactive")
int lru_shrink_inactive(u64 *ctx)
{
    struct mem_reclaim_event_t ev = {};
    ev.ts = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    ev.pid = (u32)pid_tgid;
    ev.tgid = pid_tgid >> 32;
    if (ev.tgid == 0)
        ev.tgid = ev.pid;
    ev.lru_type = 1;
    ev.is_direct = 0;
    ev.is_kswapd = 0;
    ev.nid = (__s32)ctx[0];
    ev.nr_scanned = (__u32)ctx[1];
    ev.nr_reclaimed = (__u32)ctx[2];
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    bpf_perf_event_output(ctx, &mem_reclaim_events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
    return 0;
}

// lru_shrink_active: { ent; int nid; ulong nr_taken; ulong nr_active; ulong nr_deactivated; ... }
SEC("tp_btf/mm_vmscan_lru_shrink_active")
int lru_shrink_active(u64 *ctx)
{
    struct mem_reclaim_event_t ev = {};
    ev.ts = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    ev.pid = (u32)pid_tgid;
    ev.tgid = pid_tgid >> 32;
    if (ev.tgid == 0)
        ev.tgid = ev.pid;
    ev.lru_type = 2;
    ev.is_direct = 0;
    ev.is_kswapd = 0;
    ev.nid = (__s32)ctx[0];
    ev.nr_scanned = (__u32)ctx[1];   // nr_taken
    ev.nr_reclaimed = (__u32)ctx[3]; // nr_deactivated
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    bpf_perf_event_output(ctx, &mem_reclaim_events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
    return 0;
}

// =========================================================================
// Memory Dimension - Phase M3: Page Fault
// =========================================================================
// 挂载点：
//   kprobe/handle_mm_fault（5.0+，稳定）
//   tp_btf/exceptions/page_fault_user（5.10+，用户态缺页）
//   tp_btf/exceptions/page_fault_kernel（5.10+，内核态缺页）

struct mem_fault_event_t {
    __u64 ts;
    __u64 duration_ns;      // fault 处理耗时
    __u32 pid;              // 进程 ID (tid)
    __u32 tgid;             // 进程组 ID
    __u64 fault_addr;       // 触发缺页的虚拟地址
    __u32 is_major;         // 1: major fault, 0: minor fault
    __u32 is_user;          // 1: user page fault, 0: kernel
    __u8  is_write;         // 1: write fault, 0: read
    __u8  pad0[3];
    char  comm[16];
    __u32 stack_id;
    __u32 pad1;
} __attribute__((packed));

struct mem_fault_event_t *unused_mem_fault_event_t __attribute__((unused));

// 记录每个 tid 的 fault 开始时间（handle_mm_fault enter → exit 之间）
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u64);
} fault_start_by_pid SEC(".maps");

// 输出事件
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 256 * 1024);
} mem_fault_events SEC(".maps");

// handle_mm_fault kprobe enter
// 签名：vm_fault_t handle_mm_fault(struct vm_area_struct *vma, unsigned long address,
//                                   unsigned int flags)
// 返回值的 VM_FAULT_MAJOR = 0x4
SEC("kprobe/handle_mm_fault")
int handle_mm_fault_enter(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&fault_start_by_pid, &tid, &ts, BPF_ANY);
    return 0;
}

// handle_mm_fault kretprobe
// 在返回时判断是否为 major fault（retval & VM_FAULT_MAJOR != 0）
SEC("kretprobe/handle_mm_fault")
int handle_mm_fault_exit(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    __u32 tgid = pid_tgid >> 32;
    __u64 now = bpf_ktime_get_ns();

    __u64 *start_ts = bpf_map_lookup_elem(&fault_start_by_pid, &tid);
    if (!start_ts)
        return 0;

    __u64 duration = now - *start_ts;

    // 从返回值判断是否 major fault
    // 返回值在 PT_REGS_RC 中（x86 的 rax，arm64 的 x0）
    __u64 retval = PT_REGS_RC(ctx);
    __u32 is_major = (retval & 0x4) ? 1 : 0;  // VM_FAULT_MAJOR = 0x4

    // 仅在 major fault 或持续时间较长时采集事件
    #define MAJOR_FAULT_THRESHOLD_NS 100000  // 100µs
    if (is_major == 0 && duration < MAJOR_FAULT_THRESHOLD_NS) {
        bpf_map_delete_elem(&fault_start_by_pid, &tid);
        return 0;
    }

    struct mem_fault_event_t ev = {};
    ev.ts = now;
    ev.duration_ns = duration;
    ev.pid = tid;
    ev.tgid = tgid ? tgid : tid;
    ev.is_major = is_major;
    ev.is_user = 1;  // handle_mm_fault 既处理用户态也处理内核态，简化为 1
    ev.is_write = 0;  // 无法从 retval 直接判断，由 Go 侧补充
    ev.fault_addr = 0;  // 无法获取，由 Go 侧补充

    // major fault 时采集栈
    if (is_major) {
        ev.stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_FAST_STACK_CMP);
    } else {
        ev.stack_id = -1;
    }

    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    bpf_perf_event_output(ctx, &mem_fault_events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));

    bpf_map_delete_elem(&fault_start_by_pid, &tid);
    return 0;
}

// =========================================================================
// Memory Dimension - Phase M5: OOM Killer
// =========================================================================
// 挂载点：
//   kprobe/oom_kill_process（稳定，所有内核）
//   tp_btf/oom/mark_victim（5.10+，优先）

struct mem_oom_event_t {
    __u64 ts;
    __u32 victim_pid;
    __u32 victim_tgid;
    __u64 victim_rss_bytes;
    __u32 trigger_pid;      // 触发 OOM 的进程 PID
    __u32 trigger_tgid;     // 触发 OOM 的进程 tgid
    __u32 oom_score;        // oom_score_adj
    __u8  is_cgroup;        // 1: cgroup OOM, 0: 全局 OOM
    __u8  pad0[3];
    char  victim_comm[16];
    char  trigger_comm[16];
    __u64 pad1;
} __attribute__((packed));

struct mem_oom_event_t *unused_mem_oom_event_t __attribute__((unused));

// OOM 事件输出
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 256 * 1024);
} mem_oom_events SEC(".maps");

// oom_kill_process kprobe 版本（兼容所有内核）
// 简化方案：只记录 OOM 事件触发，不尝试读取复杂的 struct oom_control
// 被杀进程信息通过 Go 侧监听内核日志或系统其他机制获知
//
// 此 kprobe 的作用是：标记 OOM 事件发生的时刻，供诊断观测
SEC("kprobe/oom_kill_process")
int oom_kill_process_kprobe(struct pt_regs *ctx)
{
	struct mem_oom_event_t ev = {};
	ev.ts = bpf_ktime_get_ns();
	// 其他字段留 0，Go 侧通过 dmesg / /proc 补充

	bpf_perf_event_output(ctx, &mem_oom_events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
	return 0;
}

char __license[] SEC("license") = "Dual BSD/GPL";
