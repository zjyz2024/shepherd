# Shepherd 调度分析测试方法

本文档详细说明如何测试 Phase 2-5 各阶段的功能。

## 环境准备

```powershell
# 1. 生成 BPF 绑定（如果修改了 trace.c）
cd c:\Users\user\Code\shepherd
go generate

# 2. 构建二进制
make build

# 3. 准备测试负载（建议在 Linux 目标机器上）
# - 使用 stress-ng 或 sysbench 进行压测
# - 或使用 Go 编写的测试程序
```

## Phase 2 - Off-CPU 分析测试

### 功能描述
- 采集进程离开 CPU 时的栈跟踪
- 计算每个进程的 Off-CPU 总时间和事件计数
- 支持 1/100 采样率（可调整）

### 测试步骤

#### 2.1 CLI 显示测试
```bash
# 启动 shepherd
./shepherd

# 按下 "/" 打开列表菜单
# 选择 "[4] OFF_CPU" 查看列：
# - PID: 进程ID
# - COMM: 进程名
# - OFF_CPU(ms): 累积离开 CPU 时间
# - COUNT: Off-CPU 事件次数
```

#### 2.2 Prometheus 指标验证
```bash
# 启动 shepherd（需配置 Prometheus 端口，默认 8080）
./shepherd --metrics-port 8080

# 在另一个终端查询指标
curl http://localhost:8080/metrics | grep off_cpu

# 预期输出：
# off_cpu_time_ns{comm="...",pid="..."} <value>
# off_cpu_event_count{comm="...",pid="..."} <value>
```

#### 2.3 数据正确性验证
- 运行高 IO 密集的任务（e.g., `dd if=/dev/urandom of=/dev/null`)
- 观察该进程的 OFF_CPU 时间是否增加
- 使用 `top -d 0.5` 或 `ps` 验证进程是否频繁 Sleep/等待

### 预期结果
- ✅ Off-CPU 时间持续增加
- ✅ `COUNT` 值反映采样事件数（约实际事件的 1%）
- ✅ Prometheus 指标显示正确的 PID 和进程名

---

## Phase 3 - 上下文切换分析测试

### 功能描述
- 区分自愿上下文切换（进程主动放弃 CPU）
- 统计非自愿上下文切换（被抢占）
- 导出 Prometheus 指标

### 测试步骤

#### 3.1 CLI 显示测试
```bash
./shepherd

# 按 "/" 打开菜单，选择 "[2] CTXT_SWITCH"
# 列：
# - PID, COMM
# - VOL_CTX: 自愿上下文切换
# - INVOL_CTX: 非自愿上下文切换
# - CTX_TOTAL: 总切换次数
```

#### 3.2 排序验证
```bash
# 按 "t" 切换排序字段
# 验证 VOL_CTX 和 INVOL_CTX 列是否按正确顺序排列
```

#### 3.3 Prometheus 指标验证
```bash
curl http://localhost:8080/metrics | grep context_switches

# 预期输出：
# voluntary_context_switches{comm="...",pid="..."} <value>
# involuntary_context_switches{comm="...",pid="..."} <value>
```

#### 3.4 场景验证
- **高自愿切换**：运行 `sleep` 命令或多线程 I/O 程序
  - 预期：VOL_CTX 快速增加
  
- **高非自愿切换**：运行 CPU 密集任务，同时创建竞争
  ```bash
  stress-ng --cpu 4 --timeout 30s
  ```
  - 预期：INVOL_CTX 快速增加

### 预期结果
- ✅ VOL_CTX 和 INVOL_CTX 分别统计正确
- ✅ VOL_CTX + INVOL_CTX ≈ 总切换次数（无丢失）
- ✅ Prometheus 指标可正确导出

---

## Phase 4 - CPU 迁移跟踪测试

### 功能描述
- 捕获进程在 CPU 间迁移事件
- 计算迁移距离（原始 CPU 到目标 CPU 的差值）
- 统计平均迁移距离

### 测试步骤

#### 4.1 CLI 显示测试
```bash
./shepherd

# 按 "/" 打开菜单，选择 "[3] MIGRATION"
# 列：
# - PID, COMM
# - MIGRATIONS: 迁移次数
# - AVG_DIST: 平均迁移距离（CPU 核心数差值）
```

#### 4.2 迁移触发
```bash
# 在多核心系统上运行
# 使用 taskset 强制改变进程亲和性：
for i in {1..10}; do
  taskset -p -c $((i % $(nproc))) $$ & sleep 1
done

# 验证迁移计数是否增加
```

#### 4.3 Prometheus 指标验证
```bash
curl http://localhost:8080/metrics | grep migration

# 预期输出：
# migration_count{comm="...",pid="..."} <value>
# avg_migration_distance{comm="...",pid="..."} <value>
```

#### 4.4 距离计算验证
- 在 4 核 CPU 上：从 CPU0 迁移到 CPU3，距离 = 3
- 从 CPU2 迁移到 CPU0，距离 = 2
- 验证 AVG_DIST 是所有迁移距离的平均值

### 预期结果
- ✅ 多核系统上能捕获迁移事件
- ✅ 迁移距离计算正确
- ✅ Prometheus 指标准确反映迁移统计

---

## Phase 5 - 优先级反转检测测试

### 功能描述
- 检测高优先级进程被低优先级进程延迟的情况
- 统计优先级反转次数
- 记录最大反转阻塞时间

### 测试步骤

#### 5.1 CLI 显示测试
```bash
./shepherd

# 按 "/" 打开菜单，选择 "[5] PRIORITY_INVERSION"
# 列：
# - PID, COMM
# - PI_COUNT: 优先级反转次数
# - MAX_BLOCK_TIME(ms): 最大反转阻塞时间
```

#### 5.2 优先级反转场景模拟
```bash
# 方案 1：使用线程优先级竞争
# 创建低优先级持有锁，高优先级等待的场景：

# 创建测试程序 (Go):
cat > pi_test.go << 'EOF'
package main
import (
    "sync"
    "time"
)
func main() {
    var mu sync.Mutex
    done := make(chan bool)
    
    // 低优先级线程持有锁
    go func() {
        mu.Lock()
        defer mu.Unlock()
        time.Sleep(5 * time.Second) // 持有 5 秒
    }()
    
    time.Sleep(100 * time.Millisecond)
    
    // 高优先级线程等待锁
    go func() {
        mu.Lock()
        mu.Unlock()
        done <- true
    }()
    
    <-done
}
EOF

go run pi_test.go
```

#### 5.3 Prometheus 指标验证
```bash
curl http://localhost:8080/metrics | grep priority_inversion

# 预期输出：
# priority_inversion_count{comm="...",pid="..."} <value>
# max_inversion_block_time_ns{comm="...",pid="..."} <value>
```

#### 5.4 排序验证
```bash
# 按 "t" 循环排序，验证 PI_COUNT 排序功能
# 预期高优先级反转的进程排在前面
```

### 预期结果
- ✅ 检测到高优先级被低优先级延迟的情况
- ✅ PI_COUNT 累加正确
- ✅ MAX_BLOCK_TIME 记录最长阻塞时间
- ✅ Prometheus 指标正确导出

---

## 集成测试 - FULL 列模式

```bash
./shepherd

# 按 "/" 选择 "[6] FULL"
# 同时显示所有指标（Phase 1-5）
```

### 验证检查清单
- [ ] LATENCY(ms) 显示阿正值 > 0
- [ ] PREEMPT 计数增加
- [ ] VOL_CTX 和 INVOL_CTX 分别统计
- [ ] MIGRATIONS 和 AVG_DIST 显示迁移信息
- [ ] OFF_CPU 时间持续增加
- [ ] PI_COUNT 和 MAX_BLOCK 显示反演信息
- [ ] STACK_TRACE 显示内核栈（如启用符号解析）

---

## 快捷键速查表

| 按键 | 功能 |
|------|------|
| `/` | 打开列选择菜单 |
| `l` | 在列组间循环切换 |
| `t` | 循环切换排序字段 |
| `s` | 切换符号解析开关 |
| `d` | 回到调度视图 |
| `n` | 切换其他视图 |
| `r` | 重置为默认视图 |
| `q` 或 `Ctrl+C` | 退出 |

---

## 故障排除

### 问题：Off-CPU 时间总是 0
- ✅ 检查进程是否真的离开 CPU（e.g., 运行 I/O 密集操作）
- ✅ 调整 BPF 采样率（当前 1/100）

### 问题：没有上下文切换数据
- ✅ 确认进程确实在运行（检查 `ps` 或 `top`）
- ✅ 验证 BPF tracepoint 是否正确附加

### 问题：迁移计数为 0
- ✅ 确认系统是多核
- ✅ 使用 `taskset` 手动强制迁移进程
- ✅ 检查 `sched_migrate_task` tracepoint 是否可用

### 问题：无法在 Prometheus 看到数据
- ✅ 确认 shepherd 已启动并暴露了 metrics 端口
- ✅ 检查防火墙规则
- ✅ 访问 `http://localhost:8080/metrics` 查看是否有数据

---

## 构建和汇报

构建完成后，如遇到编译错误：

```powershell
# 1. 检查错误信息
make build 2>&1 | Tee build.log

# 2. 常见错误：
# - undefined: binary.ShepherdSchedLatencyT.IsPriorityInversion
#   → 需要运行 go generate 重新生成绑定

# 3. 重新生成后再构建
go generate
make build
```

---

## 性能影响

Shepherd 在生产环境的典型性能开销：
- **CPU**: < 2% (默认采样率)
- **内存**: ~50-100MB (hash map + caches)
- **系统调用**: ~100-500/秒 (perf buffer reads)

可通过调整采样率降低开销。

---

## 参考

- Linux kernel doc: sched_switch, sched_wakeup, sched_migrate_task tracepoints
- CI/eBPF library: [cilium/ebpf](https://github.com/cilium/ebpf)
- 优先级反转参考: [Priority Inversion Detection](https://en.wikipedia.org/wiki/Priority_inversion)
