package run

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"syscall"

	ebpfbinary "github.com/cen-ngc5139/shepherd/internal/binary"
	"github.com/cen-ngc5139/shepherd/internal/bpf"
	"github.com/cen-ngc5139/shepherd/internal/config"
	"github.com/cen-ngc5139/shepherd/internal/log"
	"github.com/cen-ngc5139/shepherd/internal/output"
	"github.com/cen-ngc5139/shepherd/server"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

func Run(cfg config.Configuration) {
	if cfg.ConfigPath != "" {
		err := config.LoadConfig(&cfg)
		if err != nil {
			log.Fatal(err)
			os.Exit(1)
		}
	}

	stopChan := make(chan struct{})
	defer close(stopChan)

	if cfg.Pprof.Enable {
		go func() {

			http.ListenAndServe(":6060", nil)
		}()
	}

	// 读取环境变量
	var nodeName string
	nodeName = os.Getenv("NODE_NAME")
	if nodeName == "" {
		// 获取当前节点主机名
		var err error
		nodeName, err = os.Hostname()
		if err != nil {
			log.Errorf("Failed to get the hostname: %v", err)
			os.Exit(1)
		}
	}

	// 移除 eBPF 程序的内存限制
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock limit: %v\n", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// 设置临时 rlimit
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &unix.Rlimit{
		Cur: 8192,
		Max: 8192,
	}); err != nil {
		log.Fatalf("failed to set temporary rlimit: %s", err)
	}

	// 获取 BPF 程序的入口函数名
	var btfSpec *btf.Spec
	var err error
	if cfg.BTF.Kernel != "" {
		btfSpec, err = btf.LoadSpec(cfg.BTF.Kernel)
	} else {
		// 从 /sys/kernel/btf/vmlinux 加载内核 BTF 规范
		btfSpec, err = btf.LoadKernelSpec()
	}

	if err != nil {
		log.Fatalf("Failed to load BTF spec: %s", err)
	}

	var opts ebpf.CollectionOptions
	opts.Programs.KernelTypes = btfSpec
	opts.Programs.LogLevel = ebpf.LogLevelInstruction

	// 加载 ebpf 程序集
	var bpfSpec *ebpf.CollectionSpec
	bpfSpec, err = ebpfbinary.LoadShepherd()
	if err != nil {
		log.Fatalf("Failed to load bpf spec: %v", err)
	}

	// 加载 ebpf 程序集
	coll, err := ebpf.NewCollectionWithOptions(bpfSpec, opts)
	if err != nil {
		var (
			ve          *ebpf.VerifierError
			verifierLog string
		)
		if errors.As(err, &ve) {
			verifierLog = fmt.Sprintf("Verifier error: %+v\n", ve)
		}

		log.Fatalf("Failed to load objects: %s\n%+v", verifierLog, err)
	}
	defer coll.Close()

	// 附加调度跟踪点
	schedTrace, err := bpf.AttachTracepointProgs(coll, bpf.SchedTracepointTargetProgs, "sched")
	if err != nil {
		log.Fatalf("Failed to attach sched tracepoint: %v", err)
	}
	defer schedTrace.Detach()

	// 附加中断跟踪点
	irqProgs := map[string]*ebpf.Program{
		"irq_handler_entry": coll.Programs["irq_handler_entry"],
		"irq_handler_exit":  coll.Programs["irq_handler_exit"],
	}
	irqTrace, err := bpf.AttachTracingProgs(coll, irqProgs, "irq")
	if err != nil {
		log.Errorf("Failed to attach irq tracing: %v", err)
	} else {
		defer irqTrace.Detach()
	}

	softirqProgs := map[string]*ebpf.Program{
		"softirq_entry": coll.Programs["softirq_entry"],
		"softirq_exit":  coll.Programs["softirq_exit"],
	}
	softirqTrace, err := bpf.AttachTracingProgs(coll, softirqProgs, "softirq")
	if err != nil {
		log.Errorf("Failed to attach softirq tracing: %v", err)
	} else {
		defer softirqTrace.Detach()
	}

	// 启动任务管理器，从 ebpf map 中获取数据并进行处理
	tm := NewTaskManager()

	tm.Add("服务器", func() error { return server.NewServer().Start() })
	tm.Add("处理调度延迟", func() error { output.ProcessSchedDelay(coll, ctx, cfg); return nil })
	// 运行所有任务
	if err := tm.Run(); err != nil {
		log.Errorf("错误: %v\n", err)
	}
}
