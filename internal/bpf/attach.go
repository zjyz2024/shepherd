package bpf

import (
	"github.com/cilium/ebpf"
)

var (
	SchedTracepointTargetProgs = map[string]string{
		"sched_wakeup":     "sched_wakeup",
		"sched_wakeup_new": "sched_wakeup_new",
		"sched_switch":     "sched_switch",
	}
)

func AttachTracepointProgs(coll *ebpf.Collection, target map[string]string, group string) (*tracing, error) {
	btfTracepointProgs := map[string]*ebpf.Program{}
	tracepointProgs := map[string]*ebpf.Program{}
	for name, prog := range coll.Programs {
		key, ok := target[name]
		if !ok {
			continue
		}

		switch prog.Type().String() {
		case ebpf.TracePoint.String():
			tracepointProgs[key] = prog
		case ebpf.Tracing.String():
			btfTracepointProgs[key] = prog
		}
	}

	t := &tracing{}
	if err := t.Tracepoint(group, tracepointProgs); err != nil {
		return nil, err
	}

	if err := t.Tracing(group, btfTracepointProgs); err != nil {
		return nil, err
	}

	return t, nil
}

func AttachTracingProgs(coll *ebpf.Collection, target map[string]*ebpf.Program, group string) (*tracing, error) {
	btfTracepointProgs := map[string]*ebpf.Program{}
	for name, prog := range target {
		if prog == nil {
			continue
		}
		btfTracepointProgs[name] = prog
	}

	t := &tracing{}
	if err := t.Tracing(group, btfTracepointProgs); err != nil {
		return nil, err
	}

	return t, nil
}
