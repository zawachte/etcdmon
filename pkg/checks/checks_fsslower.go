package checks

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/fsslower/tracer"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/fsslower/types"
	"github.com/rivo/tview"
)

func Fsslower(ctx context.Context, textView *tview.TextView) {
	// In some kernel versions it's needed to bump the rlimits to
	// use run BPF programs.
	if err := rlimit.RemoveMemlock(); err != nil {
		return
	}

	start := 0
	maxLat := uint64(0)
	maxLatOp := "W"
	fmt.Fprintf(textView, " number of slow fs operations (> 10ms) from etcd: %v\n slowest operation: %v, %s", start, maxLat, maxLatOp)
	// Define a callback to be called each time there is an event.
	eventCallback := func(event *types.Event) {
		if event.Comm != "etcd" {
			return
		}

		if event.Latency > maxLat {
			maxLat = event.Latency
			maxLatOp = event.Op
		}

		start = start + 1
		textView.Clear()
		fmt.Fprintf(textView, " number of slow fs operations (>10ms) from etcd: %v\n last slow operation: %.2f ms, %s, %s\n slowest operation: %.2f ms, %s",
			start,
			float64(event.Latency)/1000.0,
			event.Op,
			time.Unix(0, int64(event.Timestamp)).Format("2006-01-02T15:04:05"),
			float64(maxLat)/1000.0,
			maxLatOp)
	}

	// Create the tracer. An empty configuration is passed as we are
	// not interesting on filtering by any container. For the same
	// reason, no enricher is passed.
	tracer, err := tracer.NewTracer(&tracer.Config{

		Filesystem: "ext4",
		MinLatency: 10,
	}, nil, eventCallback)
	if err != nil {
		fmt.Printf("error creating tracer: %s\n", err)
		return
	}
	defer tracer.Stop()

	// Graceful shutdown
	exit := make(chan os.Signal, 1)
	signal.Notify(exit, syscall.SIGINT, syscall.SIGTERM)
	<-exit
}
