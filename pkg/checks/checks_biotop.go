package checks

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns/formatter/textcolumns"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/block-io/tracer"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/block-io/types"
	"github.com/rivo/tview"
)

var gadgetColumns = columns.MustCreateColumns[types.Stats]()

func Biotop(ctx context.Context, textView *tview.TextView) {
	// In some kernel versions it's needed to bump the rlimits to
	// use run BPF programs.
	if err := rlimit.RemoveMemlock(); err != nil {
		return
	}

	// Leave out kubernetes info for this one, but include gadget data (not-embedded struct) and runtime information
	formatter := textcolumns.NewFormatter(
		gadgetColumns.GetColumnMap(columns.And(columns.WithEmbedded(false), columns.WithoutTag("runtime"))),
		textcolumns.WithAutoScale(false),
	)

	formatter.SetShowColumns([]string{"pid", "r/w", "bytes", "time"})

	// Define a callback to be called each time there is an event.
	eventCallback := func(event *top.Event[types.Stats]) {
		for _, stat := range event.Stats {
			if stat.Comm == "etcd" {
				textView.Clear()
				formatter.WriteTable(textView, []*types.Stats{stat})
				//fmt.Fprintf(textView, " number of slow fs operations (> 10ms) from etcd: %v\n slowest operation: %v, %s", start, maxLat, maxLatOp)
			}

		}
	}

	// Create the tracer. An empty configuration is passed as we are
	// not interesting on filtering by any container. For the same
	// reason, no enricher is passed.
	tracer, err := tracer.NewTracer(&tracer.Config{
		MaxRows:  20,
		Interval: 1 * time.Second,
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
