package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/cilium/ebpf/rlimit"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/profile/block-io/tracer"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/profile/block-io/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/mum4k/termdash/widgets/barchart"
)

func Biolatency(ctx context.Context, bc *barchart.BarChart) {

	// In some kernel versions it's needed to bump the rlimits to
	// use run BPF programs.
	if err := rlimit.RemoveMemlock(); err != nil {
		return
	}

	// Create the tracer. An empty configuration is passed as we are
	// not interesting on filtering by any container. For the same
	// reason, no enricher is passed.
	tracer, err := tracer.NewTracer()
	if err != nil {
		fmt.Printf("error creating tracer: %s\n", err)
		return
	}
	defer tracer.Stop()

	for {
		timeoutDuration := time.Second
		gadgetCtx := gadgetcontext.New(
			ctx,
			"",
			nil,
			nil,
			nil,
			nil,
			nil,
			nil,
			nil,
			logger.DefaultLogger(),
			timeoutDuration,
		)
		defer gadgetCtx.Cancel()

		reportBytes, err := tracer.RunWithResult(gadgetCtx)
		if err != nil {
			continue
		}

		report := &types.Report{}
		err = json.Unmarshal(reportBytes, report)
		if err != nil {
			panic(err)
		}

		var values []int
		maxValue := 20

		labels := []string{}

		for i := 0; i < len(report.Intervals); i++ {
			values = append(values, int(report.Intervals[i].Count))

			if int(report.Intervals[i].Count) > maxValue {
				maxValue = int(report.Intervals[i].Count)
			}

			labels = append(labels, fmt.Sprintf("%v-%v", report.Intervals[i].Start, report.Intervals[i].End))
		}

		if err := bc.Values(values, maxValue, barchart.Labels(labels)); err != nil {
			continue
		}
	}

}
