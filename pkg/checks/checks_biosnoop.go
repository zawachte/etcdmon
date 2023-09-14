package checks

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/rlimit"
	"github.com/zawachte/etcdmon/pkg/biosnoop/tracer"
	"github.com/zawachte/etcdmon/pkg/biosnoop/types"
)

func Biosnoop() {
	// In some kernel versions it's needed to bump the rlimits to
	// use run BPF programs.
	if err := rlimit.RemoveMemlock(); err != nil {
		return
	}

	// Define a callback to be called each time there is an event.
	eventCallback := func(event *types.Event) {
		eventBytes, err := json.Marshal(event)
		if err == nil {
			fmt.Println(string(eventBytes))
		}
	}

	// Create the tracer. An empty configuration is passed as we are
	// not interesting on filtering by any container. For the same
	// reason, no enricher is passed.
	tracer, err := tracer.NewTracer(&tracer.Config{
		//Interval: time.Second,
		//MaxRows:  5,
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
