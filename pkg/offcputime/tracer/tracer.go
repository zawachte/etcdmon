// Copyright 2022-2023 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build !withoutebpf

package tracer

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/kallsyms"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/zawachte/etcdmon/pkg/biosnoop/types"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-global-types -target $TARGET -cc clang -type event biosnoop ./bpf/biosnoop.bpf.c -- -I./bpf/ -I../../../../../go/pkg/mod/github.com/inspektor-gadget/inspektor-gadget@v0.19.0/pkg/${TARGET} -I../../../../../go/pkg/mod/github.com/inspektor-gadget/inspektor-gadget@v0.19.0/pkg/gadgets/common

type Config struct {
	MountnsMap *ebpf.Map

	Filesystem string
	MinLatency uint
}

type Tracer struct {
	config        *Config
	enricher      gadgets.DataEnricherByMntNs
	eventCallback func(*types.Event)

	objs                 biosnoopObjects
	blkAccountIoMergeBio link.Link
	blkAccountIoStart    link.Link
	blockIoStart         link.Link
	blockRqComplete      link.Link
	blockRqInsert        link.Link
	blockRqIssue         link.Link
	reader               *perf.Reader
}

type fsConf struct {
	read  string
	write string
	open  string
	fsync string
}

func NewTracer(config *Config, enricher gadgets.DataEnricherByMntNs,
	eventCallback func(*types.Event),
) (*Tracer, error) {
	t := &Tracer{
		config:        config,
		enricher:      enricher,
		eventCallback: eventCallback,
	}

	if err := t.install(); err != nil {
		t.close()
		return nil, errors.New(fmt.Sprintf("%v install tracer", err))
	}

	fmt.Println("about to run")
	go t.run()

	return t, nil
}

// Stop stops the tracer
// TODO: Remove after refactoring
func (t *Tracer) Stop() {
	t.close()
}

func (t *Tracer) close() {

	t.blkAccountIoMergeBio = gadgets.CloseLink(t.blkAccountIoMergeBio)
	t.blkAccountIoStart = gadgets.CloseLink(t.blkAccountIoStart)
	t.blockIoStart = gadgets.CloseLink(t.blockIoStart)
	t.blockRqComplete = gadgets.CloseLink(t.blockRqComplete)
	t.blockRqInsert = gadgets.CloseLink(t.blockRqInsert)
	t.blockRqIssue = gadgets.CloseLink(t.blockRqIssue)

	if t.reader != nil {
		t.reader.Close()
	}

	t.objs.Close()
}

func (t *Tracer) install() error {
	var err error

	spec, err := loadBiosnoop()
	if err != nil {
		return fmt.Errorf("loading ebpf program: %w", err)
	}

	if err := gadgets.LoadeBPFSpec(t.config.MountnsMap, spec, nil, &t.objs); err != nil {
		return fmt.Errorf("loading ebpf spec: %w", err)
	}

	kernelSymbols, err := kallsyms.NewKAllSyms()
	if err != nil {
		return fmt.Errorf("loading kernel symbols: %w", err)
	}

	t.blkAccountIoMergeBio, err = link.Kprobe("blk_account_io_merge_bio", t.objs.BlkAccountIoMergeBio, nil)
	if err != nil {
		return fmt.Errorf("attaching kprobe blk_account_io_merge_bio: %w", err)
	}

	blkAccountIoStartFunction := "__blk_account_io_start"
	if !kernelSymbols.SymbolExists(blkAccountIoStartFunction) {
		blkAccountIoStartFunction = "blk_account_io_start"
	}

	t.blkAccountIoStart, err = link.Kprobe("blk_account_io_start", t.objs.BlkAccountIoStart, nil)
	if err != nil {
		return fmt.Errorf("attaching kprobe blk_account_io_start: %w", err)
	}

	blockRqCompleteLink, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: "block_rq_complete", Program: t.objs.BlockRqComplete})
	if err != nil {
		return fmt.Errorf("attaching tracepoint for block_rq_complete: %w", err)
	}
	t.blockRqComplete = blockRqCompleteLink

	blockRqInsertLink, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: "block_rq_insert", Program: t.objs.Z_blockRqInsert})
	if err != nil {
		return fmt.Errorf("attaching tracepoint for block_rq_insert: %w", err)
	}
	t.blockRqInsert = blockRqInsertLink

	blockRqIssueLink, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: "block_rq_issue", Program: t.objs.Z_blockRqIssue})
	if err != nil {
		return fmt.Errorf("attaching tracepoint for block_rq_issue: %w", err)
	}
	t.blockRqIssue = blockRqIssueLink

	t.reader, err = perf.NewReader(t.objs.biosnoopMaps.Events, gadgets.PerfBufferPages*os.Getpagesize())
	if err != nil {
		return fmt.Errorf("creating perf ring buffer: %w", err)
	}

	fmt.Println("left this install")

	return nil
}

var startTs float64

func (t *Tracer) run() {
	for {
		record, err := t.reader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				// nothing to do, we're done
				return
			}

			msg := fmt.Sprintf("Error reading perf ring buffer: %s", err)
			t.eventCallback(types.Base(eventtypes.Err(msg)))
			return
		}

		if record.LostSamples > 0 {
			msg := fmt.Sprintf("lost %d samples", record.LostSamples)
			t.eventCallback(types.Base(eventtypes.Warn(msg)))
			continue
		}

		bpfEvent := (*biosnoopEvent)(unsafe.Pointer(&record.RawSample[0]))

		if startTs == 0 {
			startTs = float64(bpfEvent.Ts)
		}

		time := (float64(bpfEvent.Ts) - startTs) / 1000000000.0
		lat := float64(bpfEvent.Delta) / 1000000.0
		event := types.Event{
			Event: eventtypes.Event{
				Type: eventtypes.NORMAL,
			},
			Comm:   gadgets.FromCString(bpfEvent.Comm[:]),
			Pid:    bpfEvent.Pid,
			Time:   time,
			Lat:    lat,
			Sector: bpfEvent.Sector,
			Len:    bpfEvent.Len,
		}

		if t.enricher != nil {
			t.enricher.EnrichByMntNs(&event.CommonData, event.MountNsID)
		}

		t.eventCallback(&event)
	}
}

// --- Registry changes

func (t *Tracer) Run(gadgetCtx gadgets.GadgetContext) error {
	params := gadgetCtx.GadgetParams()
	t.config.Filesystem = params.Get(ParamFilesystem).AsString()

	defer t.close()
	if err := t.install(); err != nil {
		return fmt.Errorf("installing tracer: %w", err)
	}

	go t.run()
	gadgetcontext.WaitForTimeoutOrDone(gadgetCtx)

	return nil
}

func (t *Tracer) SetMountNsMap(mountnsMap *ebpf.Map) {
	t.config.MountnsMap = mountnsMap
}

func (t *Tracer) SetEventHandler(handler any) {
	nh, ok := handler.(func(ev *types.Event))
	if !ok {
		panic("event handler invalid")
	}
	t.eventCallback = nh
}

func (g *GadgetDesc) NewInstance() (gadgets.Gadget, error) {
	tracer := &Tracer{
		config: &Config{},
	}
	return tracer, nil
}
