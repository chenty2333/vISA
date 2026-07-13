package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"

	"github.com/partite-ai/wacogo"
	"github.com/partite-ai/wacogo/host"
	keyvalue "visa.local/wacogo-qualification/generated/visa/continuity/keyvalue"
	timers "visa.local/wacogo-qualification/generated/visa/continuity/timers"
)

const (
	componentSHA256 = "4d8c99fbe7475aa02983592f55a8cfdc4260753aec75de74e18a19ec47813e3b"
	witSHA256       = "709eb08784d446068bbaed47dbfb1dddd637f957cf5de1f3713d5be0aa7d5920"
	wacogoVersion   = "v0.0.0-20260617023329-3de16a61796c"
	wazeroVersion   = "v1.11.1-0.20260418165552-5cb4bb3ec0c1"
	workloadName    = "visa:continuity/workload@0.1.0"
	goVersion       = "go1.26.5"
	wacogoReplace   = "../wacogo"
	patchsetName    = "vISA downstream patchset v1"
	patch1SHA256    = "c04b82a5ec2a95c45f5f81bdce5b2cbff11e25556865eb19928b48b6f94eed69"
	patch2SHA256    = "3531ff7a61de7c41f4237d7077a4dd0602bedd15e3067db070fd3e659575a37e"
	patch3SHA256    = "4b32fe31643aedab8472c42ae38d635abbfc9133093866b5ff1de9dcc4548d0e"
)

type keyValueHost struct{}
type timersHost struct{}

type storedValue struct {
	value   []byte
	version uint64
}

type kvStore struct {
	values                map[string]storedValue
	expectedVersionChecks int
}

type namespaceResource struct {
	store *kvStore
	puts  int
	reads int
	drops int
}

func (n *namespaceResource) ConditionalPut(_ context.Context, idempotencyKey string, key string, expected keyvalue.OptionU64, value []uint8) (keyvalue.ResultWriteResultKvError, error) {
	n.puts++
	current, exists := n.store.values[key]
	if expected.IsSome {
		n.store.expectedVersionChecks++
		if !exists || current.version != expected.Value {
			return keyvalue.ResultWriteResultKvErrorErr{Value: keyvalue.KvErrorConflict{}}, nil
		}
	} else if exists {
		return keyvalue.ResultWriteResultKvErrorErr{Value: keyvalue.KvErrorConflict{}}, nil
	}
	version := uint64(1)
	if exists {
		version = current.version + 1
	}
	n.store.values[key] = storedValue{value: append([]byte(nil), value...), version: version}
	return keyvalue.ResultWriteResultKvErrorOk{Value: keyvalue.WriteResult{
		OperationID: idempotencyKey,
		Version:     version,
		Applied:     true,
	}}, nil
}

func (n *namespaceResource) Read(_ context.Context, key string) (keyvalue.ResultOptionVersionedValueKvError, error) {
	n.reads++
	current, exists := n.store.values[key]
	if !exists {
		return keyvalue.ResultOptionVersionedValueKvErrorOk{Value: keyvalue.NoneVersionedValue()}, nil
	}
	return keyvalue.ResultOptionVersionedValueKvErrorOk{Value: keyvalue.SomeVersionedValue(keyvalue.VersionedValue{
		Value:   append([]byte(nil), current.value...),
		Version: current.version,
	})}, nil
}

func (n *namespaceResource) Drop(context.Context) error {
	n.drops++
	return nil
}

type timerResource struct {
	arms    int
	cancels int
	drops   int
}

func (t *timerResource) Arm(_ context.Context, idempotencyKey string, _ uint64) (timers.ResultArmResultTimerError, error) {
	t.arms++
	return timers.ResultArmResultTimerErrorOk{Value: timers.ArmResult{OperationID: idempotencyKey}}, nil
}

func (t *timerResource) Cancel(_ context.Context, _ string) (timers.Result_TimerError, error) {
	t.cancels++
	return timers.Result_TimerErrorOk{}, nil
}

func (t *timerResource) Drop(context.Context) error {
	t.drops++
	return nil
}

type runtimeCell struct {
	kv       *host.ComponentInstance
	timer    *host.ComponentInstance
	guest    *wacogo.ComponentInstance
	workload *wacogo.ComponentInstance
}

func main() {
	if len(os.Args) != 3 {
		fatalf("usage: wacogo-probe COMPONENT WORLD_WIT")
	}

	component := verifiedBytes("component", os.Args[1], componentSHA256)
	if len(component) != 146486 {
		fatalf("component length mismatch: expected 146486, observed %d", len(component))
	}
	_ = verifiedBytes("world-wit", os.Args[2], witSHA256)
	verifyBuildIdentity()

	ctx := context.Background()
	engine := wacogo.NewEngine(ctx)
	defer closeOrFatal("engine", func() error { return engine.Close(ctx) })

	componentModel, err := engine.LoadComponent(ctx, bytes.NewReader(component))
	must("load unchanged component", err)
	verifySurface(componentModel)
	fmt.Println("parse-validate=passed")

	kvFactory, err := keyvalue.NewFactory(ctx, engine)
	must("build key-value host interface", err)
	defer closeOrFatal("key-value factory", func() error { return kvFactory.Close(ctx) })
	timerFactory, err := timers.NewFactory(ctx, engine)
	must("build timers host interface", err)
	defer closeOrFatal("timers factory", func() error { return timerFactory.Close(ctx) })

	source := newRuntimeCell(ctx, componentModel, kvFactory, timerFactory, true)
	fmt.Printf("kv-error-export=%T\n", source.kv.Core().ExportedType("kv-error"))
	fmt.Println("host-interface-build-and-host-instantiation=passed")
	fmt.Println("unchanged-component-instantiation=passed")

	const expectedMissingImportFailure = `wacogo: import "visa:continuity/timers@0.1.0": was not found`
	var missingImportFailures [2]string
	for attempt := range missingImportFailures {
		missing, missingErr := componentModel.Instantiate(
			ctx,
			wacogo.WithInstanceImport(keyvalue.InterfaceName, source.kv.Core()),
		)
		if missingErr == nil {
			if missing != nil {
				_ = missing.Close(ctx)
			}
			fatalf("missing timers import unexpectedly instantiated on attempt %d", attempt+1)
		}
		if missing != nil {
			_ = missing.Close(ctx)
			fatalf("missing timers import returned both an instance and an error on attempt %d", attempt+1)
		}
		missingImportFailures[attempt] = missingErr.Error()
		if missingImportFailures[attempt] != expectedMissingImportFailure {
			fatalf(
				"unexpected missing-import failure on attempt %d: got %q, want %q",
				attempt+1,
				missingImportFailures[attempt],
				expectedMissingImportFailure,
			)
		}
	}
	if missingImportFailures[0] != missingImportFailures[1] {
		fatalf(
			"missing-import diagnostics were not deterministic: first=%q second=%q",
			missingImportFailures[0],
			missingImportFailures[1],
		)
	}
	fmt.Printf(
		"negative-link-failure=classification:missing-required-import source:wacogo-diagnostic attempts:2 exact:true deterministic:true fallback:false error=%q\n",
		missingImportFailures[0],
	)

	store := &kvStore{values: make(map[string]storedValue)}
	sourceNamespace1 := &namespaceResource{store: store}
	sourceTimer1 := &timerResource{}
	nsOwn, timerOwn := source.ownedPair(sourceNamespace1, sourceTimer1)
	callResultOK(ctx, "source activate", source.export("activate"),
		wacogo.ValString("qualification-session"),
		wacogo.ValString("counter"),
		valBytes([]byte("initial")),
		valBytes([]byte("complete")),
		wacogo.ValU64(5_000_000_000),
		wacogo.ValString("baseline-op"),
		wacogo.ValString("timer-op"),
		wacogo.ValString("completion-op"),
		nsOwn,
		timerOwn,
	)
	requirePhase(ctx, "source status after activate", source, 0)
	if sourceNamespace1.puts != 1 || sourceNamespace1.reads != 1 || sourceTimer1.arms != 1 {
		fatalf("source activate callbacks: kv put/read=%d/%d timer arm=%d, want 1/1/1", sourceNamespace1.puts, sourceNamespace1.reads, sourceTimer1.arms)
	}
	fmt.Println("typed-owned-resource-transfer=passed")

	frozen := callResultOK(ctx, "source freeze", source.export("freeze"))
	frozenState, ok := frozen.(*wacogo.ValRecord)
	if !ok {
		fatalf("source freeze payload=%T, want record", frozen)
	}
	requireStatePhase("source frozen state", frozenState, 1)
	requireStatusNone(ctx, "source status after freeze", source)
	if sourceNamespace1.drops != 1 || sourceTimer1.drops != 1 {
		fatalf("source freeze drops: namespace/timer=%d/%d, want 1/1", sourceNamespace1.drops, sourceTimer1.drops)
	}

	sourceNamespace2 := &namespaceResource{store: store}
	sourceTimer2 := &timerResource{}
	nsOwn, timerOwn = source.ownedPair(sourceNamespace2, sourceTimer2)
	callResultOK(ctx, "source thaw", source.export("thaw"), frozenState, nsOwn, timerOwn)
	requirePhase(ctx, "source status after thaw", source, 0)
	callResultOK(ctx, "source cancel-pending", source.export("cancel-pending"))
	requirePhase(ctx, "source status after cancel", source, 3)
	if sourceTimer2.cancels != 1 || sourceTimer2.drops != 1 {
		fatalf("source cancel callbacks: cancel/drop=%d/%d, want 1/1", sourceTimer2.cancels, sourceTimer2.drops)
	}
	cancelled := callResultOK(ctx, "source freeze after cancel", source.export("freeze"))
	cancelledState, ok := cancelled.(*wacogo.ValRecord)
	if !ok {
		fatalf("source cancelled freeze payload=%T, want record", cancelled)
	}
	requireStatePhase("source cancelled state", cancelledState, 3)
	requireStatusNone(ctx, "source status after cancelled freeze", source)
	if sourceNamespace2.drops != 1 {
		fatalf("source cancelled namespace drops=%d, want 1", sourceNamespace2.drops)
	}
	fmt.Println("source-lifecycle=activate,status,freeze,thaw,cancel-pending,status,freeze passed")

	destination := newRuntimeCell(ctx, componentModel, kvFactory, timerFactory, false)
	destinationNamespace := &namespaceResource{store: store}
	destinationTimer := &timerResource{}
	nsOwn, timerOwn = destination.ownedPair(destinationNamespace, destinationTimer)
	callResultOK(ctx, "destination restore", destination.export("restore"),
		frozenState,
		wacogo.ValU64(4_000_000_000),
		nsOwn,
		timerOwn,
	)
	requirePhase(ctx, "destination status after restore", destination, 0)
	callResultOK(ctx, "destination timer-fired", destination.export("timer-fired"), wacogo.ValString("timer-op"))
	requirePhase(ctx, "destination status after timer-fired", destination, 2)
	if destinationTimer.arms != 1 || destinationTimer.drops != 1 || destinationNamespace.puts != 1 {
		fatalf("destination callbacks: timer arm/drop=%d/%d kv put=%d, want 1/1/1", destinationTimer.arms, destinationTimer.drops, destinationNamespace.puts)
	}
	completed := callResultOK(ctx, "destination freeze", destination.export("freeze"))
	completedState, ok := completed.(*wacogo.ValRecord)
	if !ok {
		fatalf("destination freeze payload=%T, want record", completed)
	}
	requireStatePhase("destination completed state", completedState, 2)
	requireStatusNone(ctx, "destination status after freeze", destination)
	if destinationNamespace.drops != 1 {
		fatalf("destination namespace drops=%d, want 1", destinationNamespace.drops)
	}
	finalValue, ok := store.values["counter"]
	if !ok || finalValue.version != 2 || !bytes.Equal(finalValue.value, []byte("complete")) || store.expectedVersionChecks != 1 {
		fatalf("shared KV final state: exists=%t version=%d value=%q expected-version-checks=%d, want true/2/complete/1", ok, finalValue.version, finalValue.value, store.expectedVersionChecks)
	}
	fmt.Println("shared-versioned-kv=version:2 value:complete expected-version-checks:1")
	fmt.Println("destination-lifecycle=restore,status,timer-fired,status,freeze passed")

	putCount := sourceNamespace1.puts + sourceNamespace2.puts + destinationNamespace.puts
	readCount := sourceNamespace1.reads + sourceNamespace2.reads + destinationNamespace.reads
	armCount := sourceTimer1.arms + sourceTimer2.arms + destinationTimer.arms
	cancelCount := sourceTimer1.cancels + sourceTimer2.cancels + destinationTimer.cancels
	namespaceDropCount := sourceNamespace1.drops + sourceNamespace2.drops + destinationNamespace.drops
	timerDropCount := sourceTimer1.drops + sourceTimer2.drops + destinationTimer.drops
	if putCount != 2 || readCount != 1 || armCount != 2 || cancelCount != 1 || namespaceDropCount != 3 || timerDropCount != 3 {
		fatalf("callback totals: put/read/arm/cancel/namespace-drop/timer-drop=%d/%d/%d/%d/%d/%d, want 2/1/2/1/3/3", putCount, readCount, armCount, cancelCount, namespaceDropCount, timerDropCount)
	}
	fmt.Printf("callback-counts=kv-put:%d kv-read:%d timer-arm:%d timer-cancel:%d namespace-drop:%d timer-binding-drop:%d\n", putCount, readCount, armCount, cancelCount, namespaceDropCount, timerDropCount)

	beforeCloseDrops := namespaceDropCount + timerDropCount
	closeOrFatal("destination guest", func() error { return destination.guest.Close(ctx) })
	closeOrFatal("destination timers host", func() error { return destination.timer.Close(ctx) })
	closeOrFatal("destination key-value host", func() error { return destination.kv.Close(ctx) })
	closeOrFatal("source guest", func() error { return source.guest.Close(ctx) })
	closeOrFatal("source timers host", func() error { return source.timer.Close(ctx) })
	closeOrFatal("source key-value host", func() error { return source.kv.Close(ctx) })
	afterCloseDrops := sourceNamespace1.drops + sourceNamespace2.drops + sourceTimer1.drops + sourceTimer2.drops + destinationNamespace.drops + destinationTimer.drops
	if beforeCloseDrops != 6 || afterCloseDrops != beforeCloseDrops {
		fatalf("resource drops before/after close=%d/%d, want 6/6", beforeCloseDrops, afterCloseDrops)
	}
	fmt.Println("real-host-callbacks=key-value.conditional-put,key-value.read,timers.arm,timers.cancel,namespace.drop,timer-binding.drop")
	fmt.Println("cleanup=all-guest-and-host-instances-closed no-orphans=true")
	fmt.Println("qualification-gates=7/7 passed")
	fmt.Println("selected-runtime=wacogo 3de16a6 + vISA downstream patchset v1")
	fmt.Println("decision=go")
}

func newRuntimeCell(
	ctx context.Context,
	component *wacogo.Component,
	kvFactory *keyvalue.Factory,
	timerFactory *timers.Factory,
	reportPreflight bool,
) *runtimeCell {
	kv, err := kvFactory.NewInstance(ctx, keyValueHost{}, nil)
	must("instantiate key-value host interface", err)
	timer, err := timerFactory.NewInstance(ctx, timersHost{}, nil)
	if err != nil {
		_ = kv.Close(ctx)
		fatalf("instantiate timers host interface: %v", err)
	}
	options := []wacogo.InstantiateOption{
		wacogo.WithInstanceImport(keyvalue.InterfaceName, kv.Core()),
		wacogo.WithInstanceImport(timers.InterfaceName, timer.Core()),
	}
	if err := component.CheckInstantiation(options...); err != nil {
		_ = timer.Close(ctx)
		_ = kv.Close(ctx)
		fatalf("preflight unchanged component: %v", err)
	}
	if reportPreflight {
		fmt.Println("non-executing-preflight=passed imports=key-value,timers")
	}
	guest, err := component.Instantiate(ctx, options...)
	if err != nil {
		_ = timer.Close(ctx)
		_ = kv.Close(ctx)
		fatalf("instantiate unchanged component: %v", err)
	}
	workload := guest.ExportedInstance(workloadName)
	if workload == nil {
		_ = guest.Close(ctx)
		_ = timer.Close(ctx)
		_ = kv.Close(ctx)
		fatalf("missing exported workload instance")
	}
	return &runtimeCell{kv: kv, timer: timer, guest: guest, workload: workload}
}

func (c *runtimeCell) export(name string) *wacogo.ExportedFunc {
	fn := c.workload.ExportedFunc(name)
	if fn == nil {
		fatalf("missing workload export %q", name)
	}
	return fn
}

func (c *runtimeCell) ownedPair(namespace *namespaceResource, timer *timerResource) (*wacogo.ValOwnHandle, *wacogo.ValOwnHandle) {
	nsTR, ok := c.kv.Core().ExportedType("namespace").(*wacogo.TypeResource)
	if !ok {
		fatalf("namespace resource export has type %T", c.kv.Core().ExportedType("namespace"))
	}
	timerTR, ok := c.timer.Core().ExportedType("timer-binding").(*wacogo.TypeResource)
	if !ok {
		fatalf("timer-binding resource export has type %T", c.timer.Core().ExportedType("timer-binding"))
	}
	return wacogo.NewValOwnHandle(nsTR, uint32(c.kv.RegisterResource(namespace))),
		wacogo.NewValOwnHandle(timerTR, uint32(c.timer.RegisterResource(timer)))
}

func callResultOK(ctx context.Context, label string, fn *wacogo.ExportedFunc, args ...wacogo.Val) wacogo.Val {
	results, err := fn.Call(ctx, args...)
	must("call "+label, err)
	if len(results) != 1 {
		fatalf("%s result count=%d, want 1", label, len(results))
	}
	result, ok := results[0].(*wacogo.ValResult)
	if !ok {
		fatalf("%s result=%T, want *ValResult", label, results[0])
	}
	if !result.IsOk() {
		failure, _ := result.Err().(*wacogo.ValVariant)
		if failure == nil {
			fatalf("%s returned non-variant workload error %T", label, result.Err())
		}
		fatalf("%s workload error: discriminant=%d payload=%#v", label, failure.Discriminant(), failure.Val())
	}
	return result.Ok()
}

func requirePhase(ctx context.Context, label string, cell *runtimeCell, expected uint32) *wacogo.ValRecord {
	results, err := cell.export("status").Call(ctx)
	must("call "+label, err)
	if len(results) != 1 {
		fatalf("%s result count=%d, want 1", label, len(results))
	}
	option, ok := results[0].(*wacogo.ValOption)
	if !ok || option.IsNone() {
		fatalf("%s result=%T %#v, want some state", label, results[0], results[0])
	}
	state, ok := option.Val().(*wacogo.ValRecord)
	if !ok {
		fatalf("%s state=%T, want record", label, option.Val())
	}
	requireStatePhase(label, state, expected)
	return state
}

func requireStatusNone(ctx context.Context, label string, cell *runtimeCell) {
	results, err := cell.export("status").Call(ctx)
	must("call "+label, err)
	if len(results) != 1 {
		fatalf("%s result count=%d, want 1", label, len(results))
	}
	option, ok := results[0].(*wacogo.ValOption)
	if !ok || !option.IsNone() {
		fatalf("%s result=%T %#v, want none", label, results[0], results[0])
	}
}

func requireStatePhase(label string, state *wacogo.ValRecord, expected uint32) {
	phase, ok := state.Field("phase").(*wacogo.ValEnum)
	if !ok {
		fatalf("%s phase=%T, want enum", label, state.Field("phase"))
	}
	if phase.Discriminant() != expected {
		fatalf("%s phase=%d, want %d", label, phase.Discriminant(), expected)
	}
}

func valBytes(data []byte) *wacogo.ValList {
	elems := make([]wacogo.ValU8, len(data))
	for i, b := range data {
		elems[i] = wacogo.ValU8(b)
	}
	return wacogo.NewValListOf(elems...)
}

func verifiedBytes(label, path, expected string) []byte {
	data, err := os.ReadFile(path)
	must("read "+label, err)
	digest := sha256.Sum256(data)
	observed := hex.EncodeToString(digest[:])
	if observed != expected {
		fatalf("%s SHA-256 mismatch: expected %s, observed %s", label, expected, observed)
	}
	fmt.Printf("%s-sha256=%s\n", label, observed)
	return data
}

func verifyBuildIdentity() {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		fatalf("Go build identity unavailable")
	}
	if info.GoVersion != goVersion || runtime.Version() != goVersion || runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		fatalf(
			"Go build identity mismatch: build=%s runtime=%s target=%s/%s, want %s linux/amd64",
			info.GoVersion,
			runtime.Version(),
			runtime.GOOS,
			runtime.GOARCH,
			goVersion,
		)
	}
	if info.Main.Path != "visa.local/wacogo-qualification" {
		fatalf("main module mismatch: %s", info.Main.Path)
	}
	fmt.Printf("go-build=%s target=%s/%s main=%s\n", info.GoVersion, runtime.GOOS, runtime.GOARCH, info.Main.Path)
	expected := map[string]struct {
		version string
		replace string
	}{
		"github.com/partite-ai/wacogo":  {version: wacogoVersion, replace: wacogoReplace},
		"github.com/tetratelabs/wazero": {version: wazeroVersion},
	}
	for _, dependency := range info.Deps {
		if want, ok := expected[dependency.Path]; ok {
			observedReplace := ""
			if dependency.Replace != nil {
				observedReplace = dependency.Replace.Path
			}
			if dependency.Version != want.version || observedReplace != want.replace {
				fatalf(
					"dependency identity mismatch for %s: version=%s replacement=%q",
					dependency.Path,
					dependency.Version,
					observedReplace,
				)
			}
			if observedReplace == "" {
				fmt.Printf("dependency=%s@%s\n", dependency.Path, dependency.Version)
			} else {
				fmt.Printf("dependency=%s@%s replace=%s\n", dependency.Path, dependency.Version, observedReplace)
			}
			delete(expected, dependency.Path)
		}
	}
	if len(expected) != 0 {
		missing := make([]string, 0, len(expected))
		for path := range expected {
			missing = append(missing, path)
		}
		sort.Strings(missing)
		fatalf("missing build dependencies: %s", strings.Join(missing, ", "))
	}
	fmt.Printf(
		"downstream-patchset=%s patch-sha256=%s,%s,%s\n",
		patchsetName,
		patch1SHA256,
		patch2SHA256,
		patch3SHA256,
	)
}

func verifySurface(component *wacogo.Component) {
	expectedImports := map[string]wacogo.Sort{
		keyvalue.InterfaceName: wacogo.SortInstance,
		timers.InterfaceName:   wacogo.SortInstance,
	}
	if len(component.Imports()) != len(expectedImports) {
		fatalf("unexpected import count: %d", len(component.Imports()))
	}
	for _, item := range component.Imports() {
		kind, ok := expectedImports[item.Name]
		if !ok || item.Kind != kind {
			fatalf("unexpected import: name=%q kind=%v", item.Name, item.Kind)
		}
		fmt.Printf("import=%s kind=instance\n", item.Name)
	}
	if len(component.Exports()) != 1 {
		fatalf("unexpected export count: %d", len(component.Exports()))
	}
	export := component.Exports()[0]
	if export.Name != workloadName || export.Kind != wacogo.SortInstance {
		fatalf("unexpected export: name=%q kind=%v", export.Name, export.Kind)
	}
	fmt.Printf("export=%s kind=instance\n", export.Name)
}

func must(label string, err error) {
	if err != nil {
		fatalf("%s: %v", label, err)
	}
}

func closeOrFatal(label string, close func() error) {
	if err := close(); err != nil {
		fatalf("close %s: %v", label, err)
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
