package runtimecell

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/partite-ai/wacogo"
	"github.com/partite-ai/wacogo/host"
	keyvalue "visa.local/wacogo-runtime/generated/visa/continuity/keyvalue"
	timers "visa.local/wacogo-runtime/generated/visa/continuity/timers"
	"visa.local/wacogo-runtime/internal/protocol"
)

const (
	workloadName            = "visa:continuity/workload@0.1.0"
	acceptedComponentSize   = 146486
	acceptedComponentSHA256 = "4d8c99fbe7475aa02983592f55a8cfdc4260753aec75de74e18a19ec47813e3b"
)

var requiredWorkloadExports = [...]string{
	"activate",
	"freeze",
	"restore",
	"thaw",
	"timer-fired",
	"cancel-pending",
	"status",
}

type keyValueHost struct{}
type timersHost struct{}

type resourceKind string

const (
	resourceKV    resourceKind = "kv"
	resourceTimer resourceKind = "timer"
)

type resourceKey struct {
	kind resourceKind
	id   uint64
}

type Cell struct {
	ctx           context.Context
	channel       *protocol.Channel
	engine        *wacogo.Engine
	component     *wacogo.Component
	kvFactory     *keyvalue.Factory
	timerFactory  *timers.Factory
	kvHost        *host.ComponentInstance
	timerHost     *host.ComponentInstance
	namespaceType *wacogo.TypeResource
	timerType     *wacogo.TypeResource
	guest         *wacogo.ComponentInstance
	workload      *wacogo.ComponentInstance
	resources     map[resourceKey]struct{}
	instantiated  bool
	closed        bool
}

func Prepare(
	ctx context.Context,
	channel *protocol.Channel,
	componentBytes []byte,
) (*Cell, *protocol.WireError) {
	if err := verifyAcceptedComponent(componentBytes); err != nil {
		return nil, protocol.NewError("preflight", "unsupported-runtime-feature", err)
	}
	cell := &Cell{
		ctx:       ctx,
		channel:   channel,
		resources: make(map[resourceKey]struct{}),
	}
	cell.engine = wacogo.NewEngine(ctx)

	component, err := cell.engine.LoadComponent(ctx, bytes.NewReader(componentBytes))
	if err != nil {
		return nil, cell.prepareFailure("preflight", "invalid-component", err)
	}
	cell.component = component
	if err := verifySurface(component); err != nil {
		return nil, cell.prepareFailure("preflight", "invalid-surface", err)
	}

	cell.kvFactory, err = keyvalue.NewFactory(ctx, cell.engine)
	if err != nil {
		return nil, cell.prepareFailure("link", "key-value-factory", err)
	}
	cell.timerFactory, err = timers.NewFactory(ctx, cell.engine)
	if err != nil {
		return nil, cell.prepareFailure("link", "timers-factory", err)
	}
	cell.kvHost, err = cell.kvFactory.NewInstance(ctx, keyValueHost{}, nil)
	if err != nil {
		return nil, cell.prepareFailure("link", "key-value-instance", err)
	}
	cell.timerHost, err = cell.timerFactory.NewInstance(ctx, timersHost{}, nil)
	if err != nil {
		return nil, cell.prepareFailure("link", "timers-instance", err)
	}

	var ok bool
	cell.namespaceType, ok = cell.kvHost.Core().ExportedType("namespace").(*wacogo.TypeResource)
	if !ok {
		return nil, cell.prepareFailure(
			"link",
			"namespace-resource-type",
			fmt.Errorf("namespace export has type %T", cell.kvHost.Core().ExportedType("namespace")),
		)
	}
	cell.timerType, ok = cell.timerHost.Core().ExportedType("timer-binding").(*wacogo.TypeResource)
	if !ok {
		return nil, cell.prepareFailure(
			"link",
			"timer-resource-type",
			fmt.Errorf("timer-binding export has type %T", cell.timerHost.Core().ExportedType("timer-binding")),
		)
	}

	if err := component.CheckInstantiation(cell.instantiateOptions()...); err != nil {
		return nil, cell.prepareFailure("link", "check-instantiation", err)
	}
	return cell, nil
}

func (c *Cell) Instantiate() *protocol.WireError {
	if c.closed || c.instantiated {
		return protocol.ErrorDetail("protocol", "invalid-state", "instantiate requires a prepared cell")
	}
	guest, err := c.component.Instantiate(c.ctx, c.instantiateOptions()...)
	if err != nil {
		return protocol.NewError("instantiation", "component-instantiate", err)
	}
	workload := guest.ExportedInstance(workloadName)
	if workload == nil {
		_ = guest.Close(c.ctx)
		return protocol.ErrorDetail(
			"instantiation",
			"missing-workload-export",
			"instantiated component did not export the typed workload instance",
		)
	}
	if err := verifyLiveWorkloadSurface(workload); err != nil {
		_ = guest.Close(c.ctx)
		return protocol.NewError("instantiation", "invalid-workload-surface", err)
	}
	c.guest = guest
	c.workload = workload
	c.instantiated = true
	return nil
}

func (c *Cell) Handle(op string, raw json.RawMessage) (any, *protocol.WireError, bool) {
	if op == "instantiate" {
		if err := decodeEmpty(raw); err != nil {
			return nil, protocol.NewError("protocol", "invalid-arguments", err), true
		}
		if failure := c.Instantiate(); failure != nil {
			return nil, failure, true
		}
		return nil, nil, false
	}
	if op == "shutdown" {
		if err := decodeEmpty(raw); err != nil {
			return nil, protocol.NewError("protocol", "invalid-arguments", err), true
		}
		if err := c.Close(); err != nil {
			return nil, protocol.NewError("trap", "shutdown-cleanup", err), true
		}
		if c.LiveResources() != 0 {
			return nil, protocol.ErrorDetail(
				"trap",
				"shutdown-live-resources",
				fmt.Sprintf("shutdown retained %d runtime resources", c.LiveResources()),
			), true
		}
		return nil, nil, true
	}
	if !c.instantiated || c.closed {
		return nil, protocol.ErrorDetail(
			"protocol",
			"invalid-state",
			"lifecycle command requires a live component instance",
		), true
	}

	var result any
	var failure *protocol.WireError
	switch op {
	case "activate":
		result, failure = c.activate(raw)
	case "freeze":
		result, failure = c.freeze(raw)
	case "thaw":
		result, failure = c.thaw(raw)
	case "restore":
		result, failure = c.restore(raw)
	case "timer-fired":
		result, failure = c.timerFired(raw)
	case "cancel-pending":
		result, failure = c.cancelPending(raw)
	case "status":
		result, failure = c.status(raw)
	default:
		return nil, protocol.ErrorDetail(
			"protocol",
			"unknown-command",
			fmt.Sprintf("unknown command operation %q", op),
		), true
	}
	return result, failure, failure != nil && failure.Domain != "workload"
}

func (c *Cell) LiveResources() uint64 {
	return uint64(len(c.resources))
}

func (c *Cell) Close() error {
	if c.closed {
		return nil
	}
	c.closed = true
	var closeErrors []error
	if c.guest != nil {
		closeErrors = appendIfError(closeErrors, "guest", c.guest.Close(c.ctx))
		c.guest = nil
		c.workload = nil
	}
	if c.timerHost != nil {
		closeErrors = appendIfError(closeErrors, "timers host instance", c.timerHost.Close(c.ctx))
		c.timerHost = nil
	}
	if c.kvHost != nil {
		closeErrors = appendIfError(closeErrors, "key-value host instance", c.kvHost.Close(c.ctx))
		c.kvHost = nil
	}
	if c.timerFactory != nil {
		closeErrors = appendIfError(closeErrors, "timers factory", c.timerFactory.Close(c.ctx))
		c.timerFactory = nil
	}
	if c.kvFactory != nil {
		closeErrors = appendIfError(closeErrors, "key-value factory", c.kvFactory.Close(c.ctx))
		c.kvFactory = nil
	}
	if c.engine != nil {
		closeErrors = appendIfError(closeErrors, "engine", c.engine.Close(c.ctx))
		c.engine = nil
	}
	return errors.Join(closeErrors...)
}

func (c *Cell) prepareFailure(domain, kind string, cause error) *protocol.WireError {
	if closeErr := c.Close(); closeErr != nil {
		cause = errors.Join(cause, fmt.Errorf("preflight cleanup: %w", closeErr))
	}
	return protocol.NewError(domain, kind, cause)
}

func (c *Cell) instantiateOptions() []wacogo.InstantiateOption {
	return []wacogo.InstantiateOption{
		wacogo.WithInstanceImport(keyvalue.InterfaceName, c.kvHost.Core()),
		wacogo.WithInstanceImport(timers.InterfaceName, c.timerHost.Core()),
	}
}

type activateArgs struct {
	SessionID                string `json:"sessionId"`
	Key                      string `json:"key"`
	InitialValueHex          string `json:"initialValueHex"`
	CompletionValueHex       string `json:"completionValueHex"`
	DelayNS                  string `json:"delayNs"`
	BaselineIdempotencyKey   string `json:"baselineIdempotencyKey"`
	TimerIdempotencyKey      string `json:"timerIdempotencyKey"`
	CompletionIdempotencyKey string `json:"completionIdempotencyKey"`
	KVResource               uint64 `json:"kvResource"`
	TimerResource            uint64 `json:"timerResource"`
}

func (c *Cell) activate(raw json.RawMessage) (any, *protocol.WireError) {
	var args activateArgs
	if err := protocol.DecodeArgs(raw, &args); err != nil {
		return nil, protocol.NewError("protocol", "invalid-arguments", err)
	}
	initial, err := protocol.DecodeLowerHex(args.InitialValueHex)
	if err != nil {
		return nil, protocol.NewError("protocol", "invalid-initial-value", err)
	}
	completion, err := protocol.DecodeLowerHex(args.CompletionValueHex)
	if err != nil {
		return nil, protocol.NewError("protocol", "invalid-completion-value", err)
	}
	delay, err := protocol.ParseCanonicalU64(args.DelayNS)
	if err != nil {
		return nil, protocol.NewError("protocol", "invalid-delay", err)
	}
	namespace, timer, failure := c.ownedPair(args.KVResource, args.TimerResource)
	if failure != nil {
		return nil, failure
	}
	_, failure = c.callResult(
		"activate",
		wacogo.ValString(args.SessionID),
		wacogo.ValString(args.Key),
		valBytes(initial),
		valBytes(completion),
		wacogo.ValU64(delay),
		wacogo.ValString(args.BaselineIdempotencyKey),
		wacogo.ValString(args.TimerIdempotencyKey),
		wacogo.ValString(args.CompletionIdempotencyKey),
		namespace,
		timer,
	)
	return nil, failure
}

func (c *Cell) freeze(raw json.RawMessage) (any, *protocol.WireError) {
	if err := decodeEmpty(raw); err != nil {
		return nil, protocol.NewError("protocol", "invalid-arguments", err)
	}
	value, failure := c.callResult("freeze")
	if failure != nil {
		return nil, failure
	}
	state, err := stateFromVal(value)
	if err != nil {
		return nil, protocol.NewError("trap", "invalid-state-result", err)
	}
	return state, nil
}

type thawArgs struct {
	State         stateWire `json:"state"`
	KVResource    uint64    `json:"kvResource"`
	TimerResource uint64    `json:"timerResource"`
}

func (c *Cell) thaw(raw json.RawMessage) (any, *protocol.WireError) {
	var args thawArgs
	if err := protocol.DecodeArgs(raw, &args); err != nil {
		return nil, protocol.NewError("protocol", "invalid-arguments", err)
	}
	state, err := args.State.toVal()
	if err != nil {
		return nil, protocol.NewError("protocol", "invalid-state", err)
	}
	namespace, timer, failure := c.ownedPair(args.KVResource, args.TimerResource)
	if failure != nil {
		return nil, failure
	}
	_, failure = c.callResult("thaw", state, namespace, timer)
	return nil, failure
}

type restoreArgs struct {
	State               stateWire `json:"state"`
	RemainingDurationNS string    `json:"remainingDurationNs"`
	KVResource          uint64    `json:"kvResource"`
	TimerResource       uint64    `json:"timerResource"`
}

func (c *Cell) restore(raw json.RawMessage) (any, *protocol.WireError) {
	var args restoreArgs
	if err := protocol.DecodeArgs(raw, &args); err != nil {
		return nil, protocol.NewError("protocol", "invalid-arguments", err)
	}
	state, err := args.State.toVal()
	if err != nil {
		return nil, protocol.NewError("protocol", "invalid-state", err)
	}
	remaining, err := protocol.ParseCanonicalU64(args.RemainingDurationNS)
	if err != nil {
		return nil, protocol.NewError("protocol", "invalid-remaining-duration", err)
	}
	namespace, timer, failure := c.ownedPair(args.KVResource, args.TimerResource)
	if failure != nil {
		return nil, failure
	}
	_, failure = c.callResult("restore", state, wacogo.ValU64(remaining), namespace, timer)
	return nil, failure
}

type timerFiredArgs struct {
	OperationID string `json:"operationId"`
}

func (c *Cell) timerFired(raw json.RawMessage) (any, *protocol.WireError) {
	var args timerFiredArgs
	if err := protocol.DecodeArgs(raw, &args); err != nil {
		return nil, protocol.NewError("protocol", "invalid-arguments", err)
	}
	_, failure := c.callResult("timer-fired", wacogo.ValString(args.OperationID))
	return nil, failure
}

func (c *Cell) cancelPending(raw json.RawMessage) (any, *protocol.WireError) {
	if err := decodeEmpty(raw); err != nil {
		return nil, protocol.NewError("protocol", "invalid-arguments", err)
	}
	_, failure := c.callResult("cancel-pending")
	return nil, failure
}

func (c *Cell) status(raw json.RawMessage) (any, *protocol.WireError) {
	if err := decodeEmpty(raw); err != nil {
		return nil, protocol.NewError("protocol", "invalid-arguments", err)
	}
	function, failure := c.requiredExport("status")
	if failure != nil {
		return nil, failure
	}
	results, err := function.Call(c.ctx)
	if err != nil {
		return nil, protocol.NewError("trap", "guest-trap", err)
	}
	if len(results) != 1 {
		return nil, protocol.ErrorDetail(
			"trap",
			"invalid-result",
			fmt.Sprintf("status returned %d values, expected one", len(results)),
		)
	}
	option, ok := results[0].(*wacogo.ValOption)
	if !ok {
		return nil, protocol.ErrorDetail(
			"trap",
			"invalid-result",
			fmt.Sprintf("status returned %T, expected option", results[0]),
		)
	}
	if option.IsNone() {
		return nil, nil
	}
	state, err := stateFromVal(option.Val())
	if err != nil {
		return nil, protocol.NewError("trap", "invalid-state-result", err)
	}
	return state, nil
}

func (c *Cell) export(name string) *wacogo.ExportedFunc {
	if c.workload == nil {
		return nil
	}
	return c.workload.ExportedFunc(name)
}

func (c *Cell) requiredExport(name string) (*wacogo.ExportedFunc, *protocol.WireError) {
	function := c.export(name)
	if function == nil {
		return nil, protocol.ErrorDetail(
			"trap",
			"missing-export",
			fmt.Sprintf("workload export %q was not found", name),
		)
	}
	return function, nil
}

func (c *Cell) callResult(name string, args ...wacogo.Val) (wacogo.Val, *protocol.WireError) {
	function, failure := c.requiredExport(name)
	if failure != nil {
		return nil, failure
	}
	results, err := function.Call(c.ctx, args...)
	if err != nil {
		return nil, protocol.NewError("trap", "guest-trap", err)
	}
	if len(results) != 1 {
		return nil, protocol.ErrorDetail(
			"trap",
			"invalid-result",
			fmt.Sprintf("%s returned %d values, expected one", name, len(results)),
		)
	}
	result, ok := results[0].(*wacogo.ValResult)
	if !ok {
		return nil, protocol.ErrorDetail(
			"trap",
			"invalid-result",
			fmt.Sprintf("%s returned %T, expected result", name, results[0]),
		)
	}
	if result.IsOk() {
		return result.Ok(), nil
	}
	return nil, workloadFailure(result.Err())
}

func workloadFailure(value wacogo.Val) *protocol.WireError {
	outer, ok := value.(*wacogo.ValVariant)
	if !ok {
		return protocol.ErrorDetail(
			"trap",
			"invalid-workload-error",
			fmt.Sprintf("workload error has type %T, expected variant", value),
		)
	}
	unit := func(kind string) *protocol.WireError {
		if outer.Val() != nil {
			return protocol.ErrorDetail(
				"trap",
				"invalid-workload-error",
				fmt.Sprintf("workload error %s unexpectedly carried a payload", kind),
			)
		}
		return &protocol.WireError{Domain: "workload", Kind: kind}
	}
	switch outer.Discriminant() {
	case 0:
		return unit("already-active")
	case 1:
		return unit("invalid-state")
	case 2:
		return unit("wrong-timer")
	case 3:
		return unit("safe-point-unavailable")
	case 4:
		return nestedKVFailure(outer.Val())
	case 5:
		return nestedTimerFailure(outer.Val())
	default:
		return protocol.ErrorDetail(
			"trap",
			"invalid-workload-error",
			fmt.Sprintf("unknown workload error discriminant %d", outer.Discriminant()),
		)
	}
}

func nestedKVFailure(value wacogo.Val) *protocol.WireError {
	variant, ok := value.(*wacogo.ValVariant)
	if !ok {
		return protocol.ErrorDetail(
			"trap",
			"invalid-workload-error",
			fmt.Sprintf("kv workload error has type %T, expected variant", value),
		)
	}
	unit := func(kind string) *protocol.WireError {
		if variant.Val() != nil {
			return protocol.ErrorDetail("trap", "invalid-workload-error", "unit kv error carried a payload")
		}
		return &protocol.WireError{Domain: "workload", Kind: "kv." + kind}
	}
	switch variant.Discriminant() {
	case 0:
		return unit("denied")
	case 1:
		return unit("conflict")
	case 2:
		return unit("stale-binding")
	case 3:
		detail, ok := variant.Val().(wacogo.ValString)
		if !ok || detail == "" {
			return protocol.ErrorDetail(
				"trap",
				"invalid-workload-error",
				"kv.indeterminate requires a non-empty string payload",
			)
		}
		text := string(detail)
		return &protocol.WireError{Domain: "workload", Kind: "kv.indeterminate", Detail: &text}
	case 4:
		return unit("unavailable")
	default:
		return protocol.ErrorDetail(
			"trap",
			"invalid-workload-error",
			fmt.Sprintf("unknown kv error discriminant %d", variant.Discriminant()),
		)
	}
}

func nestedTimerFailure(value wacogo.Val) *protocol.WireError {
	variant, ok := value.(*wacogo.ValVariant)
	if !ok {
		return protocol.ErrorDetail(
			"trap",
			"invalid-workload-error",
			fmt.Sprintf("timer workload error has type %T, expected variant", value),
		)
	}
	if variant.Val() != nil {
		return protocol.ErrorDetail(
			"trap",
			"invalid-workload-error",
			"unit timer error carried a payload",
		)
	}
	kind := ""
	switch variant.Discriminant() {
	case 0:
		kind = "denied"
	case 1:
		kind = "stale-binding"
	case 2:
		kind = "not-pending"
	case 3:
		kind = "unavailable"
	default:
		return protocol.ErrorDetail(
			"trap",
			"invalid-workload-error",
			fmt.Sprintf("unknown timer error discriminant %d", variant.Discriminant()),
		)
	}
	return &protocol.WireError{Domain: "workload", Kind: "timer." + kind}
}

func (c *Cell) ownedPair(kvID, timerID uint64) (*wacogo.ValOwnHandle, *wacogo.ValOwnHandle, *protocol.WireError) {
	if len(c.resources) != 0 {
		return nil, nil, protocol.ErrorDetail(
			"protocol",
			"live-resources",
			fmt.Sprintf("cannot create a fresh pair with %d resources live", len(c.resources)),
		)
	}
	if kvID == 0 || timerID == 0 || kvID == timerID {
		return nil, nil, protocol.ErrorDetail(
			"protocol",
			"invalid-resource-id",
			"resource ids must be distinct positive integers",
		)
	}
	c.resources[resourceKey{kind: resourceKV, id: kvID}] = struct{}{}
	c.resources[resourceKey{kind: resourceTimer, id: timerID}] = struct{}{}
	namespace := &remoteNamespace{cell: c, id: kvID}
	timer := &remoteTimer{cell: c, id: timerID}
	namespaceRep := uint32(c.kvHost.RegisterResource(namespace))
	timerRep := uint32(c.timerHost.RegisterResource(timer))
	return wacogo.NewValOwnHandle(c.namespaceType, namespaceRep),
		wacogo.NewValOwnHandle(c.timerType, timerRep), nil
}

type remoteNamespace struct {
	cell *Cell
	id   uint64
}

func (n *remoteNamespace) Read(
	_ context.Context,
	key string,
) (keyvalue.ResultOptionVersionedValueKvError, error) {
	raw, semantic, err := n.cell.channel.HostCall(n.id, "kv.read", struct {
		Key string `json:"key"`
	}{Key: key})
	if err != nil {
		return nil, err
	}
	if semantic != nil {
		failure, err := kvError(semantic)
		if err != nil {
			return nil, err
		}
		return keyvalue.ResultOptionVersionedValueKvErrorErr{Value: failure}, nil
	}
	if isNull(raw) {
		return keyvalue.ResultOptionVersionedValueKvErrorOk{
			Value: keyvalue.NoneVersionedValue(),
		}, nil
	}
	var result struct {
		ValueHex string `json:"valueHex"`
		Version  string `json:"version"`
	}
	if err := protocol.DecodeStrict(raw, &result); err != nil {
		return nil, err
	}
	value, err := protocol.DecodeLowerHex(result.ValueHex)
	if err != nil {
		return nil, err
	}
	version, err := protocol.ParseCanonicalU64(result.Version)
	if err != nil {
		return nil, err
	}
	return keyvalue.ResultOptionVersionedValueKvErrorOk{
		Value: keyvalue.SomeVersionedValue(keyvalue.VersionedValue{Value: value, Version: version}),
	}, nil
}

func (n *remoteNamespace) ConditionalPut(
	_ context.Context,
	idempotencyKey string,
	key string,
	expected keyvalue.OptionU64,
	value []uint8,
) (keyvalue.ResultWriteResultKvError, error) {
	var expectedVersion any
	if expected.IsSome {
		expectedVersion = strconv.FormatUint(expected.Value, 10)
	}
	raw, semantic, err := n.cell.channel.HostCall(n.id, "kv.conditional-put", struct {
		IdempotencyKey string `json:"idempotencyKey"`
		Key            string `json:"key"`
		Expected       any    `json:"expectedVersion"`
		ValueHex       string `json:"valueHex"`
	}{
		IdempotencyKey: idempotencyKey,
		Key:            key,
		Expected:       expectedVersion,
		ValueHex:       protocol.EncodeHex(value),
	})
	if err != nil {
		return nil, err
	}
	if semantic != nil {
		failure, err := kvError(semantic)
		if err != nil {
			return nil, err
		}
		return keyvalue.ResultWriteResultKvErrorErr{Value: failure}, nil
	}
	var result struct {
		OperationID string `json:"operationId"`
		Version     string `json:"version"`
		Applied     bool   `json:"applied"`
	}
	if err := protocol.DecodeStrict(raw, &result); err != nil {
		return nil, err
	}
	version, err := protocol.ParseCanonicalU64(result.Version)
	if err != nil {
		return nil, err
	}
	return keyvalue.ResultWriteResultKvErrorOk{Value: keyvalue.WriteResult{
		OperationID: result.OperationID,
		Version:     version,
		Applied:     result.Applied,
	}}, nil
}

func (n *remoteNamespace) Drop(context.Context) error {
	return n.cell.dispose(resourceKV, n.id)
}

type remoteTimer struct {
	cell *Cell
	id   uint64
}

func (t *remoteTimer) Arm(
	_ context.Context,
	idempotencyKey string,
	durationNS uint64,
) (timers.ResultArmResultTimerError, error) {
	raw, semantic, err := t.cell.channel.HostCall(t.id, "timer.arm", struct {
		IdempotencyKey string `json:"idempotencyKey"`
		DurationNS     string `json:"durationNs"`
	}{IdempotencyKey: idempotencyKey, DurationNS: strconv.FormatUint(durationNS, 10)})
	if err != nil {
		return nil, err
	}
	if semantic != nil {
		failure, err := timerError(semantic)
		if err != nil {
			return nil, err
		}
		return timers.ResultArmResultTimerErrorErr{Value: failure}, nil
	}
	var result struct {
		OperationID string `json:"operationId"`
	}
	if err := protocol.DecodeStrict(raw, &result); err != nil {
		return nil, err
	}
	return timers.ResultArmResultTimerErrorOk{
		Value: timers.ArmResult{OperationID: result.OperationID},
	}, nil
}

func (t *remoteTimer) Cancel(
	_ context.Context,
	operationID string,
) (timers.Result_TimerError, error) {
	raw, semantic, err := t.cell.channel.HostCall(t.id, "timer.cancel", struct {
		OperationID string `json:"operationId"`
	}{OperationID: operationID})
	if err != nil {
		return nil, err
	}
	if semantic != nil {
		failure, err := timerError(semantic)
		if err != nil {
			return nil, err
		}
		return timers.Result_TimerErrorErr{Value: failure}, nil
	}
	if !isNull(raw) {
		return nil, errors.New("timer.cancel host result must be null")
	}
	return timers.Result_TimerErrorOk{}, nil
}

func (t *remoteTimer) Drop(context.Context) error {
	return t.cell.dispose(resourceTimer, t.id)
}

func (c *Cell) dispose(kind resourceKind, id uint64) error {
	key := resourceKey{kind: kind, id: id}
	if _, ok := c.resources[key]; !ok {
		return fmt.Errorf("resource %s/%d was already disposed or never registered", kind, id)
	}
	raw, semantic, err := c.channel.HostCall(id, "resource.dispose", struct {
		Kind resourceKind `json:"kind"`
	}{Kind: kind})
	if err != nil {
		return err
	}
	if semantic != nil {
		return fmt.Errorf("resource dispose failed: %w", semantic)
	}
	if !isNull(raw) {
		return errors.New("resource.dispose host result must be null")
	}
	delete(c.resources, key)
	return nil
}

func kvError(wireError *protocol.WireError) (keyvalue.KvError, error) {
	if wireError.Domain != "kv" {
		return nil, fmt.Errorf("kv hostcall returned non-kv error %s", wireError)
	}
	if wireError.Kind != "indeterminate" && wireError.Detail != nil {
		return nil, fmt.Errorf("kv error %s unexpectedly carried detail", wireError.Kind)
	}
	switch wireError.Kind {
	case "denied":
		return keyvalue.KvErrorDenied{}, nil
	case "conflict":
		return keyvalue.KvErrorConflict{}, nil
	case "stale-binding":
		return keyvalue.KvErrorStaleBinding{}, nil
	case "indeterminate":
		if wireError.Detail == nil || *wireError.Detail == "" {
			return nil, errors.New("kv indeterminate error requires a non-empty operation id")
		}
		return keyvalue.KvErrorIndeterminate{Value: *wireError.Detail}, nil
	case "unavailable":
		return keyvalue.KvErrorUnavailable{}, nil
	default:
		return nil, fmt.Errorf("unknown kv error kind %q", wireError.Kind)
	}
}

func timerError(wireError *protocol.WireError) (timers.TimerError, error) {
	if wireError.Domain != "timer" || wireError.Detail != nil {
		return nil, fmt.Errorf("invalid timer hostcall error %s", wireError)
	}
	switch wireError.Kind {
	case "denied":
		return timers.TimerErrorDenied{}, nil
	case "stale-binding":
		return timers.TimerErrorStaleBinding{}, nil
	case "not-pending":
		return timers.TimerErrorNotPending{}, nil
	case "unavailable":
		return timers.TimerErrorUnavailable{}, nil
	default:
		return nil, fmt.Errorf("unknown timer error kind %q", wireError.Kind)
	}
}

type stateWire struct {
	SessionID                string `json:"sessionId"`
	Key                      string `json:"key"`
	ExpectedVersion          string `json:"expectedVersion"`
	CompletionValueHex       string `json:"completionValueHex"`
	TimerOperationID         string `json:"timerOperationId"`
	TimerIdempotencyKey      string `json:"timerIdempotencyKey"`
	CompletionIdempotencyKey string `json:"completionIdempotencyKey"`
	Phase                    string `json:"phase"`
}

func (s stateWire) toVal() (*wacogo.ValRecord, error) {
	expectedVersion, err := protocol.ParseCanonicalU64(s.ExpectedVersion)
	if err != nil {
		return nil, err
	}
	completionValue, err := protocol.DecodeLowerHex(s.CompletionValueHex)
	if err != nil {
		return nil, err
	}
	phase, err := phaseDiscriminant(s.Phase)
	if err != nil {
		return nil, err
	}
	return wacogo.NewValRecord(
		wacogo.Field{Name: "session-id", Val: wacogo.ValString(s.SessionID)},
		wacogo.Field{Name: "key", Val: wacogo.ValString(s.Key)},
		wacogo.Field{Name: "expected-version", Val: wacogo.ValU64(expectedVersion)},
		wacogo.Field{Name: "completion-value", Val: valBytes(completionValue)},
		wacogo.Field{Name: "timer-operation-id", Val: wacogo.ValString(s.TimerOperationID)},
		wacogo.Field{Name: "timer-idempotency-key", Val: wacogo.ValString(s.TimerIdempotencyKey)},
		wacogo.Field{Name: "completion-idempotency-key", Val: wacogo.ValString(s.CompletionIdempotencyKey)},
		wacogo.Field{Name: "phase", Val: wacogo.NewValEnum(phase)},
	), nil
}

func stateFromVal(value wacogo.Val) (stateWire, error) {
	record, ok := value.(*wacogo.ValRecord)
	if !ok {
		return stateWire{}, fmt.Errorf("component state has type %T, expected record", value)
	}
	expectedFields := []string{
		"session-id",
		"key",
		"expected-version",
		"completion-value",
		"timer-operation-id",
		"timer-idempotency-key",
		"completion-idempotency-key",
		"phase",
	}
	fields := record.Fields()
	if len(fields) != len(expectedFields) {
		return stateWire{}, fmt.Errorf("component state has %d fields, expected %d", len(fields), len(expectedFields))
	}
	for index, expected := range expectedFields {
		if fields[index].Name != expected {
			return stateWire{}, fmt.Errorf(
				"component state field %d is %q, expected %q",
				index,
				fields[index].Name,
				expected,
			)
		}
	}
	sessionID, ok := fields[0].Val.(wacogo.ValString)
	if !ok {
		return stateWire{}, fmt.Errorf("session-id has type %T", fields[0].Val)
	}
	key, ok := fields[1].Val.(wacogo.ValString)
	if !ok {
		return stateWire{}, fmt.Errorf("key has type %T", fields[1].Val)
	}
	expectedVersion, ok := fields[2].Val.(wacogo.ValU64)
	if !ok {
		return stateWire{}, fmt.Errorf("expected-version has type %T", fields[2].Val)
	}
	completionValue, err := bytesFromVal(fields[3].Val)
	if err != nil {
		return stateWire{}, err
	}
	timerOperationID, ok := fields[4].Val.(wacogo.ValString)
	if !ok {
		return stateWire{}, fmt.Errorf("timer-operation-id has type %T", fields[4].Val)
	}
	timerIdempotencyKey, ok := fields[5].Val.(wacogo.ValString)
	if !ok {
		return stateWire{}, fmt.Errorf("timer-idempotency-key has type %T", fields[5].Val)
	}
	completionIdempotencyKey, ok := fields[6].Val.(wacogo.ValString)
	if !ok {
		return stateWire{}, fmt.Errorf("completion-idempotency-key has type %T", fields[6].Val)
	}
	phaseValue, ok := fields[7].Val.(*wacogo.ValEnum)
	if !ok {
		return stateWire{}, fmt.Errorf("phase has type %T", fields[7].Val)
	}
	phase, err := phaseName(phaseValue.Discriminant())
	if err != nil {
		return stateWire{}, err
	}
	return stateWire{
		SessionID:                string(sessionID),
		Key:                      string(key),
		ExpectedVersion:          strconv.FormatUint(uint64(expectedVersion), 10),
		CompletionValueHex:       protocol.EncodeHex(completionValue),
		TimerOperationID:         string(timerOperationID),
		TimerIdempotencyKey:      string(timerIdempotencyKey),
		CompletionIdempotencyKey: string(completionIdempotencyKey),
		Phase:                    phase,
	}, nil
}

func valBytes(value []byte) *wacogo.ValList {
	elements := make([]wacogo.ValU8, len(value))
	for index, element := range value {
		elements[index] = wacogo.ValU8(element)
	}
	return wacogo.NewValListOf(elements...)
}

func bytesFromVal(value wacogo.Val) ([]byte, error) {
	list, ok := value.(*wacogo.ValList)
	if !ok {
		return nil, fmt.Errorf("completion-value has type %T, expected list", value)
	}
	result := make([]byte, list.Len())
	for index := range result {
		element, ok := list.Get(index).(wacogo.ValU8)
		if !ok {
			return nil, fmt.Errorf("completion-value element %d has type %T", index, list.Get(index))
		}
		result[index] = byte(element)
	}
	return result, nil
}

func phaseDiscriminant(name string) (uint32, error) {
	switch name {
	case "armed":
		return 0, nil
	case "frozen":
		return 1, nil
	case "completed":
		return 2, nil
	case "cancelled":
		return 3, nil
	default:
		return 0, fmt.Errorf("unknown workload phase %q", name)
	}
}

func phaseName(discriminant uint32) (string, error) {
	switch discriminant {
	case 0:
		return "armed", nil
	case 1:
		return "frozen", nil
	case 2:
		return "completed", nil
	case 3:
		return "cancelled", nil
	default:
		return "", fmt.Errorf("unknown workload phase discriminant %d", discriminant)
	}
}

func verifySurface(component *wacogo.Component) error {
	expectedImports := map[string]wacogo.Sort{
		keyvalue.InterfaceName: wacogo.SortInstance,
		timers.InterfaceName:   wacogo.SortInstance,
	}
	if len(component.Imports()) != len(expectedImports) {
		return fmt.Errorf("component has %d imports, expected %d", len(component.Imports()), len(expectedImports))
	}
	for _, item := range component.Imports() {
		kind, ok := expectedImports[item.Name]
		if !ok || item.Kind != kind {
			return fmt.Errorf("unexpected component import %q with kind %v", item.Name, item.Kind)
		}
	}
	if len(component.Exports()) != 1 {
		return fmt.Errorf("component has %d exports, expected one", len(component.Exports()))
	}
	export := component.Exports()[0]
	if export.Name != workloadName || export.Kind != wacogo.SortInstance {
		return fmt.Errorf("unexpected component export %q with kind %v", export.Name, export.Kind)
	}
	return nil
}

func verifyAcceptedComponent(component []byte) error {
	digest := sha256.Sum256(component)
	observedSHA256 := fmt.Sprintf("%x", digest)
	if len(component) != acceptedComponentSize || observedSHA256 != acceptedComponentSHA256 {
		return fmt.Errorf(
			"unsupported Component identity: size=%d sha256=%s, expected size=%d sha256=%s",
			len(component),
			observedSHA256,
			acceptedComponentSize,
			acceptedComponentSHA256,
		)
	}
	return nil
}

func verifyLiveWorkloadSurface(workload *wacogo.ComponentInstance) error {
	if workload == nil {
		return errors.New("workload instance was nil")
	}
	for _, name := range requiredWorkloadExports {
		if workload.ExportedFunc(name) == nil {
			return fmt.Errorf("workload export %q was not found", name)
		}
	}
	return nil
}

func decodeEmpty(raw json.RawMessage) error {
	var args struct{}
	return protocol.DecodeArgs(raw, &args)
}

func isNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

func appendIfError(existing []error, label string, err error) []error {
	if err != nil {
		return append(existing, fmt.Errorf("close %s: %w", label, err))
	}
	return existing
}
