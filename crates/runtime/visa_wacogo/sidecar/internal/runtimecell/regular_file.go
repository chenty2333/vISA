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
	regularfile "visa.local/wacogo-runtime/generated/visa/file-continuity/regularfile"
	"visa.local/wacogo-runtime/internal/protocol"
)

const (
	regularFileWorkloadName            = "visa:file-continuity/workload@0.1.0"
	regularFileAcceptedComponentSize   = 215370
	regularFileAcceptedComponentSHA256 = "c7fd1ec2a2f0fa7c33c7587bbbf686c1cc04a94937c3eb25707222973af69541"
)

var regularFileRequiredExports = [...]string{
	"activate",
	"read",
	"write",
	"append",
	"truncate",
	"rename",
	"sync",
	"acquire-lock",
	"release-lock",
	"freeze",
	"thaw",
	"restore",
	"status",
}

type regularFileHost struct{}

type regularFileCell struct {
	ctx          context.Context
	channel      *protocol.Channel
	engine       *wacogo.Engine
	component    *wacogo.Component
	factory      *regularfile.Factory
	fileHost     *host.ComponentInstance
	fileType     *wacogo.TypeResource
	guest        *wacogo.ComponentInstance
	workload     *wacogo.ComponentInstance
	resources    map[uint64]struct{}
	instantiated bool
	closed       bool
}

func prepareRegularFile(
	ctx context.Context,
	channel *protocol.Channel,
	componentBytes []byte,
) (*regularFileCell, *protocol.WireError) {
	if err := verifyRegularFileComponentIdentity(componentBytes); err != nil {
		return nil, protocol.NewError("preflight", "unsupported-runtime-feature", err)
	}
	cell := &regularFileCell{
		ctx:       ctx,
		channel:   channel,
		resources: make(map[uint64]struct{}),
	}
	cell.engine = wacogo.NewEngine(ctx)

	component, err := cell.engine.LoadComponent(ctx, bytes.NewReader(componentBytes))
	if err != nil {
		return nil, cell.prepareFailure("preflight", "invalid-component", err)
	}
	cell.component = component
	if err := verifyRegularFileSurface(component); err != nil {
		return nil, cell.prepareFailure("preflight", "invalid-surface", err)
	}

	cell.factory, err = regularfile.NewFactory(ctx, cell.engine)
	if err != nil {
		return nil, cell.prepareFailure("link", "regular-file-factory", err)
	}
	cell.fileHost, err = cell.factory.NewInstance(ctx, regularFileHost{}, nil)
	if err != nil {
		return nil, cell.prepareFailure("link", "regular-file-instance", err)
	}
	var ok bool
	cell.fileType, ok = cell.fileHost.Core().ExportedType("file-binding").(*wacogo.TypeResource)
	if !ok {
		return nil, cell.prepareFailure(
			"link",
			"file-binding-resource-type",
			fmt.Errorf("file-binding export has type %T", cell.fileHost.Core().ExportedType("file-binding")),
		)
	}
	if err := component.CheckInstantiation(cell.instantiateOptions()...); err != nil {
		return nil, cell.prepareFailure("link", "check-instantiation", err)
	}
	return cell, nil
}

func (c *regularFileCell) Instantiate() *protocol.WireError {
	if c.closed || c.instantiated {
		return protocol.ErrorDetail("protocol", "invalid-state", "instantiate requires a prepared regular-file cell")
	}
	guest, err := c.component.Instantiate(c.ctx, c.instantiateOptions()...)
	if err != nil {
		return protocol.NewError("instantiation", "component-instantiate", err)
	}
	workload := guest.ExportedInstance(regularFileWorkloadName)
	if workload == nil {
		_ = guest.Close(c.ctx)
		return protocol.ErrorDetail(
			"instantiation",
			"missing-workload-export",
			"instantiated regular-file component did not export the typed workload instance",
		)
	}
	if err := verifyRegularFileLiveSurface(workload); err != nil {
		_ = guest.Close(c.ctx)
		return protocol.NewError("instantiation", "invalid-workload-surface", err)
	}
	c.guest = guest
	c.workload = workload
	c.instantiated = true
	return nil
}

func (c *regularFileCell) Handle(op string, raw json.RawMessage) (any, *protocol.WireError, bool) {
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
				fmt.Sprintf("shutdown retained %d regular-file resources", c.LiveResources()),
			), true
		}
		return nil, nil, true
	}
	if !c.instantiated || c.closed {
		return nil, protocol.ErrorDetail(
			"protocol",
			"invalid-state",
			"regular-file command requires a live component instance",
		), true
	}

	var result any
	var failure *protocol.WireError
	switch op {
	case "activate":
		result, failure = c.activate(raw)
	case "read":
		result, failure = c.read(raw)
	case "write":
		result, failure = c.write(raw)
	case "append":
		result, failure = c.append(raw)
	case "truncate":
		result, failure = c.truncate(raw)
	case "rename":
		result, failure = c.rename(raw)
	case "sync":
		result, failure = c.sync(raw)
	case "acquire-lock":
		result, failure = c.acquireLock(raw)
	case "release-lock":
		result, failure = c.releaseLock(raw)
	case "freeze":
		result, failure = c.freeze(raw)
	case "thaw":
		result, failure = c.thaw(raw)
	case "restore":
		result, failure = c.restore(raw)
	case "status":
		result, failure = c.status(raw)
	default:
		return nil, protocol.ErrorDetail(
			"protocol",
			"unknown-command",
			fmt.Sprintf("unknown regular-file command operation %q", op),
		), true
	}
	return result, failure, failure != nil && failure.Domain != "workload"
}

func (c *regularFileCell) LiveResources() uint64 {
	return uint64(len(c.resources))
}

func (c *regularFileCell) Close() error {
	if c.closed {
		return nil
	}
	c.closed = true
	var closeErrors []error
	if c.guest != nil {
		closeErrors = appendIfError(closeErrors, "regular-file guest", c.guest.Close(c.ctx))
		c.guest = nil
		c.workload = nil
	}
	if c.fileHost != nil {
		closeErrors = appendIfError(closeErrors, "regular-file host instance", c.fileHost.Close(c.ctx))
		c.fileHost = nil
	}
	if c.factory != nil {
		closeErrors = appendIfError(closeErrors, "regular-file factory", c.factory.Close(c.ctx))
		c.factory = nil
	}
	if c.engine != nil {
		closeErrors = appendIfError(closeErrors, "regular-file engine", c.engine.Close(c.ctx))
		c.engine = nil
	}
	return errors.Join(closeErrors...)
}

func (c *regularFileCell) prepareFailure(domain, kind string, cause error) *protocol.WireError {
	if closeErr := c.Close(); closeErr != nil {
		cause = errors.Join(cause, fmt.Errorf("regular-file preflight cleanup: %w", closeErr))
	}
	return protocol.NewError(domain, kind, cause)
}

func (c *regularFileCell) instantiateOptions() []wacogo.InstantiateOption {
	return []wacogo.InstantiateOption{
		wacogo.WithInstanceImport(regularfile.InterfaceName, c.fileHost.Core()),
	}
}

type regularFileActivateArgs struct {
	SessionID    string               `json:"sessionId"`
	State        regularFileStateWire `json:"state"`
	FileResource uint64               `json:"fileResource"`
}

func (c *regularFileCell) activate(raw json.RawMessage) (any, *protocol.WireError) {
	var args regularFileActivateArgs
	if err := protocol.DecodeArgs(raw, &args); err != nil {
		return nil, protocol.NewError("protocol", "invalid-arguments", err)
	}
	state, err := args.State.toVal()
	if err != nil {
		return nil, protocol.NewError("protocol", "invalid-state", err)
	}
	file, failure := c.ownedFile(args.FileResource)
	if failure != nil {
		return nil, failure
	}
	_, failure = c.callResult(
		"activate",
		wacogo.ValString(args.SessionID),
		state,
		file,
	)
	return nil, failure
}

type regularFileReadArgs struct {
	MaxBytes uint32 `json:"maxBytes"`
}

func (c *regularFileCell) read(raw json.RawMessage) (any, *protocol.WireError) {
	var args regularFileReadArgs
	if err := protocol.DecodeArgs(raw, &args); err != nil {
		return nil, protocol.NewError("protocol", "invalid-arguments", err)
	}
	value, failure := c.callResult("read", wacogo.ValU32(args.MaxBytes))
	if failure != nil {
		return nil, failure
	}
	result, err := regularFileReadFromVal(value)
	if err != nil {
		return nil, protocol.NewError("trap", "invalid-read-result", err)
	}
	return result, nil
}

type regularFileBytesArgs struct {
	IdempotencyKey string `json:"idempotencyKey"`
	BytesHex       string `json:"bytesHex"`
	Durability     string `json:"durability"`
}

func (c *regularFileCell) write(raw json.RawMessage) (any, *protocol.WireError) {
	var args regularFileBytesArgs
	if err := protocol.DecodeArgs(raw, &args); err != nil {
		return nil, protocol.NewError("protocol", "invalid-arguments", err)
	}
	return c.callBytesOperation("write", args)
}

func (c *regularFileCell) append(raw json.RawMessage) (any, *protocol.WireError) {
	var args regularFileBytesArgs
	if err := protocol.DecodeArgs(raw, &args); err != nil {
		return nil, protocol.NewError("protocol", "invalid-arguments", err)
	}
	return c.callBytesOperation("append", args)
}

func (c *regularFileCell) callBytesOperation(
	name string,
	args regularFileBytesArgs,
) (any, *protocol.WireError) {
	data, err := protocol.DecodeLowerHex(args.BytesHex)
	if err != nil {
		return nil, protocol.NewError("protocol", "invalid-bytes", err)
	}
	durability, err := regularFileDurabilityDiscriminant(args.Durability)
	if err != nil {
		return nil, protocol.NewError("protocol", "invalid-durability", err)
	}
	return c.callObservation(
		name,
		wacogo.ValString(args.IdempotencyKey),
		valBytes(data),
		wacogo.NewValEnum(durability),
	)
}

type regularFileTruncateArgs struct {
	IdempotencyKey string `json:"idempotencyKey"`
	Size           string `json:"size"`
	Durability     string `json:"durability"`
}

func (c *regularFileCell) truncate(raw json.RawMessage) (any, *protocol.WireError) {
	var args regularFileTruncateArgs
	if err := protocol.DecodeArgs(raw, &args); err != nil {
		return nil, protocol.NewError("protocol", "invalid-arguments", err)
	}
	size, err := protocol.ParseCanonicalU64(args.Size)
	if err != nil {
		return nil, protocol.NewError("protocol", "invalid-size", err)
	}
	durability, err := regularFileDurabilityDiscriminant(args.Durability)
	if err != nil {
		return nil, protocol.NewError("protocol", "invalid-durability", err)
	}
	return c.callObservation(
		"truncate",
		wacogo.ValString(args.IdempotencyKey),
		wacogo.ValU64(size),
		wacogo.NewValEnum(durability),
	)
}

type regularFileRenameArgs struct {
	IdempotencyKey string `json:"idempotencyKey"`
	RelativePath   string `json:"relativePath"`
}

func (c *regularFileCell) rename(raw json.RawMessage) (any, *protocol.WireError) {
	var args regularFileRenameArgs
	if err := protocol.DecodeArgs(raw, &args); err != nil {
		return nil, protocol.NewError("protocol", "invalid-arguments", err)
	}
	return c.callObservation(
		"rename",
		wacogo.ValString(args.IdempotencyKey),
		wacogo.ValString(args.RelativePath),
	)
}

type regularFileSyncArgs struct {
	IdempotencyKey string `json:"idempotencyKey"`
	Durability     string `json:"durability"`
}

func (c *regularFileCell) sync(raw json.RawMessage) (any, *protocol.WireError) {
	var args regularFileSyncArgs
	if err := protocol.DecodeArgs(raw, &args); err != nil {
		return nil, protocol.NewError("protocol", "invalid-arguments", err)
	}
	durability, err := regularFileDurabilityDiscriminant(args.Durability)
	if err != nil {
		return nil, protocol.NewError("protocol", "invalid-durability", err)
	}
	return c.callObservation(
		"sync",
		wacogo.ValString(args.IdempotencyKey),
		wacogo.NewValEnum(durability),
	)
}

type regularFileIdempotencyArgs struct {
	IdempotencyKey string `json:"idempotencyKey"`
}

func (c *regularFileCell) acquireLock(raw json.RawMessage) (any, *protocol.WireError) {
	var args regularFileIdempotencyArgs
	if err := protocol.DecodeArgs(raw, &args); err != nil {
		return nil, protocol.NewError("protocol", "invalid-arguments", err)
	}
	return c.callObservation("acquire-lock", wacogo.ValString(args.IdempotencyKey))
}

func (c *regularFileCell) releaseLock(raw json.RawMessage) (any, *protocol.WireError) {
	var args regularFileIdempotencyArgs
	if err := protocol.DecodeArgs(raw, &args); err != nil {
		return nil, protocol.NewError("protocol", "invalid-arguments", err)
	}
	return c.callObservation("release-lock", wacogo.ValString(args.IdempotencyKey))
}

func (c *regularFileCell) freeze(raw json.RawMessage) (any, *protocol.WireError) {
	if err := decodeEmpty(raw); err != nil {
		return nil, protocol.NewError("protocol", "invalid-arguments", err)
	}
	value, failure := c.callResult("freeze")
	if failure != nil {
		return nil, failure
	}
	state, err := regularFileStateFromVal(value)
	if err != nil {
		return nil, protocol.NewError("trap", "invalid-state-result", err)
	}
	return state, nil
}

type regularFileResumeArgs struct {
	State        regularFileStateWire `json:"state"`
	FileResource uint64               `json:"fileResource"`
}

func (c *regularFileCell) thaw(raw json.RawMessage) (any, *protocol.WireError) {
	return c.resume("thaw", raw)
}

func (c *regularFileCell) restore(raw json.RawMessage) (any, *protocol.WireError) {
	return c.resume("restore", raw)
}

func (c *regularFileCell) resume(name string, raw json.RawMessage) (any, *protocol.WireError) {
	var args regularFileResumeArgs
	if err := protocol.DecodeArgs(raw, &args); err != nil {
		return nil, protocol.NewError("protocol", "invalid-arguments", err)
	}
	state, err := args.State.toVal()
	if err != nil {
		return nil, protocol.NewError("protocol", "invalid-state", err)
	}
	file, failure := c.ownedFile(args.FileResource)
	if failure != nil {
		return nil, failure
	}
	_, failure = c.callResult(name, state, file)
	return nil, failure
}

func (c *regularFileCell) status(raw json.RawMessage) (any, *protocol.WireError) {
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
			fmt.Sprintf("regular-file status returned %d values, expected one", len(results)),
		)
	}
	option, ok := results[0].(*wacogo.ValOption)
	if !ok {
		return nil, protocol.ErrorDetail(
			"trap",
			"invalid-result",
			fmt.Sprintf("regular-file status returned %T, expected option", results[0]),
		)
	}
	if option.IsNone() {
		return nil, nil
	}
	state, err := regularFileStateFromVal(option.Val())
	if err != nil {
		return nil, protocol.NewError("trap", "invalid-state-result", err)
	}
	return state, nil
}

func (c *regularFileCell) callObservation(
	name string,
	args ...wacogo.Val,
) (any, *protocol.WireError) {
	value, failure := c.callResult(name, args...)
	if failure != nil {
		return nil, failure
	}
	observation, err := regularFileObservationFromVal(value)
	if err != nil {
		return nil, protocol.NewError("trap", "invalid-observation-result", err)
	}
	return observation, nil
}

func (c *regularFileCell) requiredExport(name string) (*wacogo.ExportedFunc, *protocol.WireError) {
	if c.workload == nil {
		return nil, protocol.ErrorDetail("trap", "missing-workload", "regular-file workload is unavailable")
	}
	function := c.workload.ExportedFunc(name)
	if function == nil {
		return nil, protocol.ErrorDetail(
			"trap",
			"missing-export",
			fmt.Sprintf("regular-file workload export %q was not found", name),
		)
	}
	return function, nil
}

func (c *regularFileCell) callResult(name string, args ...wacogo.Val) (wacogo.Val, *protocol.WireError) {
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
			fmt.Sprintf("regular-file %s returned %d values, expected one", name, len(results)),
		)
	}
	result, ok := results[0].(*wacogo.ValResult)
	if !ok {
		return nil, protocol.ErrorDetail(
			"trap",
			"invalid-result",
			fmt.Sprintf("regular-file %s returned %T, expected result", name, results[0]),
		)
	}
	if result.IsOk() {
		return result.Ok(), nil
	}
	return nil, regularFileWorkloadFailure(result.Err())
}

func regularFileWorkloadFailure(value wacogo.Val) *protocol.WireError {
	outer, ok := value.(*wacogo.ValVariant)
	if !ok {
		return protocol.ErrorDetail(
			"trap",
			"invalid-workload-error",
			fmt.Sprintf("regular-file workload error has type %T, expected variant", value),
		)
	}
	unit := func(kind string) *protocol.WireError {
		if outer.Val() != nil {
			return protocol.ErrorDetail(
				"trap",
				"invalid-workload-error",
				fmt.Sprintf("regular-file workload error %s unexpectedly carried a payload", kind),
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
		return unit("safe-point-unavailable")
	case 3:
		return nestedRegularFileFailure(outer.Val())
	default:
		return protocol.ErrorDetail(
			"trap",
			"invalid-workload-error",
			fmt.Sprintf("unknown regular-file workload error discriminant %d", outer.Discriminant()),
		)
	}
}

func nestedRegularFileFailure(value wacogo.Val) *protocol.WireError {
	variant, ok := value.(*wacogo.ValVariant)
	if !ok {
		return protocol.ErrorDetail(
			"trap",
			"invalid-workload-error",
			fmt.Sprintf("file workload error has type %T, expected variant", value),
		)
	}
	unit := func(kind string) *protocol.WireError {
		if variant.Val() != nil {
			return protocol.ErrorDetail("trap", "invalid-workload-error", "unit file error carried a payload")
		}
		return &protocol.WireError{Domain: "workload", Kind: "file." + kind}
	}
	switch variant.Discriminant() {
	case 0:
		return unit("denied")
	case 1:
		return unit("conflict")
	case 2:
		return unit("stale-binding")
	case 3:
		return unit("unsupported")
	case 4:
		detail, ok := variant.Val().(wacogo.ValString)
		if !ok || detail == "" {
			return protocol.ErrorDetail(
				"trap",
				"invalid-workload-error",
				"file.indeterminate requires a non-empty string payload",
			)
		}
		text := string(detail)
		return &protocol.WireError{Domain: "workload", Kind: "file.indeterminate", Detail: &text}
	case 5:
		return unit("unavailable")
	default:
		return protocol.ErrorDetail(
			"trap",
			"invalid-workload-error",
			fmt.Sprintf("unknown file error discriminant %d", variant.Discriminant()),
		)
	}
}

func (c *regularFileCell) ownedFile(id uint64) (*wacogo.ValOwnHandle, *protocol.WireError) {
	if len(c.resources) != 0 {
		return nil, protocol.ErrorDetail(
			"protocol",
			"live-resources",
			fmt.Sprintf("cannot create a fresh file binding with %d resources live", len(c.resources)),
		)
	}
	if id == 0 {
		return nil, protocol.ErrorDetail(
			"protocol",
			"invalid-resource-id",
			"file resource id must be a positive integer",
		)
	}
	c.resources[id] = struct{}{}
	remote := &remoteRegularFile{cell: c, id: id}
	representation := uint32(c.fileHost.RegisterResource(remote))
	return wacogo.NewValOwnHandle(c.fileType, representation), nil
}

type remoteRegularFile struct {
	cell *regularFileCell
	id   uint64
}

func (f *remoteRegularFile) Read(
	_ context.Context,
	maxBytes uint32,
) (regularfile.ResultReadResultFileError, error) {
	raw, semantic, err := f.cell.channel.HostCall(f.id, "file.read", struct {
		MaxBytes uint32 `json:"maxBytes"`
	}{MaxBytes: maxBytes})
	if err != nil {
		return nil, err
	}
	if semantic != nil {
		failure, err := regularFileError(semantic)
		if err != nil {
			return nil, err
		}
		return regularfile.ResultReadResultFileErrorErr{Value: failure}, nil
	}
	var wire regularFileReadWire
	if err := protocol.DecodeStrict(raw, &wire); err != nil {
		return nil, fmt.Errorf("decode file.read result: %w", err)
	}
	value, err := wire.generated()
	if err != nil {
		return nil, err
	}
	return regularfile.ResultReadResultFileErrorOk{Value: value}, nil
}

func (f *remoteRegularFile) Write(
	_ context.Context,
	idempotencyKey string,
	data []uint8,
	durability regularfile.Durability,
) (regularfile.ResultFileObservationFileError, error) {
	return f.mutate("file.write", idempotencyKey, struct {
		IdempotencyKey string `json:"idempotencyKey"`
		BytesHex       string `json:"bytesHex"`
		Durability     string `json:"durability"`
	}{idempotencyKey, protocol.EncodeHex(data), durability.String()})
}

func (f *remoteRegularFile) Append(
	_ context.Context,
	idempotencyKey string,
	data []uint8,
	durability regularfile.Durability,
) (regularfile.ResultFileObservationFileError, error) {
	return f.mutate("file.append", idempotencyKey, struct {
		IdempotencyKey string `json:"idempotencyKey"`
		BytesHex       string `json:"bytesHex"`
		Durability     string `json:"durability"`
	}{idempotencyKey, protocol.EncodeHex(data), durability.String()})
}

func (f *remoteRegularFile) Truncate(
	_ context.Context,
	idempotencyKey string,
	size uint64,
	durability regularfile.Durability,
) (regularfile.ResultFileObservationFileError, error) {
	return f.mutate("file.truncate", idempotencyKey, struct {
		IdempotencyKey string `json:"idempotencyKey"`
		Size           string `json:"size"`
		Durability     string `json:"durability"`
	}{idempotencyKey, strconv.FormatUint(size, 10), durability.String()})
}

func (f *remoteRegularFile) Rename(
	_ context.Context,
	idempotencyKey string,
	relativePath string,
) (regularfile.ResultFileObservationFileError, error) {
	return f.mutate("file.rename", idempotencyKey, struct {
		IdempotencyKey string `json:"idempotencyKey"`
		RelativePath   string `json:"relativePath"`
	}{idempotencyKey, relativePath})
}

func (f *remoteRegularFile) Sync(
	_ context.Context,
	idempotencyKey string,
	durability regularfile.Durability,
) (regularfile.ResultFileObservationFileError, error) {
	return f.mutate("file.sync", idempotencyKey, struct {
		IdempotencyKey string `json:"idempotencyKey"`
		Durability     string `json:"durability"`
	}{idempotencyKey, durability.String()})
}

func (f *remoteRegularFile) AcquireLock(
	_ context.Context,
	idempotencyKey string,
) (regularfile.ResultFileObservationFileError, error) {
	return f.mutate("file.acquire-lock", idempotencyKey, struct {
		IdempotencyKey string `json:"idempotencyKey"`
	}{idempotencyKey})
}

func (f *remoteRegularFile) ReleaseLock(
	_ context.Context,
	idempotencyKey string,
) (regularfile.ResultFileObservationFileError, error) {
	return f.mutate("file.release-lock", idempotencyKey, struct {
		IdempotencyKey string `json:"idempotencyKey"`
	}{idempotencyKey})
}

func (f *remoteRegularFile) mutate(
	op string,
	idempotencyKey string,
	args any,
) (regularfile.ResultFileObservationFileError, error) {
	if idempotencyKey == "" {
		return nil, errors.New("file mutation requires a non-empty idempotency key")
	}
	raw, semantic, err := f.cell.channel.HostCall(f.id, op, args)
	if err != nil {
		return nil, err
	}
	if semantic != nil {
		failure, err := regularFileError(semantic)
		if err != nil {
			return nil, err
		}
		return regularfile.ResultFileObservationFileErrorErr{Value: failure}, nil
	}
	var wire regularFileObservationWire
	if err := protocol.DecodeStrict(raw, &wire); err != nil {
		return nil, fmt.Errorf("decode %s result: %w", op, err)
	}
	value, err := wire.generated()
	if err != nil {
		return nil, err
	}
	return regularfile.ResultFileObservationFileErrorOk{Value: value}, nil
}

func (f *remoteRegularFile) Drop(context.Context) error {
	if _, ok := f.cell.resources[f.id]; !ok {
		return fmt.Errorf("file resource %d was already disposed or never registered", f.id)
	}
	raw, semantic, err := f.cell.channel.HostCall(f.id, "resource.dispose", struct {
		Kind string `json:"kind"`
	}{Kind: "file"})
	if err != nil {
		return err
	}
	if semantic != nil {
		return fmt.Errorf("file resource dispose failed: %w", semantic)
	}
	if !isNull(raw) {
		return errors.New("resource.dispose host result must be null")
	}
	delete(f.cell.resources, f.id)
	return nil
}

func regularFileError(wireError *protocol.WireError) (regularfile.FileError, error) {
	if wireError.Domain != "file" {
		return nil, fmt.Errorf("file hostcall returned non-file error %s", wireError)
	}
	if wireError.Kind != "indeterminate" && wireError.Detail != nil {
		return nil, fmt.Errorf("file error %s unexpectedly carried detail", wireError.Kind)
	}
	switch wireError.Kind {
	case "denied":
		return regularfile.FileErrorDenied{}, nil
	case "conflict":
		return regularfile.FileErrorConflict{}, nil
	case "stale-binding":
		return regularfile.FileErrorStaleBinding{}, nil
	case "unsupported":
		return regularfile.FileErrorUnsupported{}, nil
	case "indeterminate":
		if wireError.Detail == nil || *wireError.Detail == "" {
			return nil, errors.New("file indeterminate error requires a non-empty operation id")
		}
		return regularfile.FileErrorIndeterminate{Value: *wireError.Detail}, nil
	case "unavailable":
		return regularfile.FileErrorUnavailable{}, nil
	default:
		return nil, fmt.Errorf("unknown file error kind %q", wireError.Kind)
	}
}

type regularFileObservationWire struct {
	OperationID      string `json:"operationId"`
	LogicalOffset    string `json:"logicalOffset"`
	Version          string `json:"version"`
	Size             string `json:"size"`
	ContentDigestHex string `json:"contentDigestHex"`
	DurableThrough   string `json:"durableThrough"`
}

func (w regularFileObservationWire) generated() (regularfile.FileObservation, error) {
	logicalOffset, err := protocol.ParseCanonicalU64(w.LogicalOffset)
	if err != nil {
		return regularfile.FileObservation{}, fmt.Errorf("invalid logical offset: %w", err)
	}
	version, err := protocol.ParseCanonicalU64(w.Version)
	if err != nil {
		return regularfile.FileObservation{}, fmt.Errorf("invalid version: %w", err)
	}
	size, err := protocol.ParseCanonicalU64(w.Size)
	if err != nil {
		return regularfile.FileObservation{}, fmt.Errorf("invalid size: %w", err)
	}
	digest, err := protocol.DecodeLowerHex(w.ContentDigestHex)
	if err != nil || len(digest) != sha256.Size {
		return regularfile.FileObservation{}, errors.New("content digest must be 32 bytes of canonical lowercase hex")
	}
	durability, err := regularFileDurability(w.DurableThrough)
	if err != nil {
		return regularfile.FileObservation{}, err
	}
	if w.OperationID == "" {
		return regularfile.FileObservation{}, errors.New("file observation requires an operation id")
	}
	return regularfile.FileObservation{
		OperationID:    w.OperationID,
		LogicalOffset:  logicalOffset,
		Version:        version,
		Size:           size,
		ContentDigest:  digest,
		DurableThrough: durability,
	}, nil
}

type regularFileReadWire struct {
	Observation regularFileObservationWire `json:"observation"`
	BytesHex    string                     `json:"bytesHex"`
}

func (w regularFileReadWire) generated() (regularfile.ReadResult, error) {
	observation, err := w.Observation.generated()
	if err != nil {
		return regularfile.ReadResult{}, err
	}
	data, err := protocol.DecodeLowerHex(w.BytesHex)
	if err != nil {
		return regularfile.ReadResult{}, err
	}
	return regularfile.ReadResult{Observation: observation, Bytes: data}, nil
}

type regularFileStateWire struct {
	SessionID        string  `json:"sessionId"`
	RelativePath     string  `json:"relativePath"`
	LogicalOffset    string  `json:"logicalOffset"`
	Version          string  `json:"version"`
	Size             string  `json:"size"`
	ContentDigestHex string  `json:"contentDigestHex"`
	DurableThrough   string  `json:"durableThrough"`
	LockHeld         bool    `json:"lockHeld"`
	LastOperationID  *string `json:"lastOperationId"`
	Phase            string  `json:"phase"`
}

func (s regularFileStateWire) toVal() (*wacogo.ValRecord, error) {
	logicalOffset, err := protocol.ParseCanonicalU64(s.LogicalOffset)
	if err != nil {
		return nil, err
	}
	version, err := protocol.ParseCanonicalU64(s.Version)
	if err != nil {
		return nil, err
	}
	size, err := protocol.ParseCanonicalU64(s.Size)
	if err != nil {
		return nil, err
	}
	digest, err := protocol.DecodeLowerHex(s.ContentDigestHex)
	if err != nil || len(digest) != sha256.Size {
		return nil, errors.New("state content digest must be 32 bytes of canonical lowercase hex")
	}
	durability, err := regularFileDurabilityDiscriminant(s.DurableThrough)
	if err != nil {
		return nil, err
	}
	phase, err := regularFilePhaseDiscriminant(s.Phase)
	if err != nil {
		return nil, err
	}
	lastOperation := wacogo.ValOptionNone()
	if s.LastOperationID != nil {
		if *s.LastOperationID == "" {
			return nil, errors.New("last operation id must be omitted rather than empty")
		}
		lastOperation = wacogo.ValOptionSome(wacogo.ValString(*s.LastOperationID))
	}
	return wacogo.NewValRecord(
		wacogo.Field{Name: "session-id", Val: wacogo.ValString(s.SessionID)},
		wacogo.Field{Name: "relative-path", Val: wacogo.ValString(s.RelativePath)},
		wacogo.Field{Name: "logical-offset", Val: wacogo.ValU64(logicalOffset)},
		wacogo.Field{Name: "version", Val: wacogo.ValU64(version)},
		wacogo.Field{Name: "size", Val: wacogo.ValU64(size)},
		wacogo.Field{Name: "content-digest", Val: valBytes(digest)},
		wacogo.Field{Name: "durable-through", Val: wacogo.NewValEnum(durability)},
		wacogo.Field{Name: "lock-held", Val: wacogo.ValBool(s.LockHeld)},
		wacogo.Field{Name: "last-operation-id", Val: lastOperation},
		wacogo.Field{Name: "phase", Val: wacogo.NewValEnum(phase)},
	), nil
}

func regularFileStateFromVal(value wacogo.Val) (regularFileStateWire, error) {
	record, fields, err := regularFileRecord(value, []string{
		"session-id",
		"relative-path",
		"logical-offset",
		"version",
		"size",
		"content-digest",
		"durable-through",
		"lock-held",
		"last-operation-id",
		"phase",
	})
	if err != nil {
		return regularFileStateWire{}, err
	}
	_ = record
	sessionID, ok := fields[0].Val.(wacogo.ValString)
	if !ok {
		return regularFileStateWire{}, fmt.Errorf("session-id has type %T", fields[0].Val)
	}
	relativePath, ok := fields[1].Val.(wacogo.ValString)
	if !ok {
		return regularFileStateWire{}, fmt.Errorf("relative-path has type %T", fields[1].Val)
	}
	logicalOffset, ok := fields[2].Val.(wacogo.ValU64)
	if !ok {
		return regularFileStateWire{}, fmt.Errorf("logical-offset has type %T", fields[2].Val)
	}
	version, ok := fields[3].Val.(wacogo.ValU64)
	if !ok {
		return regularFileStateWire{}, fmt.Errorf("version has type %T", fields[3].Val)
	}
	size, ok := fields[4].Val.(wacogo.ValU64)
	if !ok {
		return regularFileStateWire{}, fmt.Errorf("size has type %T", fields[4].Val)
	}
	digest, err := bytesFromVal(fields[5].Val)
	if err != nil || len(digest) != sha256.Size {
		return regularFileStateWire{}, errors.New("state content-digest is not a 32-byte list")
	}
	durabilityValue, ok := fields[6].Val.(*wacogo.ValEnum)
	if !ok {
		return regularFileStateWire{}, fmt.Errorf("durable-through has type %T", fields[6].Val)
	}
	durability, err := regularFileDurabilityName(durabilityValue.Discriminant())
	if err != nil {
		return regularFileStateWire{}, err
	}
	lockHeld, ok := fields[7].Val.(wacogo.ValBool)
	if !ok {
		return regularFileStateWire{}, fmt.Errorf("lock-held has type %T", fields[7].Val)
	}
	lastOption, ok := fields[8].Val.(*wacogo.ValOption)
	if !ok {
		return regularFileStateWire{}, fmt.Errorf("last-operation-id has type %T", fields[8].Val)
	}
	var lastOperationID *string
	if !lastOption.IsNone() {
		text, ok := lastOption.Val().(wacogo.ValString)
		if !ok || text == "" {
			return regularFileStateWire{}, errors.New("last-operation-id some value must be a non-empty string")
		}
		value := string(text)
		lastOperationID = &value
	}
	phaseValue, ok := fields[9].Val.(*wacogo.ValEnum)
	if !ok {
		return regularFileStateWire{}, fmt.Errorf("phase has type %T", fields[9].Val)
	}
	phase, err := regularFilePhaseName(phaseValue.Discriminant())
	if err != nil {
		return regularFileStateWire{}, err
	}
	return regularFileStateWire{
		SessionID:        string(sessionID),
		RelativePath:     string(relativePath),
		LogicalOffset:    strconv.FormatUint(uint64(logicalOffset), 10),
		Version:          strconv.FormatUint(uint64(version), 10),
		Size:             strconv.FormatUint(uint64(size), 10),
		ContentDigestHex: protocol.EncodeHex(digest),
		DurableThrough:   durability,
		LockHeld:         bool(lockHeld),
		LastOperationID:  lastOperationID,
		Phase:            phase,
	}, nil
}

func regularFileObservationFromVal(value wacogo.Val) (regularFileObservationWire, error) {
	_, fields, err := regularFileRecord(value, []string{
		"operation-id",
		"logical-offset",
		"version",
		"size",
		"content-digest",
		"durable-through",
	})
	if err != nil {
		return regularFileObservationWire{}, err
	}
	operationID, ok := fields[0].Val.(wacogo.ValString)
	if !ok || operationID == "" {
		return regularFileObservationWire{}, errors.New("observation operation-id must be a non-empty string")
	}
	logicalOffset, ok := fields[1].Val.(wacogo.ValU64)
	if !ok {
		return regularFileObservationWire{}, fmt.Errorf("observation logical-offset has type %T", fields[1].Val)
	}
	version, ok := fields[2].Val.(wacogo.ValU64)
	if !ok {
		return regularFileObservationWire{}, fmt.Errorf("observation version has type %T", fields[2].Val)
	}
	size, ok := fields[3].Val.(wacogo.ValU64)
	if !ok {
		return regularFileObservationWire{}, fmt.Errorf("observation size has type %T", fields[3].Val)
	}
	digest, err := bytesFromVal(fields[4].Val)
	if err != nil || len(digest) != sha256.Size {
		return regularFileObservationWire{}, errors.New("observation content-digest is not a 32-byte list")
	}
	durabilityValue, ok := fields[5].Val.(*wacogo.ValEnum)
	if !ok {
		return regularFileObservationWire{}, fmt.Errorf("observation durable-through has type %T", fields[5].Val)
	}
	durability, err := regularFileDurabilityName(durabilityValue.Discriminant())
	if err != nil {
		return regularFileObservationWire{}, err
	}
	return regularFileObservationWire{
		OperationID:      string(operationID),
		LogicalOffset:    strconv.FormatUint(uint64(logicalOffset), 10),
		Version:          strconv.FormatUint(uint64(version), 10),
		Size:             strconv.FormatUint(uint64(size), 10),
		ContentDigestHex: protocol.EncodeHex(digest),
		DurableThrough:   durability,
	}, nil
}

func regularFileReadFromVal(value wacogo.Val) (regularFileReadWire, error) {
	_, fields, err := regularFileRecord(value, []string{"observation", "bytes"})
	if err != nil {
		return regularFileReadWire{}, err
	}
	observation, err := regularFileObservationFromVal(fields[0].Val)
	if err != nil {
		return regularFileReadWire{}, err
	}
	data, err := bytesFromVal(fields[1].Val)
	if err != nil {
		return regularFileReadWire{}, err
	}
	return regularFileReadWire{Observation: observation, BytesHex: protocol.EncodeHex(data)}, nil
}

func regularFileRecord(
	value wacogo.Val,
	expected []string,
) (*wacogo.ValRecord, []wacogo.Field, error) {
	record, ok := value.(*wacogo.ValRecord)
	if !ok {
		return nil, nil, fmt.Errorf("regular-file value has type %T, expected record", value)
	}
	fields := record.Fields()
	if len(fields) != len(expected) {
		return nil, nil, fmt.Errorf("regular-file record has %d fields, expected %d", len(fields), len(expected))
	}
	for index, name := range expected {
		if fields[index].Name != name {
			return nil, nil, fmt.Errorf(
				"regular-file record field %d is %q, expected %q",
				index,
				fields[index].Name,
				name,
			)
		}
	}
	return record, fields, nil
}

func regularFileDurability(name string) (regularfile.Durability, error) {
	switch name {
	case "visible":
		return regularfile.DurabilityVisible, nil
	case "data":
		return regularfile.DurabilityData, nil
	case "data-and-metadata":
		return regularfile.DurabilityDataAndMetadata, nil
	default:
		return 0, fmt.Errorf("unknown regular-file durability %q", name)
	}
}

func regularFileDurabilityDiscriminant(name string) (uint32, error) {
	value, err := regularFileDurability(name)
	return uint32(value), err
}

func regularFileDurabilityName(discriminant uint32) (string, error) {
	if discriminant > uint32(regularfile.DurabilityDataAndMetadata) {
		return "", fmt.Errorf("unknown regular-file durability discriminant %d", discriminant)
	}
	return regularfile.Durability(discriminant).String(), nil
}

func regularFilePhaseDiscriminant(name string) (uint32, error) {
	switch name {
	case "active":
		return 0, nil
	case "frozen":
		return 1, nil
	default:
		return 0, fmt.Errorf("unknown regular-file workload phase %q", name)
	}
}

func regularFilePhaseName(discriminant uint32) (string, error) {
	switch discriminant {
	case 0:
		return "active", nil
	case 1:
		return "frozen", nil
	default:
		return "", fmt.Errorf("unknown regular-file workload phase discriminant %d", discriminant)
	}
}

func verifyRegularFileSurface(component *wacogo.Component) error {
	if len(component.Imports()) != 1 {
		return fmt.Errorf("regular-file component has %d imports, expected one", len(component.Imports()))
	}
	item := component.Imports()[0]
	if item.Name != regularfile.InterfaceName || item.Kind != wacogo.SortInstance {
		return fmt.Errorf("unexpected regular-file component import %q with kind %v", item.Name, item.Kind)
	}
	if len(component.Exports()) != 1 {
		return fmt.Errorf("regular-file component has %d exports, expected one", len(component.Exports()))
	}
	export := component.Exports()[0]
	if export.Name != regularFileWorkloadName || export.Kind != wacogo.SortInstance {
		return fmt.Errorf("unexpected regular-file component export %q with kind %v", export.Name, export.Kind)
	}
	return nil
}

func verifyRegularFileComponentIdentity(component []byte) error {
	digest := sha256.Sum256(component)
	observedSHA256 := fmt.Sprintf("%x", digest)
	if len(component) != regularFileAcceptedComponentSize || observedSHA256 != regularFileAcceptedComponentSHA256 {
		return fmt.Errorf(
			"unsupported regular-file Component identity: size=%d sha256=%s, expected size=%d sha256=%s",
			len(component),
			observedSHA256,
			regularFileAcceptedComponentSize,
			regularFileAcceptedComponentSHA256,
		)
	}
	return nil
}

func verifyRegularFileLiveSurface(workload *wacogo.ComponentInstance) error {
	if workload == nil {
		return errors.New("regular-file workload instance was nil")
	}
	for _, name := range regularFileRequiredExports {
		if workload.ExportedFunc(name) == nil {
			return fmt.Errorf("regular-file workload export %q was not found", name)
		}
	}
	return nil
}
