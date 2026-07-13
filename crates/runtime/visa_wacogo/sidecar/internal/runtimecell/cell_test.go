package runtimecell

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/partite-ai/wacogo"
	"github.com/partite-ai/wacogo/wasmtools"
	"visa.local/wacogo-runtime/internal/protocol"
)

func TestPrepareRejectsSameNameEmptyWorkloadBeforeInstantiation(t *testing.T) {
	ctx := context.Background()
	tool, err := wasmtools.Default(ctx)
	if err != nil {
		t.Fatalf("wasmtools.Default: %v", err)
	}
	component, err := tool.Parse(ctx, []byte(`(component
  (type $empty (instance))
  (import "visa:continuity/key-value@0.1.0" (instance $kv (type $empty)))
  (import "visa:continuity/timers@0.1.0" (instance $timer (type $empty)))
  (instance $workload)
  (export "visa:continuity/workload@0.1.0" (instance $workload))
)`))
	if err != nil {
		t.Fatalf("parse malformed same-name Component: %v", err)
	}
	digest := sha256.Sum256(component)
	observedSHA256 := hex.EncodeToString(digest[:])
	const fixtureSHA256 = "f8d32de44e12533b51fd0539e24145910ca2b584a542227b8e3ea85f3bfed869"
	if len(component) != 179 || observedSHA256 != fixtureSHA256 {
		t.Fatalf(
			"malformed fixture identity = size %d sha256 %s, want size 179 sha256 %s",
			len(component),
			observedSHA256,
			fixtureSHA256,
		)
	}

	cell, failure := Prepare(
		ctx,
		protocol.NewChannel(bytes.NewReader(nil), &bytes.Buffer{}),
		component,
	)
	if cell != nil {
		_ = cell.Close()
		t.Fatal("malformed same-name Component unexpectedly produced a prepared cell")
	}
	if failure == nil || failure.Domain != "preflight" || failure.Kind != "unsupported-runtime-feature" {
		t.Fatalf("malformed same-name Component failure = %+v", failure)
	}
	if failure.Detail == nil ||
		!strings.Contains(*failure.Detail, "size=179 sha256="+fixtureSHA256) {
		t.Fatalf("malformed same-name Component detail = %v", failure.Detail)
	}
}

func TestMissingWorkloadExportsReturnStructuredTraps(t *testing.T) {
	cell := &Cell{ctx: context.Background(), instantiated: true}
	for _, name := range requiredWorkloadExports {
		t.Run(name, func(t *testing.T) {
			var failure *protocol.WireError
			if name == "status" {
				_, failure = cell.status(json.RawMessage(`{}`))
			} else {
				_, failure = cell.callResult(name)
			}
			if failure == nil || failure.Domain != "trap" || failure.Kind != "missing-export" {
				t.Fatalf("missing export %q failure = %+v", name, failure)
			}
			if failure.Detail == nil || !strings.Contains(*failure.Detail, name) {
				t.Fatalf("missing export %q detail = %v", name, failure.Detail)
			}
		})
	}
	if err := verifyLiveWorkloadSurface(nil); err == nil {
		t.Fatal("nil workload surface unexpectedly passed live verification")
	}
}

func TestComponentStateRoundTripsThroughTypedValues(t *testing.T) {
	wire := stateWire{
		SessionID:                "session-a",
		Key:                      "counter",
		ExpectedVersion:          "7",
		CompletionValueHex:       "00ff10",
		TimerOperationID:         "timer-operation",
		TimerIdempotencyKey:      "timer-key",
		CompletionIdempotencyKey: "completion-key",
		Phase:                    "frozen",
	}
	value, err := wire.toVal()
	if err != nil {
		t.Fatal(err)
	}
	roundTrip, err := stateFromVal(value)
	if err != nil {
		t.Fatal(err)
	}
	if roundTrip != wire {
		t.Fatalf("round trip mismatch:\nwant %+v\n got %+v", wire, roundTrip)
	}
	completion, err := bytesFromVal(value.Field("completion-value"))
	if err != nil || !bytes.Equal(completion, []byte{0, 255, 16}) {
		t.Fatalf("completion=%x err=%v", completion, err)
	}
}

func TestComponentStateRejectsNonCanonicalOrMismatchedValues(t *testing.T) {
	for name, wire := range map[string]stateWire{
		"version": {ExpectedVersion: "01", CompletionValueHex: "", Phase: "armed"},
		"hex":     {ExpectedVersion: "0", CompletionValueHex: "FF", Phase: "armed"},
		"phase":   {ExpectedVersion: "0", CompletionValueHex: "", Phase: "paused"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := wire.toVal(); err == nil {
				t.Fatal("invalid state unexpectedly converted")
			}
		})
	}
	invalid := wacogo.NewValRecord(wacogo.Field{Name: "wrong", Val: wacogo.ValString("value")})
	if _, err := stateFromVal(invalid); err == nil {
		t.Fatal("wrong state record shape unexpectedly converted")
	}
}

func TestWorkloadErrorVariantsMapWithoutParsingText(t *testing.T) {
	for discriminant, kind := range []string{
		"already-active",
		"invalid-state",
		"wrong-timer",
		"safe-point-unavailable",
	} {
		failure := workloadFailure(wacogo.NewValVariant(uint32(discriminant), nil))
		if failure.Domain != "workload" || failure.Kind != kind || failure.Detail != nil {
			t.Fatalf("discriminant %d mapped to %+v", discriminant, failure)
		}
	}
	indeterminate := workloadFailure(wacogo.NewValVariant(
		4,
		wacogo.NewValVariant(3, wacogo.ValString("operation-a")),
	))
	if indeterminate.Domain != "workload" || indeterminate.Kind != "kv.indeterminate" ||
		indeterminate.Detail == nil || *indeterminate.Detail != "operation-a" {
		t.Fatalf("kv indeterminate mapped to %+v", indeterminate)
	}
	notPending := workloadFailure(wacogo.NewValVariant(5, wacogo.NewValVariant(2, nil)))
	if notPending.Domain != "workload" || notPending.Kind != "timer.not-pending" {
		t.Fatalf("timer not-pending mapped to %+v", notPending)
	}
}

func TestMalformedWorkloadErrorsBecomeTraps(t *testing.T) {
	for name, value := range map[string]wacogo.Val{
		"not-variant":         wacogo.ValString("already-active"),
		"unit-with-payload":   wacogo.NewValVariant(0, wacogo.ValString("bad")),
		"unknown-outer":       wacogo.NewValVariant(99, nil),
		"empty-indeterminate": wacogo.NewValVariant(4, wacogo.NewValVariant(3, wacogo.ValString(""))),
		"timer-with-payload":  wacogo.NewValVariant(5, wacogo.NewValVariant(0, wacogo.ValString("bad"))),
	} {
		t.Run(name, func(t *testing.T) {
			failure := workloadFailure(value)
			if failure.Domain != "trap" || failure.Kind != "invalid-workload-error" {
				t.Fatalf("malformed error mapped to %+v", failure)
			}
		})
	}
}
