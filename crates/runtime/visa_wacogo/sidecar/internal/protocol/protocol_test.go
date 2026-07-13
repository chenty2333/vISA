package protocol

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
)

func TestCarrierRequiresExactMagicLengthAndDigest(t *testing.T) {
	payload := []byte("component-bytes")
	digest := sha256.Sum256(payload)
	var carrier bytes.Buffer
	carrier.WriteString(CarrierVersion)
	if err := binary.Write(&carrier, binary.BigEndian, uint64(len(payload))); err != nil {
		t.Fatal(err)
	}
	carrier.Write(digest[:])
	carrier.Write(payload)

	channel := NewChannel(bytes.NewReader(carrier.Bytes()), &bytes.Buffer{})
	observed, observedDigest, err := channel.ReadCarrier()
	if err != nil {
		t.Fatalf("valid carrier: %v", err)
	}
	if !bytes.Equal(observed, payload) || observedDigest != digest {
		t.Fatalf("carrier mismatch: %q / %x", observed, observedDigest)
	}

	for name, mutate := range map[string]func([]byte){
		"magic":  func(data []byte) { data[0] ^= 1 },
		"digest": func(data []byte) { data[len(CarrierVersion)+8] ^= 1 },
		"length": func(data []byte) {
			binary.BigEndian.PutUint64(data[len(CarrierVersion):], 0)
		},
	} {
		t.Run(name, func(t *testing.T) {
			data := append([]byte(nil), carrier.Bytes()...)
			mutate(data)
			if _, _, err := NewChannel(bytes.NewReader(data), &bytes.Buffer{}).ReadCarrier(); err == nil {
				t.Fatal("malformed carrier unexpectedly passed")
			}
		})
	}
}

func TestStrictJSONRejectsDuplicateUnknownAndTrailingData(t *testing.T) {
	type message struct {
		Value string `json:"value"`
	}
	for name, input := range map[string]string{
		"duplicate": `{"value":"a","value":"b"}`,
		"unknown":   `{"value":"a","extra":true}`,
		"trailing":  `{"value":"a"} {"value":"b"}`,
	} {
		t.Run(name, func(t *testing.T) {
			var output message
			if err := DecodeStrict([]byte(input), &output); err == nil {
				t.Fatalf("malformed JSON unexpectedly passed: %s", input)
			}
		})
	}
	var output message
	if err := DecodeStrict([]byte(`{"value":"a"}`), &output); err != nil || output.Value != "a" {
		t.Fatalf("valid strict JSON: output=%+v err=%v", output, err)
	}
}

func TestCanonicalIntegerAndHexText(t *testing.T) {
	for _, value := range []string{"0", "1", "18446744073709551615"} {
		if _, err := ParseCanonicalU64(value); err != nil {
			t.Fatalf("valid u64 %q: %v", value, err)
		}
	}
	for _, value := range []string{"", "00", "01", "+1", "-0", "18446744073709551616"} {
		if _, err := ParseCanonicalU64(value); err == nil {
			t.Fatalf("non-canonical u64 passed: %q", value)
		}
	}
	if value, err := DecodeLowerHex("00ff10"); err != nil || !bytes.Equal(value, []byte{0, 255, 16}) {
		t.Fatalf("valid hex: %x / %v", value, err)
	}
	for _, value := range []string{"0", "FF", "0x00", "gg"} {
		if _, err := DecodeLowerHex(value); err == nil {
			t.Fatalf("non-canonical hex passed: %q", value)
		}
	}
}

func TestCommandHostcallResponseAndSettledSequence(t *testing.T) {
	input := strings.Join([]string{
		`{"type":"command","protocol":1,"id":1,"op":"activate","args":{}}`,
		`{"type":"hostcall-response","protocol":1,"id":1,"ok":true,"result":{"version":"1"}}`,
		"",
	}, "\n")
	var output bytes.Buffer
	channel := NewChannel(strings.NewReader(input), &output)
	command, err := channel.ReadCommand()
	if err != nil || command.ID != 1 || command.Op != "activate" {
		t.Fatalf("command=%+v err=%v", command, err)
	}
	raw, semantic, err := channel.HostCall(7, "kv.read", struct {
		Key string `json:"key"`
	}{Key: "counter"})
	if err != nil || semantic != nil {
		t.Fatalf("hostcall raw=%s semantic=%v err=%v", raw, semantic, err)
	}
	var result struct {
		Version string `json:"version"`
	}
	if err := DecodeStrict(raw, &result); err != nil || result.Version != "1" {
		t.Fatalf("host result=%+v err=%v", result, err)
	}
	if err := channel.FinishSuccess(command.ID, nil, 0); err != nil {
		t.Fatal(err)
	}

	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("protocol output has %d lines: %q", len(lines), output.String())
	}
	var hostcall map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &hostcall); err != nil {
		t.Fatal(err)
	}
	if hostcall["type"] != "hostcall" || hostcall["op"] != "kv.read" || hostcall["commandId"] != float64(1) {
		t.Fatalf("unexpected hostcall: %v", hostcall)
	}
	if !strings.Contains(lines[1], `"result":null`) || !strings.Contains(lines[2], `"type":"settled"`) {
		t.Fatalf("missing terminal response/settled: %q", output.String())
	}
}

func TestJSONLRequiresANewlineAndEnforcesTheLimit(t *testing.T) {
	for name, input := range map[string]string{
		"unterminated": `{}`,
		"oversized":    strings.Repeat("x", MaxJSONLMessageSize) + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			channel := NewChannel(strings.NewReader(input), &bytes.Buffer{})
			if _, err := channel.readJSONL(); err == nil {
				t.Fatal("invalid JSONL framing unexpectedly passed")
			}
		})
	}
}
