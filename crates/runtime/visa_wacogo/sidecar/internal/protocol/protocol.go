package protocol

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

const (
	Version             = uint32(1)
	CarrierVersion      = "VISAWCG1"
	MaxCarrierBytes     = uint64(64 * 1024 * 1024)
	MaxJSONLMessageSize = 1024 * 1024
)

type RuntimeIdentity struct {
	Implementation        string `json:"implementation"`
	ImplementationVersion string `json:"implementationVersion"`
	Engine                string `json:"engine"`
	EngineVersion         string `json:"engineVersion"`
	WacogoVersion         string `json:"wacogoVersion"`
	WacogoRevision        string `json:"wacogoRevision"`
	PatchsetSHA256        string `json:"patchsetSha256"`
	PatchedTreeSHA256     string `json:"patchedTreeSha256"`
	WazeroVersion         string `json:"wazeroVersion"`
	GoVersion             string `json:"goVersion"`
	Target                string `json:"target"`
	MainModule            string `json:"mainModule"`
}

type WireError struct {
	Domain string  `json:"domain"`
	Kind   string  `json:"kind"`
	Detail *string `json:"detail,omitempty"`
}

func NewError(domain, kind string, detail error) *WireError {
	var text *string
	if detail != nil {
		value := detail.Error()
		text = &value
	}
	return &WireError{Domain: domain, Kind: kind, Detail: text}
}

func ErrorDetail(domain, kind, detail string) *WireError {
	return &WireError{Domain: domain, Kind: kind, Detail: &detail}
}

func (e *WireError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Detail == nil {
		return e.Domain + ":" + e.Kind
	}
	return e.Domain + ":" + e.Kind + ": " + *e.Detail
}

func (e *WireError) Validate() error {
	if e == nil || e.Domain == "" || e.Kind == "" {
		return errors.New("wire error requires non-empty domain and kind")
	}
	if e.Detail != nil && *e.Detail == "" {
		return errors.New("wire error detail must be omitted rather than empty")
	}
	return nil
}

type PreparedMessage struct {
	Type              string          `json:"type"`
	Protocol          uint32          `json:"protocol"`
	ComponentSHA256   string          `json:"componentSha256"`
	GuestInstantiated bool            `json:"guestInstantiated"`
	LiveResources     uint64          `json:"liveResources"`
	Runtime           RuntimeIdentity `json:"runtime"`
}

type startupErrorMessage struct {
	Type          string     `json:"type"`
	Protocol      uint32     `json:"protocol"`
	OK            bool       `json:"ok"`
	Error         *WireError `json:"error"`
	LiveResources uint64     `json:"liveResources"`
}

type optionalRaw struct {
	Present bool
	Value   json.RawMessage
}

func (o *optionalRaw) UnmarshalJSON(data []byte) error {
	o.Present = true
	o.Value = append(o.Value[:0], data...)
	return nil
}

type commandMessage struct {
	Type     string      `json:"type"`
	Protocol uint32      `json:"protocol"`
	ID       uint64      `json:"id"`
	Op       string      `json:"op"`
	Args     optionalRaw `json:"args"`
}

type Command struct {
	ID   uint64
	Op   string
	Args json.RawMessage
}

type hostResponseMessage struct {
	Type     string      `json:"type"`
	Protocol uint32      `json:"protocol"`
	ID       uint64      `json:"id"`
	OK       bool        `json:"ok"`
	Result   optionalRaw `json:"result"`
	Error    optionalRaw `json:"error"`
}

type hostCallMessage struct {
	Type      string `json:"type"`
	Protocol  uint32 `json:"protocol"`
	ID        uint64 `json:"id"`
	CommandID uint64 `json:"commandId"`
	Resource  uint64 `json:"resource"`
	Op        string `json:"op"`
	Args      any    `json:"args"`
}

type successResponse struct {
	Type          string `json:"type"`
	Protocol      uint32 `json:"protocol"`
	ID            uint64 `json:"id"`
	OK            bool   `json:"ok"`
	Result        any    `json:"result"`
	LiveResources uint64 `json:"liveResources"`
}

type failureResponse struct {
	Type          string     `json:"type"`
	Protocol      uint32     `json:"protocol"`
	ID            uint64     `json:"id"`
	OK            bool       `json:"ok"`
	Error         *WireError `json:"error"`
	LiveResources uint64     `json:"liveResources"`
}

type settledMessage struct {
	Type     string `json:"type"`
	Protocol uint32 `json:"protocol"`
	ID       uint64 `json:"id"`
}

type Channel struct {
	reader         *bufio.Reader
	writer         *bufio.Writer
	nextCommandID  uint64
	nextHostcallID uint64
	activeCommand  uint64
}

func NewChannel(reader io.Reader, writer io.Writer) *Channel {
	return &Channel{
		reader:         bufio.NewReaderSize(reader, 64*1024),
		writer:         bufio.NewWriterSize(writer, 64*1024),
		nextCommandID:  1,
		nextHostcallID: 1,
	}
}

func (c *Channel) ReadCarrier() ([]byte, [32]byte, error) {
	header := make([]byte, len(CarrierVersion)+8+sha256.Size)
	if _, err := io.ReadFull(c.reader, header); err != nil {
		return nil, [32]byte{}, fmt.Errorf("read carrier header: %w", err)
	}
	if string(header[:len(CarrierVersion)]) != CarrierVersion {
		return nil, [32]byte{}, errors.New("invalid carrier magic")
	}
	length := binary.BigEndian.Uint64(header[len(CarrierVersion) : len(CarrierVersion)+8])
	if length == 0 || length > MaxCarrierBytes {
		return nil, [32]byte{}, fmt.Errorf("carrier length %d is outside 1..%d", length, MaxCarrierBytes)
	}
	var expected [32]byte
	copy(expected[:], header[len(CarrierVersion)+8:])
	payload := make([]byte, int(length))
	if _, err := io.ReadFull(c.reader, payload); err != nil {
		return nil, [32]byte{}, fmt.Errorf("read carrier payload: %w", err)
	}
	observed := sha256.Sum256(payload)
	if observed != expected {
		return nil, [32]byte{}, fmt.Errorf(
			"carrier digest mismatch: expected %s, observed %s",
			hex.EncodeToString(expected[:]),
			hex.EncodeToString(observed[:]),
		)
	}
	return payload, observed, nil
}

func (c *Channel) WritePrepared(digest [32]byte, runtime RuntimeIdentity) error {
	return c.writeJSON(PreparedMessage{
		Type:              "prepared",
		Protocol:          Version,
		ComponentSHA256:   hex.EncodeToString(digest[:]),
		GuestInstantiated: false,
		LiveResources:     0,
		Runtime:           runtime,
	})
}

func (c *Channel) WriteStartupError(wireError *WireError, liveResources uint64) error {
	if err := wireError.Validate(); err != nil {
		return err
	}
	return c.writeJSON(startupErrorMessage{
		Type:          "startup-error",
		Protocol:      Version,
		OK:            false,
		Error:         wireError,
		LiveResources: liveResources,
	})
}

func (c *Channel) ReadCommand() (Command, error) {
	if c.activeCommand != 0 {
		return Command{}, errors.New("cannot read a command while another command is active")
	}
	line, err := c.readJSONL()
	if err != nil {
		return Command{}, err
	}
	var message commandMessage
	if err := DecodeStrict(line, &message); err != nil {
		return Command{}, fmt.Errorf("decode command: %w", err)
	}
	if message.Type != "command" || message.Protocol != Version {
		return Command{}, fmt.Errorf("invalid command type or protocol %q/%d", message.Type, message.Protocol)
	}
	if message.ID == 0 || message.ID != c.nextCommandID {
		return Command{}, fmt.Errorf("command id %d did not match expected %d", message.ID, c.nextCommandID)
	}
	if message.Op == "" || !message.Args.Present {
		return Command{}, errors.New("command requires non-empty op and present args")
	}
	if !isJSONObject(message.Args.Value) {
		return Command{}, errors.New("command args must be a JSON object")
	}
	c.nextCommandID++
	c.activeCommand = message.ID
	return Command{ID: message.ID, Op: message.Op, Args: message.Args.Value}, nil
}

func (c *Channel) FinishSuccess(commandID uint64, result any, liveResources uint64) error {
	if err := c.requireActive(commandID); err != nil {
		return err
	}
	if err := c.writeJSON(successResponse{
		Type:          "response",
		Protocol:      Version,
		ID:            commandID,
		OK:            true,
		Result:        result,
		LiveResources: liveResources,
	}); err != nil {
		return err
	}
	return c.finishSettled(commandID)
}

func (c *Channel) FinishFailure(commandID uint64, wireError *WireError, liveResources uint64) error {
	if err := c.requireActive(commandID); err != nil {
		return err
	}
	if err := wireError.Validate(); err != nil {
		return err
	}
	if err := c.writeJSON(failureResponse{
		Type:          "response",
		Protocol:      Version,
		ID:            commandID,
		OK:            false,
		Error:         wireError,
		LiveResources: liveResources,
	}); err != nil {
		return err
	}
	return c.finishSettled(commandID)
}

func (c *Channel) HostCall(resource uint64, op string, args any) (json.RawMessage, *WireError, error) {
	if c.activeCommand == 0 || resource == 0 || op == "" {
		return nil, nil, errors.New("hostcall requires an active command, resource, and operation")
	}
	id := c.nextHostcallID
	if id == 0 {
		return nil, nil, errors.New("hostcall id exhausted")
	}
	c.nextHostcallID++
	if err := c.writeJSON(hostCallMessage{
		Type:      "hostcall",
		Protocol:  Version,
		ID:        id,
		CommandID: c.activeCommand,
		Resource:  resource,
		Op:        op,
		Args:      args,
	}); err != nil {
		return nil, nil, err
	}
	line, err := c.readJSONL()
	if err != nil {
		return nil, nil, fmt.Errorf("read hostcall response: %w", err)
	}
	var response hostResponseMessage
	if err := DecodeStrict(line, &response); err != nil {
		return nil, nil, fmt.Errorf("decode hostcall response: %w", err)
	}
	if response.Type != "hostcall-response" || response.Protocol != Version || response.ID != id {
		return nil, nil, fmt.Errorf(
			"invalid hostcall response identity: type=%q protocol=%d id=%d expected=%d",
			response.Type,
			response.Protocol,
			response.ID,
			id,
		)
	}
	if response.OK {
		if !response.Result.Present || response.Error.Present {
			return nil, nil, errors.New("successful hostcall response requires result and omits error")
		}
		return response.Result.Value, nil, nil
	}
	if response.Result.Present || !response.Error.Present {
		return nil, nil, errors.New("failed hostcall response omits result and requires error")
	}
	var wireError WireError
	if err := DecodeStrict(response.Error.Value, &wireError); err != nil {
		return nil, nil, fmt.Errorf("decode hostcall error: %w", err)
	}
	if err := wireError.Validate(); err != nil {
		return nil, nil, err
	}
	return nil, &wireError, nil
}

// WaitForEOF keeps a terminal child alive until the supervising Rust process
// has consumed the response and closed its command stream. Any extra byte is a
// protocol violation rather than a second command after the terminal boundary.
func (c *Channel) WaitForEOF() error {
	byteValue, err := c.reader.ReadByte()
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err != nil {
		return err
	}
	return fmt.Errorf("received unsolicited byte 0x%02x after terminal command", byteValue)
}

func DecodeArgs(data json.RawMessage, destination any) error {
	if !isJSONObject(data) {
		return errors.New("arguments must be a JSON object")
	}
	return DecodeStrict(data, destination)
}

func DecodeStrict(data []byte, destination any) error {
	if err := rejectDuplicateKeys(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := requireJSONEOF(decoder); err != nil {
		return err
	}
	return nil
}

func ParseCanonicalU64(value string) (uint64, error) {
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil || strconv.FormatUint(parsed, 10) != value {
		return 0, fmt.Errorf("%q is not canonical u64 text", value)
	}
	return parsed, nil
}

func DecodeLowerHex(value string) ([]byte, error) {
	if strings.ToLower(value) != value || len(value)%2 != 0 {
		return nil, errors.New("byte text must be lowercase, even-length hexadecimal")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("decode hexadecimal bytes: %w", err)
	}
	return decoded, nil
}

func EncodeHex(value []byte) string {
	return hex.EncodeToString(value)
}

func (c *Channel) finishSettled(commandID uint64) error {
	if err := c.writeJSON(settledMessage{Type: "settled", Protocol: Version, ID: commandID}); err != nil {
		return err
	}
	c.activeCommand = 0
	return nil
}

func (c *Channel) requireActive(commandID uint64) error {
	if commandID == 0 || c.activeCommand != commandID {
		return fmt.Errorf("command %d did not match active command %d", commandID, c.activeCommand)
	}
	return nil
}

func (c *Channel) writeJSON(value any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode protocol message: %w", err)
	}
	if len(encoded)+1 > MaxJSONLMessageSize {
		return fmt.Errorf("protocol message exceeds %d bytes", MaxJSONLMessageSize)
	}
	if _, err := c.writer.Write(encoded); err != nil {
		return fmt.Errorf("write protocol message: %w", err)
	}
	if err := c.writer.WriteByte('\n'); err != nil {
		return fmt.Errorf("terminate protocol message: %w", err)
	}
	if err := c.writer.Flush(); err != nil {
		return fmt.Errorf("flush protocol message: %w", err)
	}
	return nil
}

func (c *Channel) readJSONL() ([]byte, error) {
	var line []byte
	for {
		fragment, err := c.reader.ReadSlice('\n')
		if len(line)+len(fragment) > MaxJSONLMessageSize ||
			(errors.Is(err, bufio.ErrBufferFull) && len(line)+len(fragment) >= MaxJSONLMessageSize) {
			return nil, fmt.Errorf("protocol message exceeds %d bytes", MaxJSONLMessageSize)
		}
		line = append(line, fragment...)
		switch {
		case err == nil:
			line = line[:len(line)-1]
			line = bytes.TrimSuffix(line, []byte{'\r'})
			return line, nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF) && len(line) == 0:
			return nil, io.EOF
		case errors.Is(err, io.EOF):
			return nil, errors.New("protocol message ended without a newline")
		default:
			return nil, err
		}
	}
}

func isJSONObject(data []byte) bool {
	trimmed := bytes.TrimSpace(data)
	return len(trimmed) >= 2 && trimmed[0] == '{' && trimmed[len(trimmed)-1] == '}'
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("JSON message contains a second value")
	}
	return err
}

func rejectDuplicateKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := walkJSONValue(decoder); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func walkJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key was not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate JSON object key %q", key)
			}
			seen[key] = struct{}{}
			if err := walkJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim('}') {
			return errors.New("JSON object did not end with a closing brace")
		}
	case '[':
		for decoder.More() {
			if err := walkJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim(']') {
			return errors.New("JSON array did not end with a closing bracket")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
	return nil
}
