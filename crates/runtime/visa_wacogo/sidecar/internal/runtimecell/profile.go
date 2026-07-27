package runtimecell

import (
	"context"
	"encoding/json"
	"fmt"

	"visa.local/wacogo-runtime/internal/protocol"
)

// Cell is the lifecycle boundary shared by independently prepared world
// implementations. Profile dispatch happens once, before wacogo loads the
// Component; commands never cross from one profile implementation to another.
type Cell struct {
	profile protocol.Profile
	impl    profileCell
}

type profileCell interface {
	Handle(string, json.RawMessage) (any, *protocol.WireError, bool)
	LiveResources() uint64
	Close() error
}

type profileFactory func(context.Context, *protocol.Channel, []byte) (profileCell, *protocol.WireError)

var profileFactories = map[protocol.Profile]profileFactory{
	protocol.ProfileCooperativeHandoff: func(
		ctx context.Context,
		channel *protocol.Channel,
		component []byte,
	) (profileCell, *protocol.WireError) {
		return prepareCooperative(ctx, channel, component)
	},
	protocol.ProfileRegularFile: func(
		ctx context.Context,
		channel *protocol.Channel,
		component []byte,
	) (profileCell, *protocol.WireError) {
		return prepareRegularFile(ctx, channel, component)
	},
}

func Prepare(
	ctx context.Context,
	channel *protocol.Channel,
	profile protocol.Profile,
	component []byte,
) (*Cell, *protocol.WireError) {
	factory, ok := profileFactories[profile]
	if !ok {
		return nil, protocol.ErrorDetail(
			"preflight",
			"unsupported-profile",
			fmt.Sprintf("profile %q is not registered by this sidecar", profile),
		)
	}
	impl, failure := factory(ctx, channel, component)
	if failure != nil {
		return nil, failure
	}
	return &Cell{profile: profile, impl: impl}, nil
}

func (c *Cell) Profile() protocol.Profile {
	return c.profile
}

func (c *Cell) Handle(op string, raw json.RawMessage) (any, *protocol.WireError, bool) {
	return c.impl.Handle(op, raw)
}

func (c *Cell) LiveResources() uint64 {
	return c.impl.LiveResources()
}

func (c *Cell) Close() error {
	return c.impl.Close()
}
