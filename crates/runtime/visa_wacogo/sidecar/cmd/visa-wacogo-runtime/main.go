package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"visa.local/wacogo-runtime/internal/protocol"
	"visa.local/wacogo-runtime/internal/runtimecell"
)

func main() {
	os.Exit(run())
}

func run() int {
	channel := protocol.NewChannel(os.Stdin, os.Stdout)
	if err := runtimecell.ConfigureParentDeathSignal(); err != nil {
		return startupFailure(channel, "runtime-identity", err)
	}
	identity, err := runtimecell.VerifyBuildIdentity()
	if err != nil {
		return startupFailure(channel, "runtime-identity", err)
	}
	component, digest, err := channel.ReadCarrier()
	if err != nil {
		return startupFailure(channel, "invalid-carrier", err)
	}
	cell, wireError := runtimecell.Prepare(context.Background(), channel, component)
	if wireError != nil {
		if err := channel.WriteStartupError(wireError, 0); err != nil {
			fmt.Fprintf(os.Stderr, "write startup preflight failure: %v\n", err)
		}
		return 1
	}
	defer func() {
		if err := cell.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "sidecar cleanup: %v\n", err)
		}
	}()
	if err := channel.WritePrepared(digest, identity); err != nil {
		fmt.Fprintf(os.Stderr, "write prepared handshake: %v\n", err)
		return 1
	}

	for {
		command, err := channel.ReadCommand()
		if err != nil {
			if err != io.EOF {
				fmt.Fprintf(os.Stderr, "read command: %v\n", err)
			}
			return 1
		}
		result, failure, terminate := cell.Handle(command.Op, command.Args)
		liveResources := cell.LiveResources()
		if failure == nil {
			err = channel.FinishSuccess(command.ID, result, liveResources)
		} else {
			err = channel.FinishFailure(command.ID, failure, liveResources)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "write command result: %v\n", err)
			return 1
		}
		if terminate {
			if err := channel.WaitForEOF(); err != nil {
				fmt.Fprintf(os.Stderr, "terminal command boundary: %v\n", err)
				return 1
			}
			if command.Op != "shutdown" || failure != nil {
				return 1
			}
			return 0
		}
	}
}

func startupFailure(channel *protocol.Channel, kind string, cause error) int {
	if err := channel.WriteStartupError(protocol.NewError("preflight", kind, cause), 0); err != nil {
		fmt.Fprintf(os.Stderr, "write startup error: %v (original: %v)\n", err, cause)
	}
	return 1
}
