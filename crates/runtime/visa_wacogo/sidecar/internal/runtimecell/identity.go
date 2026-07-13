package runtimecell

import (
	"fmt"
	"os"
	"runtime"
	"runtime/debug"

	"golang.org/x/sys/unix"
	"visa.local/wacogo-runtime/internal/protocol"
)

const (
	implementationVersion = "0.1.0"
	wacogoVersion         = "v0.0.0-20260617023329-3de16a61796c"
	wacogoRevision        = "3de16a61796ce02d29795e4a074f37a33e6ebd87"
	wacogoReplace         = "../wacogo"
	wazeroVersion         = "v1.11.1-0.20260418165552-5cb4bb3ec0c1"
	patchsetSHA256        = "a377b3d3f0da455f14097638380a8bab566b2aa0d33a4f25d90326e7a2b211e2"
	patchedTreeSHA256     = "813eb9fad2d93d0c2237edf5d55d18316d1cc313ccf033e079c01fd18f653311"
	requiredGoVersion     = "go1.26.5"
	mainModule            = "visa.local/wacogo-runtime"
	engineVersion         = "wacogo-v0.0.0-20260617023329-3de16a61796c+visa-patchset-v1/wazero-v1.11.1-0.20260418165552-5cb4bb3ec0c1"
)

func ConfigureParentDeathSignal() error {
	parent := os.Getppid()
	if parent <= 1 {
		return fmt.Errorf("refusing to start without a live supervising parent: ppid=%d", parent)
	}
	if err := unix.Prctl(unix.PR_SET_PDEATHSIG, uintptr(unix.SIGKILL), 0, 0, 0); err != nil {
		return fmt.Errorf("set parent-death signal: %w", err)
	}
	if observed := os.Getppid(); observed != parent {
		return fmt.Errorf("supervising parent changed while arming parent-death signal: %d -> %d", parent, observed)
	}
	return nil
}

func VerifyBuildIdentity() (protocol.RuntimeIdentity, error) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return protocol.RuntimeIdentity{}, fmt.Errorf("Go build identity is unavailable")
	}
	if info.GoVersion != requiredGoVersion || runtime.Version() != requiredGoVersion {
		return protocol.RuntimeIdentity{}, fmt.Errorf(
			"Go version mismatch: build=%s runtime=%s expected=%s",
			info.GoVersion,
			runtime.Version(),
			requiredGoVersion,
		)
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		return protocol.RuntimeIdentity{}, fmt.Errorf(
			"target mismatch: %s/%s expected linux/amd64",
			runtime.GOOS,
			runtime.GOARCH,
		)
	}
	if info.Main.Path != mainModule {
		return protocol.RuntimeIdentity{}, fmt.Errorf("main module mismatch: %q", info.Main.Path)
	}

	expected := map[string]struct {
		version string
		replace string
	}{
		"github.com/partite-ai/wacogo":  {version: wacogoVersion, replace: wacogoReplace},
		"github.com/tetratelabs/wazero": {version: wazeroVersion},
	}
	for _, dependency := range info.Deps {
		want, found := expected[dependency.Path]
		if !found {
			continue
		}
		replacement := ""
		if dependency.Replace != nil {
			replacement = dependency.Replace.Path
		}
		if dependency.Version != want.version || replacement != want.replace {
			return protocol.RuntimeIdentity{}, fmt.Errorf(
				"dependency identity mismatch for %s: version=%q replace=%q",
				dependency.Path,
				dependency.Version,
				replacement,
			)
		}
		delete(expected, dependency.Path)
	}
	if len(expected) != 0 {
		return protocol.RuntimeIdentity{}, fmt.Errorf("required runtime dependencies are missing from build identity: %v", expected)
	}

	settings := make(map[string]string, len(info.Settings))
	for _, setting := range info.Settings {
		settings[setting.Key] = setting.Value
	}
	for key, expectedValue := range map[string]string{
		"CGO_ENABLED": "0",
		"GOARCH":      "amd64",
		"GOOS":        "linux",
		"GOAMD64":     "v1",
	} {
		if settings[key] != expectedValue {
			return protocol.RuntimeIdentity{}, fmt.Errorf(
				"build setting %s=%q expected %q",
				key,
				settings[key],
				expectedValue,
			)
		}
	}
	if _, present := settings["vcs.revision"]; present {
		return protocol.RuntimeIdentity{}, fmt.Errorf("sidecar unexpectedly contains VCS build metadata")
	}

	return protocol.RuntimeIdentity{
		Implementation:        "visa_wacogo",
		ImplementationVersion: implementationVersion,
		Engine:                "partite-ai/wacogo+wazero",
		EngineVersion:         engineVersion,
		WacogoVersion:         wacogoVersion,
		WacogoRevision:        wacogoRevision,
		PatchsetSHA256:        patchsetSHA256,
		PatchedTreeSHA256:     patchedTreeSHA256,
		WazeroVersion:         wazeroVersion,
		GoVersion:             requiredGoVersion,
		Target:                runtime.GOOS + "/" + runtime.GOARCH,
		MainModule:            mainModule,
	}, nil
}
