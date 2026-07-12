package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"runtime/debug"
	"sort"
	"strings"

	"github.com/partite-ai/wacogo"
	keyvalue "visa.local/wacogo-qualification/generated/visa/continuity/keyvalue"
	timers "visa.local/wacogo-qualification/generated/visa/continuity/timers"
)

const (
	componentSHA256 = "4d8c99fbe7475aa02983592f55a8cfdc4260753aec75de74e18a19ec47813e3b"
	witSHA256       = "709eb08784d446068bbaed47dbfb1dddd637f957cf5de1f3713d5be0aa7d5920"
	wacogoVersion   = "v0.0.0-20260617023329-3de16a61796c"
	wazeroVersion   = "v1.11.1-0.20260418165552-5cb4bb3ec0c1"
	workloadName    = "visa:continuity/workload@0.1.0"
)

type keyValueHost struct{}
type timersHost struct{}

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
	kvInstance, err := kvFactory.NewInstance(ctx, keyValueHost{}, nil)
	must("instantiate key-value host interface", err)
	defer closeOrFatal("key-value instance", func() error { return kvInstance.Close(ctx) })

	timerFactory, err := timers.NewFactory(ctx, engine)
	must("build timers host interface", err)
	defer closeOrFatal("timers factory", func() error { return timerFactory.Close(ctx) })
	timerInstance, err := timerFactory.NewInstance(ctx, timersHost{}, nil)
	must("instantiate timers host interface", err)
	defer closeOrFatal("timers instance", func() error { return timerInstance.Close(ctx) })

	instance, err := componentModel.Instantiate(
		ctx,
		wacogo.WithInstanceImport(keyvalue.InterfaceName, kvInstance.Core()),
		wacogo.WithInstanceImport(timers.InterfaceName, timerInstance.Core()),
	)
	if err == nil {
		_ = instance.Close(ctx)
		fatalf("unchanged component instantiation unexpectedly passed; qualification must stop for review")
	}
	const expectedFailure = `arg "import-type-kv-error" references unresolved type 24`
	if !strings.Contains(err.Error(), expectedFailure) {
		fatalf("unexpected unchanged-component instantiation failure: %v", err)
	}
	fmt.Println("host-interface-build-and-host-instantiation=passed")
	fmt.Printf("unchanged-component-instantiation=unsupported error=%q\n", err.Error())
	fmt.Println("decision=no-go")
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
	expected := map[string]string{
		"github.com/partite-ai/wacogo":  wacogoVersion,
		"github.com/tetratelabs/wazero": wazeroVersion,
	}
	for _, dependency := range info.Deps {
		if version, ok := expected[dependency.Path]; ok {
			if dependency.Version != version || dependency.Replace != nil {
				fatalf(
					"dependency identity mismatch for %s: version=%s replacement=%v",
					dependency.Path,
					dependency.Version,
					dependency.Replace,
				)
			}
			fmt.Printf("dependency=%s@%s\n", dependency.Path, dependency.Version)
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
