using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;

const string ComponentSha256 =
    "4d8c99fbe7475aa02983592f55a8cfdc4260753aec75de74e18a19ec47813e3b";
const string WitSha256 =
    "709eb08784d446068bbaed47dbfb1dddd637f957cf5de1f3713d5be0aa7d5920";

if (args.Length != 3)
{
    Console.Error.WriteLine("usage: wacs-aot-inspect COMPONENT WORLD_WIT ASSEMBLY");
    return 64;
}

VerifyInput("component", args[0], ComponentSha256);
VerifyInput("world-wit", args[1], WitSha256);

using var assemblyStream = File.OpenRead(args[2]);
using var peReader = new PEReader(assemblyStream);
if (!peReader.HasMetadata)
{
    Console.Error.WriteLine("assembly has no CLI metadata");
    return 1;
}

var metadata = peReader.GetMetadataReader();
var publicTypes = new Dictionary<string, Dictionary<string, string>>(StringComparer.Ordinal);
foreach (var typeHandle in metadata.TypeDefinitions)
{
    var type = metadata.GetTypeDefinition(typeHandle);
    if ((type.Attributes & TypeAttributes.VisibilityMask) is not
        (TypeAttributes.Public or TypeAttributes.NestedPublic))
    {
        continue;
    }

    var namespaceName = metadata.GetString(type.Namespace);
    var typeName = metadata.GetString(type.Name);
    var qualifiedName = string.IsNullOrEmpty(namespaceName)
        ? typeName
        : $"{namespaceName}.{typeName}";
    var methods = new Dictionary<string, string>(StringComparer.Ordinal);
    publicTypes.Add(qualifiedName, methods);

    foreach (var methodHandle in type.GetMethods())
    {
        var method = metadata.GetMethodDefinition(methodHandle);
        if ((method.Attributes & MethodAttributes.MemberAccessMask) != MethodAttributes.Public)
        {
            continue;
        }

        var methodName = metadata.GetString(method.Name);
        var signature = Convert.ToHexString(metadata.GetBlobBytes(method.Signature)).ToLowerInvariant();
        methods.Add(methodName, signature);
    }
}

var imports = RequireType(publicTypes, "CompiledWasm.WasmModule.IImports");
var expectedImports = new[]
{
    "visa_continuity_key_value_0_1_0__method_namespace_conditional_put",
    "visa_continuity_key_value_0_1_0__method_namespace_read",
    "visa_continuity_key_value_0_1_0__resource_drop_namespace",
    "visa_continuity_timers_0_1_0__method_timer_binding_arm",
    "visa_continuity_timers_0_1_0__method_timer_binding_cancel",
    "visa_continuity_timers_0_1_0__resource_drop_timer_binding",
};
RequireExactNames("core imports", imports.Keys, expectedImports);

var exports = RequireType(publicTypes, "CompiledWasm.WasmModule.IExports");
var workloadExports = new[]
{
    "activate",
    "cancel_pending",
    "freeze",
    "restore",
    "status",
    "thaw",
    "timer_fired",
};
foreach (var export in workloadExports)
{
    RequireMethod(exports, $"visa_continuity_workload_0_1_0_{export}");
}

var activateSignature = RequireMethod(
    exports,
    "visa_continuity_workload_0_1_0_activate"
);
if (activateSignature != "20010808")
{
    throw new InvalidDataException(
        $"unexpected raw activate signature: expected 20010808, observed {activateSignature}"
    );
}

var typedMethodNames = new HashSet<string>(
    new[] { "Activate", "CancelPending", "Freeze", "Restore", "Status", "Thaw", "TimerFired" },
    StringComparer.Ordinal
);
var typedWorkloadMethods = publicTypes
    .Where(entry => entry.Key is not
        ("CompiledWasm.WasmModule.Functions" or
         "CompiledWasm.WasmModule.IExports" or
         "CompiledWasm.WasmModule.Module"))
    .SelectMany(entry => entry.Value.Keys)
    .Where(typedMethodNames.Contains)
    .ToArray();
if (typedWorkloadMethods.Length != 0)
{
    throw new InvalidDataException(
        $"unexpected typed workload methods: {string.Join(", ", typedWorkloadMethods)}"
    );
}

Console.WriteLine($"aot-assembly-bytes={assemblyStream.Length}");
Console.WriteLine($"public-types={publicTypes.Count}");
Console.WriteLine($"core-imports={imports.Count}");
Console.WriteLine($"raw-workload-exports={workloadExports.Length}");
Console.WriteLine($"raw-activate-signature={activateSignature}");
Console.WriteLine("typed-workload-surface=absent");
return 0;

static void VerifyInput(string label, string path, string expectedSha256)
{
    using var stream = File.OpenRead(path);
    var digest = Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
    if (!string.Equals(digest, expectedSha256, StringComparison.Ordinal))
    {
        throw new InvalidDataException(
            $"{label} SHA-256 mismatch: expected {expectedSha256}, observed {digest}"
        );
    }

    Console.WriteLine($"{label}-sha256={digest}");
}

static Dictionary<string, string> RequireType(
    Dictionary<string, Dictionary<string, string>> publicTypes,
    string typeName)
{
    if (!publicTypes.TryGetValue(typeName, out var methods))
    {
        throw new InvalidDataException($"missing public type {typeName}");
    }

    return methods;
}

static string RequireMethod(Dictionary<string, string> methods, string methodName)
{
    if (!methods.TryGetValue(methodName, out var signature))
    {
        throw new InvalidDataException($"missing public method {methodName}");
    }

    return signature;
}

static void RequireExactNames(
    string label,
    IEnumerable<string> observedNames,
    IEnumerable<string> expectedNames)
{
    var observed = observedNames.Order(StringComparer.Ordinal).ToArray();
    var expected = expectedNames.Order(StringComparer.Ordinal).ToArray();
    if (!observed.SequenceEqual(expected, StringComparer.Ordinal))
    {
        throw new InvalidDataException(
            $"unexpected {label}: expected [{string.Join(", ", expected)}], " +
            $"observed [{string.Join(", ", observed)}]"
        );
    }
}
