using Wacs.ComponentModel.Runtime.Parser;
using Wacs.Core;
using System.Security.Cryptography;

const string ComponentSha256 =
    "4d8c99fbe7475aa02983592f55a8cfdc4260753aec75de74e18a19ec47813e3b";
const string WitSha256 =
    "709eb08784d446068bbaed47dbfb1dddd637f957cf5de1f3713d5be0aa7d5920";

if (args.Length != 2)
{
    Console.Error.WriteLine("usage: wacs-decode COMPONENT WORLD_WIT");
    return 64;
}

var bytes = File.ReadAllBytes(args[0]);
VerifyBytes("component", bytes, ComponentSha256);
VerifyBytes("world-wit", File.ReadAllBytes(args[1]), WitSha256);
if (bytes.Length != 146486)
{
    throw new InvalidDataException(
        $"component length mismatch: expected 146486, observed {bytes.Length}"
    );
}

Console.WriteLine($"component-bytes={bytes.Length}");
using var stream = new MemoryStream(bytes);
var component = ComponentBinaryParser.Parse(stream);
Console.WriteLine(
    $"core-modules={component.CoreModuleBinaries.Count()} nested={component.NestedComponentCount}"
);

var moduleIndex = 0;
foreach (var coreBytes in component.CoreModuleBinaries)
{
    using var coreStream = new MemoryStream(coreBytes);
    var core = BinaryModuleParser.ParseWasm(coreStream);
    Console.WriteLine($"core[{moduleIndex}] imports={core.Imports.Length} exports={core.Exports.Length}");
    foreach (var import in core.Imports)
    {
        Console.WriteLine(
            $"  import module={import.ModuleName} name={import.Name} desc={import.Desc}"
        );
    }
    moduleIndex += 1;
}

foreach (var export in component.Exports)
{
    Console.WriteLine($"export name={export.Name} sort={export.Sort} index={export.Index}");
}

return 0;

static void VerifyBytes(string label, byte[] bytes, string expectedSha256)
{
    var digest = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    if (!string.Equals(digest, expectedSha256, StringComparison.Ordinal))
    {
        throw new InvalidDataException(
            $"{label} SHA-256 mismatch: expected {expectedSha256}, observed {digest}"
        );
    }

    Console.WriteLine($"{label}-sha256={digest}");
}
