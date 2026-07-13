using Wacs.ComponentModel.Harness.Lib;
using System.Security.Cryptography;

const string ComponentSha256 =
    "4d8c99fbe7475aa02983592f55a8cfdc4260753aec75de74e18a19ec47813e3b";
const string WitSha256 =
    "709eb08784d446068bbaed47dbfb1dddd637f957cf5de1f3713d5be0aa7d5920";

if (args.Length != 2)
{
    Console.Error.WriteLine("usage: wacs-harness COMPONENT WIT_DIRECTORY");
    return 64;
}

Console.WriteLine($"dotnet-runtime={Environment.Version}");

try
{
    VerifyFile("component", args[0], ComponentSha256);
    var witDirectory = Path.GetFullPath(args[1]);
    var worldPath = Path.Combine(witDirectory, "world.wit");
    var witFiles = Directory
        .EnumerateFiles(witDirectory, "*.wit", SearchOption.AllDirectories)
        .Select(Path.GetFullPath)
        .Order(StringComparer.Ordinal)
        .ToArray();
    if (witFiles.Length != 1 || !string.Equals(witFiles[0], worldPath, StringComparison.Ordinal))
    {
        throw new InvalidDataException(
            $"expected exactly {worldPath}; observed [{string.Join(", ", witFiles)}]"
        );
    }

    VerifyFile("world-wit", worldPath, WitSha256);
    var assembly = HarnessEmitter.EmitInMemory(witDirectory);
    Console.WriteLine($"emit=passed assembly={assembly.FullName}");
    return 0;
}
catch (Exception error)
{
    Console.Error.WriteLine($"emit=failed type={error.GetType().FullName}");
    Console.Error.WriteLine(error.Message);
    Console.Error.WriteLine(error.StackTrace);
    return 1;
}

static void VerifyFile(string label, string path, string expectedSha256)
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
