# Generate this standalone module's private bindings from the single shared protocol source.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Protoc,
    [Parameter(Mandatory = $true)][string]$GoPlugin,
    [Parameter(Mandatory = $true)][string]$GrpcPlugin,
    [string]$Proto = (Join-Path $PSScriptRoot '../../proto/comet.proto')
)
$ErrorActionPreference = 'Stop'
# Paths are explicit existing inputs; this entry never discovers or downloads tools.
$source = (Resolve-Path -LiteralPath $Proto).Path
$compiler = (Resolve-Path -LiteralPath $Protoc).Path
$messagePlugin = (Resolve-Path -LiteralPath $GoPlugin).Path
$servicePlugin = (Resolve-Path -LiteralPath $GrpcPlugin).Path
$module = 'github.com/eosforge/astra/comet/go'
$mapping = "Mcomet.proto=$module/internal/protocol;protocol"
$arguments = @(
    "--proto_path=$(Split-Path -Parent $source)",
    "--plugin=protoc-gen-go=$messagePlugin",
    "--plugin=protoc-gen-go-grpc=$servicePlugin",
    "--go_out=$PSScriptRoot", "--go_opt=module=$module", "--go_opt=$mapping",
    "--go-grpc_out=$PSScriptRoot", "--go-grpc_opt=module=$module", "--go-grpc_opt=$mapping",
    'comet.proto'
)
& $compiler @arguments
if ($LASTEXITCODE -ne 0) { throw "Protocol generation failed: $LASTEXITCODE" }
# Record actual generator/input provenance without updating the shared protocol or manifests.
$identity = [ordered]@{
    source = '../../proto/comet.proto'
    sha256 = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()
    protoc = (& $compiler --version)
    go = (& $messagePlugin --version)
    grpc = (& $servicePlugin --version)
    mapping = $mapping
}
$destination = Join-Path $PSScriptRoot 'internal/protocol/generation.json'
[IO.File]::WriteAllText($destination, (($identity | ConvertTo-Json) + "`n"), [Text.UTF8Encoding]::new($false))
