# Shared child launcher for Go, Rust, and C++; environment settings belong only to the child launch.
# Preserve the caller's environment and working directory, and never write user or system settings.
param(
    [Parameter(Mandatory = $true)][string]$Executable,
    [Parameter(Mandatory = $true)][string]$WorkingDirectory,
    [Parameter(Mandatory = $true)][hashtable]$Environment,
    [string[]]$ToolArguments = @(),
    [string]$CancellationFile
)

$ErrorActionPreference = 'Stop'
$startInfo = [System.Diagnostics.ProcessStartInfo]::new()
$startInfo.FileName = (Get-Command $Executable -CommandType Application -ErrorAction Stop).Source
$startInfo.WorkingDirectory = $WorkingDirectory
$startInfo.UseShellExecute = $false
$startInfo.CreateNoWindow = $true
$startInfo.RedirectStandardOutput = $true
$startInfo.StandardOutputEncoding = [Text.UTF8Encoding]::new($false)
foreach ($entry in $Environment.GetEnumerator()) {
    $startInfo.EnvironmentVariables[$entry.Key] = $entry.Value
}

# PowerShell 7 uses native argument lists; Windows PowerShell 5.1 requires Windows command-line escaping.
# Preserve empty arguments, spaces, embedded quotes, and trailing backslashes without cmd or shell interpolation.
if ($null -ne $startInfo.PSObject.Properties['ArgumentList']) {
    foreach ($argument in $ToolArguments) { $startInfo.ArgumentList.Add($argument) }
} else {
    $startInfo.Arguments = ($ToolArguments | ForEach-Object {
        '"' + ($_ -replace '(\\*)"', '$1$1\"' -replace '(\\+)$', '$1$1') + '"'
    }) -join ' '
}

# Stream stdout line by line for PowerShell pipelines; inherit stderr and stdin directly from the parent.
# Do not buffer the entire build log; return the tool's original exit code.
$originalEncoding = [Console]::OutputEncoding
$process = $null
try {
    [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
    $process = [System.Diagnostics.Process]::Start($startInfo)
    while ($true) {
        $verdandiRead = $process.StandardOutput.ReadLineAsync()
        while (-not $verdandiRead.IsCompleted) { Start-Sleep -Milliseconds 100 }
        $line = $verdandiRead.GetAwaiter().GetResult()
        if ($null -eq $line) { break }
        Write-Output $line
    }
    $process.WaitForExit()
    exit $process.ExitCode
} finally {
    if ($null -ne $process) {
        if ($CancellationFile -and -not $process.HasExited) {
            [IO.File]::WriteAllText($CancellationFile, 'cancel')
            if (-not $process.WaitForExit(60000)) { $process.Kill() }
        }
        $process.Dispose()
    }
    [Console]::OutputEncoding = $originalEncoding
}
