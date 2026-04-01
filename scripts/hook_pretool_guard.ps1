$ErrorActionPreference = "Stop"

try {
    $inputJson = [Console]::In.ReadToEnd()
    if ([string]::IsNullOrWhiteSpace($inputJson)) {
        exit 0
    }

    $payload = $inputJson | ConvertFrom-Json -Depth 20
    $toolName = ""
    if ($null -ne $payload.toolName) {
        $toolName = [string]$payload.toolName
    }

    $commandText = ""
    if ($null -ne $payload.toolInput -and $null -ne $payload.toolInput.command) {
        $commandText = [string]$payload.toolInput.command
    }

    $blockedPatterns = @(
        "git reset --hard",
        "git checkout --",
        "rm -rf",
        "Remove-Item -Recurse -Force"
    )

    foreach ($pattern in $blockedPatterns) {
        if (-not [string]::IsNullOrWhiteSpace($commandText) -and $commandText -like "*$pattern*") {
            $deny = @{
                hookSpecificOutput = @{
                    hookEventName = "PreToolUse"
                    permissionDecision = "deny"
                    permissionDecisionReason = "Blocked destructive command pattern: $pattern"
                }
            }
            $deny | ConvertTo-Json -Compress
            exit 0
        }
    }

    $corePathHints = @(
        "cmd/scanner/main.go",
        "internal/engine/engine.go",
        "internal/engine/rules.go",
        "internal/reporter/reporter.go"
    )

    foreach ($hint in $corePathHints) {
        if ($commandText -like "*$hint*") {
            $ask = @{
                hookSpecificOutput = @{
                    hookEventName = "PreToolUse"
                    permissionDecision = "ask"
                    permissionDecisionReason = "Editing scanner core file. Consider running tests target scan after changes."
                }
            }
            $ask | ConvertTo-Json -Compress
            exit 0
        }
    }

    exit 0
}
catch {
    Write-Warning "pretool guard hook failed: $($_.Exception.Message)"
    exit 0
}
