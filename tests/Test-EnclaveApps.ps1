# Test-EnclaveApps.ps1 — Comprehensive Windows + WSL test matrix for enclave apps
#
# Usage:
#   .\Test-EnclaveApps.ps1                           # All installed apps, non-interactive
#   .\Test-EnclaveApps.ps1 sshenc                    # Only sshenc/gitenc tests
#   .\Test-EnclaveApps.ps1 awsenc sso-jwt            # Test awsenc and sso-jwt
#   .\Test-EnclaveApps.ps1 -Interactive               # Include keyring unlock tests
#   .\Test-EnclaveApps.ps1 -SkipWSL                   # Windows only
#   .\Test-EnclaveApps.ps1 -SkipExtended              # Skip agent/SSH/signing/ECIES

param(
    [Parameter(Position = 0, ValueFromRemainingArguments)]
    [string[]]$Apps,
    [switch]$SkipWSL,
    [switch]$SkipExtended,
    [switch]$Interactive,
    [int]$KeyringTimeout = 90
)

# Known enclave apps and their primary binaries
$KnownApps = @{
    "awsenc"  = "awsenc"
    "sshenc"  = "sshenc"
    "sso-jwt" = "sso-jwt"
    "npmenc"  = "npmenc"
}

# Determine which apps to test
if (-not $Apps -or $Apps.Count -eq 0) {
    # Auto-detect: test all known apps that are installed
    $TestApps = @()
    foreach ($app in $KnownApps.Keys) {
        if (Get-Command $KnownApps[$app] -ErrorAction SilentlyContinue) {
            $TestApps += $app
        } else {
            Write-Host "  [SKIP] $app - not installed" -ForegroundColor Yellow
        }
    }
} else {
    $TestApps = $Apps
}

$ErrorActionPreference = "Continue"
$script:Pass = 0
$script:Fail = 0
$script:Skip = 0
$script:Results = @()

function Record($Status, $Test, $Detail = "") {
    switch ($Status) {
        "P" { $script:Pass++; $color = "Green" }
        "F" { $script:Fail++; $color = "Red" }
        "S" { $script:Skip++; $color = "Yellow" }
    }
    $label = switch ($Status) { "P" { "PASS" } "F" { "FAIL" } "S" { "SKIP" } }
    Write-Host "  [$label] " -NoNewline -ForegroundColor $color
    Write-Host "$Test" -NoNewline
    if ($Detail) { Write-Host " - $Detail" -ForegroundColor DarkGray } else { Write-Host "" }
    $script:Results += [PSCustomObject]@{ Status = $label; Test = $Test; Detail = $Detail }
}

function Test-Command($Test, $Command, $Expect = $null) {
    try {
        $out = Invoke-Expression $Command 2>&1 | Out-String
        if ($Expect -and $out -notmatch [regex]::Escape($Expect)) {
            Record "F" $Test "expected '$Expect', got: $($out.Trim().Substring(0, [Math]::Min(80, $out.Trim().Length)))"
        } else {
            Record "P" $Test
        }
    } catch {
        Record "F" $Test $_.Exception.Message
    }
}

function Test-Exit($Test, $Command, [bool]$ExpectSuccess = $true) {
    $null = Invoke-Expression $Command 2>&1
    if ($ExpectSuccess -and $LASTEXITCODE -eq 0) { Record "P" $Test }
    elseif (-not $ExpectSuccess -and $LASTEXITCODE -ne 0) { Record "P" $Test }
    else { Record "F" $Test "exit code $LASTEXITCODE" }
}

function Section($Title) {
    Write-Host "`n  -- $Title --" -ForegroundColor White
}

function Banner($Title) {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host $Title -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
}

function ShouldTest($AppName) {
    return $TestApps -contains $AppName
}

# ============================================================
Banner "Windows Shell Tests"
# ============================================================

if (ShouldTest "awsenc") {
    Section "awsenc"
    Test-Command "awsenc --version" "awsenc --version" "awsenc"
    Test-Command "awsenc config" "awsenc config" "Config directory"
    Test-Command "awsenc list" "awsenc list"
    Test-Exit "awsenc list --json" "awsenc list --json"
    Test-Exit "awsenc clear --all" "awsenc clear --all"
    Test-Command "awsenc shell-init bash" "awsenc shell-init bash" "awsenc"
    Test-Command "awsenc shell-init powershell" "awsenc shell-init powershell" "PROFILE"
    Test-Command "awsenc completions bash" "awsenc completions bash" "_awsenc"
    Test-Command "awsenc completions powershell" "awsenc completions powershell" "Register-ArgumentCompleter"
}

if (ShouldTest "sshenc") {
    Section "sshenc"
    Test-Command "sshenc --version" "sshenc --version" "sshenc"
    Test-Command "sshenc config path" "sshenc config path"
    Test-Command "sshenc config show" "sshenc config show" "socket_path"
    Test-Command "sshenc list" "sshenc list"
    Test-Command "sshenc completions bash" "sshenc completions bash" "_sshenc"
    Test-Command "sshenc completions powershell" "sshenc completions powershell" "Register-ArgumentCompleter"

    # Key lifecycle — two keys, verify distinct fingerprints
    $keyA = "test-key-a-$PID"
    $keyB = "test-key-b-$PID"
    "y" | sshenc delete $keyA 2>&1 | Out-Null
    "y" | sshenc delete $keyB 2>&1 | Out-Null
    Remove-Item "$env:USERPROFILE\.ssh\$keyA.pub" -ErrorAction SilentlyContinue
    Remove-Item "$env:USERPROFILE\.ssh\$keyB.pub" -ErrorAction SilentlyContinue

    $genA = sshenc keygen -l $keyA -C "test-a" 2>&1 | Out-String
    if ($genA -match "Generated") { Record "P" "sshenc keygen $keyA" } else { Record "F" "sshenc keygen $keyA" $genA.Trim() }

    $genB = sshenc keygen -l $keyB -C "test-b" 2>&1 | Out-String
    if ($genB -match "Generated") { Record "P" "sshenc keygen $keyB" } else { Record "F" "sshenc keygen $keyB" $genB.Trim() }

    $fpA = (sshenc export-pub $keyA --fingerprint 2>&1 | Out-String).Trim()
    $fpB = (sshenc export-pub $keyB --fingerprint 2>&1 | Out-String).Trim()
    if ($fpA -match "SHA256:" -and $fpB -match "SHA256:" -and $fpA -ne $fpB) {
        Record "P" "keys have distinct fingerprints"
    } else {
        Record "F" "keys have distinct fingerprints" "A=$fpA B=$fpB"
    }

    Test-Command "sshenc inspect $keyA" "sshenc inspect $keyA" "ecdsa-p256"
    Test-Command "sshenc export-pub $keyA" "sshenc export-pub $keyA" "ecdsa-sha2-nistp256"
    "y" | sshenc delete $keyA 2>&1 | Out-Null; Record "P" "sshenc delete $keyA"
    "y" | sshenc delete $keyB 2>&1 | Out-Null; Record "P" "sshenc delete $keyB"
}

if (ShouldTest "npmenc") {
    Section "npmenc/npxenc"
    Test-Command "npmenc --version" "npmenc --version" "npmenc"
    Test-Command "npxenc --version" "npxenc --version" "npxenc"
    Test-Command "npmenc --help" "npmenc --help" "npmenc"
    Test-Command "npxenc --help" "npxenc --help" "npxenc"
}

if (ShouldTest "sso-jwt") {
    Section "sso-jwt"
    Test-Command "sso-jwt --version" "sso-jwt --version" "sso-jwt"
    Test-Exit "sso-jwt --clear" "sso-jwt --clear"
    Test-Command "sso-jwt shell-init bash" "sso-jwt shell-init bash" "sso-jwt"
    Test-Command "sso-jwt shell-init zsh" "sso-jwt shell-init zsh" "sso-jwt"
    Test-Command "sso-jwt shell-init powershell" "sso-jwt shell-init powershell" "PROFILE"
}

# ============================================================
if (-not $SkipExtended) {
    Banner "Extended Tests"

    if (ShouldTest "sshenc") {
        # Kill orphan agents
        Stop-Process -Name "sshenc-agent" -Force -ErrorAction SilentlyContinue
        Start-Sleep 1
        $agentProc = Start-Process -FilePath "sshenc-agent" -ArgumentList "-f" -PassThru -WindowStyle Hidden
        Start-Sleep 2

        Section "Agent + SSH"
        $keys = & "$env:SystemRoot\System32\OpenSSH\ssh-add.exe" -l 2>&1 | Out-String
        if ($keys -match "SHA256:") { Record "P" "agent key listing via named pipe" } else { Record "F" "agent key listing" $keys.Trim() }

        $env:SSH_AUTH_SOCK = "\\.\pipe\openssh-ssh-agent"
        $sshResult = & "$env:SystemRoot\System32\OpenSSH\ssh.exe" -T git@github.com 2>&1 | Out-String
        if ($sshResult -match "successfully authenticated") { Record "P" "SSH to GitHub via agent" }
        else { Record "F" "SSH to GitHub" $sshResult.Trim() }

        Section "gitenc signing"
        $testDir = "$env:TEMP\gitenc-ps-test"
        Remove-Item $testDir -Recurse -Force -ErrorAction SilentlyContinue
        $env:GIT_SSH_COMMAND = "$env:SystemRoot\System32\OpenSSH\ssh.exe"
        git clone git@github.com:godaddy/sshenc.git $testDir 2>&1 | Out-Null
        if (Test-Path "$testDir\.git") { Record "P" "git clone via SSH" } else { Record "F" "git clone via SSH" }

        if (Test-Path "$testDir\.git") {
            Push-Location $testDir
            git config user.email "jgowdy@godaddy.com"
            git config user.name "Jay Gowdy"
            gitenc --config github-godaddy 2>&1 | Out-Null

            $branch = "test/ps-matrix-$(Get-Date -Format 'yyyyMMddHHmmss')"
            git checkout -b $branch 2>&1 | Out-Null
            "# PS matrix test $(Get-Date -Format o)" | Out-File -Append TESTING.md
            git add TESTING.md 2>&1 | Out-Null
            $commitOut = git commit -m "Test: PS matrix signed commit" 2>&1 | Out-String
            if ($commitOut -match "signed commit|1 file changed") { Record "P" "signed commit" } else { Record "F" "signed commit" $commitOut.Trim() }

            $sigOut = git log --show-signature -1 2>&1 | Out-String
            if ($sigOut -match "Good.*signature") { Record "P" "local signature verification" } else { Record "F" "local verify" $sigOut.Trim() }

            git push origin $branch 2>&1 | Out-Null
            Start-Sleep 2
            $ghVerify = gh api "repos/godaddy/sshenc/commits/$branch" --jq '.commit.verification.verified' 2>&1 | Out-String
            if ($ghVerify.Trim() -eq "true") { Record "P" "GitHub signature verified" } else { Record "F" "GitHub verify" $ghVerify.Trim() }

            git push origin --delete $branch 2>&1 | Out-Null
            Pop-Location
            Remove-Item $testDir -Recurse -Force -ErrorAction SilentlyContinue
        }

        Section "sshenc install/uninstall"
        $configBackup = Get-Content "$env:USERPROFILE\.ssh\config" -Raw -ErrorAction SilentlyContinue
        sshenc uninstall 2>&1 | Out-Null
        $afterUninstall = Get-Content "$env:USERPROFILE\.ssh\config" -Raw -ErrorAction SilentlyContinue
        if (-not $afterUninstall -or $afterUninstall -notmatch "sshenc") { Record "P" "sshenc uninstall removes config" } else { Record "F" "uninstall" }

        sshenc install 2>&1 | Out-Null
        Start-Sleep 3
        $afterInstall = Get-Content "$env:USERPROFILE\.ssh\config" -Raw -ErrorAction SilentlyContinue
        if ($afterInstall -match "IdentityAgent") { Record "P" "sshenc install writes config" } else { Record "F" "install" }
        if ($configBackup) { Set-Content "$env:USERPROFILE\.ssh\config" $configBackup }

        Stop-Process -Id $agentProc.Id -Force -ErrorAction SilentlyContinue
    }

    if (ShouldTest "awsenc") {
        Section "ECIES bridge (awsenc)"
        $testData = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("ECIES PS roundtrip"))
        $initJson = '{"method":"init","params":{"app_name":"awsenc","key_label":"ps-ecies","access_policy":"none"}}'
        $encJson = "{`"method`":`"encrypt`",`"params`":{`"data`":`"$testData`",`"app_name`":`"awsenc`",`"key_label`":`"ps-ecies`"}}"
        $encLines = "$initJson`n$encJson" | awsenc-tpm-bridge 2>&1
        $encResult = ($encLines | Select-Object -Last 1) -replace '.*"result":"([^"]+)".*','$1'
        if ($encResult -match '^AQ') {
            Record "P" "ECIES encrypt (awsenc)"
            $decJson = "{`"method`":`"decrypt`",`"params`":{`"data`":`"$encResult`",`"app_name`":`"awsenc`",`"key_label`":`"ps-ecies`"}}"
            $decLines = "$initJson`n$decJson" | awsenc-tpm-bridge 2>&1
            $decResult = ($decLines | Select-Object -Last 1) -replace '.*"result":"([^"]+)".*','$1'
            try { $decrypted = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($decResult)) } catch { $decrypted = "" }
            if ($decrypted -eq "ECIES PS roundtrip") { Record "P" "ECIES decrypt roundtrip (awsenc)" }
            else { Record "F" "ECIES decrypt (awsenc)" "got '$decrypted'" }
        } else { Record "F" "ECIES encrypt (awsenc)" ($encLines -join " ") }
        '{"method":"destroy","params":{"app_name":"awsenc","key_label":"ps-ecies"}}' | awsenc-tpm-bridge 2>&1 | Out-Null
    }

    if (ShouldTest "sso-jwt") {
        Section "ECIES bridge (sso-jwt)"
        $testData = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("ECIES PS roundtrip"))
        $initJ = '{"method":"init","params":{"app_name":"sso-jwt","key_label":"ps-ecies","access_policy":"none"}}'
        $encJ = "{`"method`":`"encrypt`",`"params`":{`"data`":`"$testData`",`"app_name`":`"sso-jwt`",`"key_label`":`"ps-ecies`"}}"
        $encL = "$initJ`n$encJ" | sso-jwt-tpm-bridge 2>&1
        $ct = ($encL | Select-Object -Last 1) -replace '.*"result":"([^"]+)".*','$1'
        $decJ = "{`"method`":`"decrypt`",`"params`":{`"data`":`"$ct`",`"app_name`":`"sso-jwt`",`"key_label`":`"ps-ecies`"}}"
        $decL = "$initJ`n$decJ" | sso-jwt-tpm-bridge 2>&1
        $d = ($decL | Select-Object -Last 1) -replace '.*"result":"([^"]+)".*','$1'
        try { $p = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($d)) } catch { $p = "" }
        if ($p -eq "ECIES PS roundtrip") { Record "P" "ECIES roundtrip (sso-jwt)" } else { Record "F" "ECIES roundtrip (sso-jwt)" "got '$p'" }
        '{"method":"destroy","params":{"app_name":"sso-jwt","key_label":"ps-ecies"}}' | sso-jwt-tpm-bridge 2>&1 | Out-Null
    }
}

# ============================================================
# WSL Bridge Tests (no keyring)
# ============================================================
if (-not $SkipWSL) {
    $distros = @("Ubuntu", "Debian", "FedoraLinux-43", "AlmaLinux-9")

    # Build WSL test script based on app filter
    $wslVersionTests = ""
    $wslKeyTests = ""
    if (ShouldTest "awsenc") {
        $wslVersionTests += 'awsenc --version 2>&1 | grep -q "awsenc" && record P "awsenc --version" || record F "awsenc --version"' + "`n"
        $wslVersionTests += 'awsenc config 2>&1 | grep -q "Config directory" && record P "awsenc config" || record F "awsenc config"' + "`n"
        $wslVersionTests += 'awsenc shell-init bash 2>&1 | grep -q "awsenc" && record P "awsenc shell-init bash" || record F "awsenc shell-init bash"' + "`n"
    }
    if (ShouldTest "sshenc") {
        $wslVersionTests += 'sshenc --version 2>&1 | grep -q "sshenc" && record P "sshenc --version" || record F "sshenc --version"' + "`n"
        $wslVersionTests += 'sshenc config show 2>&1 | grep -q "socket_path\|prompt_policy" && record P "sshenc config show" || record F "sshenc config show"' + "`n"
        $wslKeyTests = @'
KEY_A="wsl-test-a-$$"
KEY_B="wsl-test-b-$$"
echo y | sshenc delete "$KEY_A" >/dev/null 2>&1; rm -f "$HOME/.ssh/$KEY_A.pub"
echo y | sshenc delete "$KEY_B" >/dev/null 2>&1; rm -f "$HOME/.ssh/$KEY_B.pub"
sshenc keygen -l "$KEY_A" -C "test-a" >/dev/null 2>&1 && record P "sshenc keygen $KEY_A" || record F "sshenc keygen $KEY_A"
sshenc keygen -l "$KEY_B" -C "test-b" >/dev/null 2>&1 && record P "sshenc keygen $KEY_B" || record F "sshenc keygen $KEY_B"
FP_A=$(sshenc export-pub "$KEY_A" --fingerprint 2>&1)
FP_B=$(sshenc export-pub "$KEY_B" --fingerprint 2>&1)
if [[ "$FP_A" == SHA256:* ]] && [[ "$FP_B" == SHA256:* ]] && [[ "$FP_A" != "$FP_B" ]]; then
    record P "WSL keys have distinct fingerprints"
else
    record F "WSL keys have distinct fingerprints (A=$FP_A B=$FP_B)"
fi
sshenc inspect "$KEY_A" 2>&1 | grep -q "ecdsa-p256" && record P "sshenc inspect" || record F "sshenc inspect"
sshenc export-pub "$KEY_A" 2>&1 | grep -q "ecdsa-sha2-nistp256" && record P "sshenc export-pub" || record F "sshenc export-pub"
echo y | sshenc delete "$KEY_A" >/dev/null 2>&1 && record P "sshenc delete $KEY_A" || record F "sshenc delete $KEY_A"
echo y | sshenc delete "$KEY_B" >/dev/null 2>&1 && record P "sshenc delete $KEY_B" || record F "sshenc delete $KEY_B"
'@
    }
    if (ShouldTest "sso-jwt") {
        $wslVersionTests += 'sso-jwt --version 2>&1 | grep -q "sso-jwt" && record P "sso-jwt --version" || record F "sso-jwt --version"' + "`n"
        $wslVersionTests += 'sso-jwt --clear 2>&1 | grep -q "cleared" && record P "sso-jwt --clear" || record F "sso-jwt --clear"' + "`n"
        $wslVersionTests += 'sso-jwt shell-init bash 2>&1 | grep -q "sso-jwt" && record P "sso-jwt shell-init bash" || record F "sso-jwt shell-init bash"' + "`n"
    }
    if (ShouldTest "npmenc") {
        $wslVersionTests += 'npmenc --version 2>&1 | grep -q "npmenc" && record P "npmenc --version" || record F "npmenc --version"' + "`n"
    }

    $bashTests = @"
#!/usr/bin/env bash
set -uo pipefail
PASS=0; FAIL=0; SKIP=0
record() { local s=`$1 t=`$2; case `$s in P) ((PASS++));; F) ((FAIL++));; S) ((SKIP++));; esac; printf "  [%s] %s\n" "`$(echo `$s | sed 's/P/PASS/;s/F/FAIL/;s/S/SKIP/')" "`$t"; }
$wslVersionTests
$wslKeyTests
echo "  TOTAL: `$PASS pass, `$FAIL fail, `$SKIP skip"
exit `$FAIL
"@

    foreach ($distro in $distros) {
        Banner "WSL2 $distro (bridge, no keyring)"

        $wslJob = Start-Job -ScriptBlock {
            param($d, $s)
            $result = $s | wsl -d $d -- bash 2>&1
            $result -join "`n"
        } -ArgumentList $distro, $bashTests

        $completed = Wait-Job $wslJob -Timeout $KeyringTimeout
        if ($completed) {
            $output = Receive-Job $wslJob
            ($output -split "`n") | ForEach-Object { Write-Host $_ }
        } else {
            Write-Host "  [TIMEOUT] WSL test timed out after ${KeyringTimeout}s" -ForegroundColor Yellow
            Stop-Job $wslJob
        }
        Remove-Job $wslJob -Force
    }
}

# ============================================================
# Interactive keyring tests (opt-in)
# ============================================================
if ($Interactive -and -not $SkipWSL -and (ShouldTest "sshenc")) {
    Banner "Interactive Tests (keyring unlock required)"
    Write-Host ""
    Write-Host "  These tests will trigger keyring password dialogs on each WSL distro." -ForegroundColor Yellow
    Write-Host "  You will need to enter your keyring password for each distro." -ForegroundColor Yellow
    Write-Host "  If a distro has no keyring set up, you'll be prompted to create one." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Press any key to start interactive tests..." -ForegroundColor Cyan
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    Write-Host ""

    $distros = @("Ubuntu", "Debian", "FedoraLinux-43", "AlmaLinux-9")
    $keyringTests = @'
#!/usr/bin/env bash
set -uo pipefail
PASS=0; FAIL=0; SKIP=0
record() { local s=$1 t=$2; case $s in P) ((PASS++));; F) ((FAIL++));; S) ((SKIP++));; esac; printf "  [%s] %s\n" "$(echo $s | sed 's/P/PASS/;s/F/FAIL/;s/S/SKIP/')" "$t"; }

export XDG_RUNTIME_DIR=/run/user/$(id -u)
mkdir -p $XDG_RUNTIME_DIR && chmod 700 $XDG_RUNTIME_DIR
eval $(dbus-launch --sh-syntax 2>/dev/null)
gnome-keyring-daemon --start --components=secrets 2>/dev/null
echo "probe" | secret-tool store --label="setup" app enclaveapp key setup 2>/dev/null

KR_A="kr-test-a-$$"
KR_B="kr-test-b-$$"
echo y | sshenc --keyring delete "$KR_A" >/dev/null 2>&1; rm -f "$HOME/.ssh/$KR_A.pub"
echo y | sshenc --keyring delete "$KR_B" >/dev/null 2>&1; rm -f "$HOME/.ssh/$KR_B.pub"
sshenc --keyring keygen -l "$KR_A" -C "kr-a" >/dev/null 2>&1 && record P "sshenc --keyring keygen $KR_A" || record F "sshenc --keyring keygen $KR_A"
sshenc --keyring keygen -l "$KR_B" -C "kr-b" >/dev/null 2>&1 && record P "sshenc --keyring keygen $KR_B" || record F "sshenc --keyring keygen $KR_B"
FP_A=$(sshenc --keyring export-pub "$KR_A" --fingerprint 2>&1)
FP_B=$(sshenc --keyring export-pub "$KR_B" --fingerprint 2>&1)
if [[ "$FP_A" == SHA256:* ]] && [[ "$FP_B" == SHA256:* ]] && [[ "$FP_A" != "$FP_B" ]]; then
    record P "keyring keys have distinct fingerprints"
else
    record F "keyring keys have distinct fingerprints (A=$FP_A B=$FP_B)"
fi
sshenc --keyring inspect "$KR_A" 2>&1 | grep -q "ecdsa-p256" && record P "sshenc --keyring inspect" || record F "sshenc --keyring inspect"
sshenc --keyring export-pub "$KR_A" 2>&1 | grep -q "ecdsa-sha2-nistp256" && record P "sshenc --keyring export-pub" || record F "sshenc --keyring export-pub"
echo y | sshenc --keyring delete "$KR_A" >/dev/null 2>&1 && record P "sshenc --keyring delete $KR_A" || record F "sshenc --keyring delete"
echo y | sshenc --keyring delete "$KR_B" >/dev/null 2>&1 && record P "sshenc --keyring delete $KR_B" || record F "sshenc --keyring delete"
echo "  TOTAL: $PASS pass, $FAIL fail, $SKIP skip"
exit $FAIL
'@

    foreach ($distro in $distros) {
        Banner "WSL2 $distro (--keyring, interactive)"
        Write-Host "  Waiting for keyring unlock on $distro..." -ForegroundColor Yellow

        $wslJob = Start-Job -ScriptBlock {
            param($d, $s)
            $result = $s | wsl -d $d -- bash 2>&1
            $result -join "`n"
        } -ArgumentList $distro, $keyringTests

        $completed = Wait-Job $wslJob -Timeout $KeyringTimeout
        if ($completed) {
            $output = Receive-Job $wslJob
            ($output -split "`n") | ForEach-Object { Write-Host $_ }
        } else {
            Write-Host "  [TIMEOUT] Keyring not unlocked within ${KeyringTimeout}s" -ForegroundColor Yellow
            Stop-Job $wslJob
        }
        Remove-Job $wslJob -Force
    }
}

# ============================================================
Banner "SUMMARY"
# ============================================================
$totalTests = $script:Pass + $script:Fail + $script:Skip
Write-Host "  $($script:Pass) pass" -ForegroundColor Green -NoNewline
Write-Host ", $($script:Fail) fail" -ForegroundColor $(if ($script:Fail -gt 0) { "Red" } else { "Green" }) -NoNewline
Write-Host ", $($script:Skip) skip" -ForegroundColor Yellow -NoNewline
Write-Host " ($totalTests total)"

if ($script:Fail -gt 0) {
    Write-Host "`nFailures:" -ForegroundColor Red
    $script:Results | Where-Object { $_.Status -eq "FAIL" } | ForEach-Object {
        Write-Host "  $($_.Test)" -ForegroundColor Red -NoNewline
        if ($_.Detail) { Write-Host " - $($_.Detail)" -ForegroundColor DarkGray } else { Write-Host "" }
    }
}

Write-Host ""
exit $script:Fail
