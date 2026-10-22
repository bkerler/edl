"""Test consent and elevation decisions without installing host software."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


@unittest.skipUnless(os.name == "nt", "Windows bootstrap controls")
class WindowsControlTests(unittest.TestCase):
    def check_script(self, body):
        with tempfile.TemporaryDirectory(prefix="edl-windows-controls-") as directory:
            work = Path(directory)
            script = work / "control-test.ps1"
            source = str(ROOT / "install_edl_win10_win11.ps1").replace("'", "''")
            target = str(work).replace("'", "''")
            script.write_text(
                "$ErrorActionPreference = 'Stop'\n. '" + source + "'\n$work = '" + target + "'\n"
                "function Assert($Value, $Message) { if (-not $Value) { throw $Message } }\n"
                + body + "\nWrite-Output 'control-check-complete'\n", encoding="utf-8-sig")
            result = subprocess.run(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script)],
                                    capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(result.stdout.splitlines()[-1], "control-check-complete")

    def test_python_y_n_and_path(self):
        self.check_script(r'''
function Find-CompatiblePython { return $null }
function Test-CompatiblePython($Candidate) { if ($Candidate -eq 'C:\chosen\python.exe') { return $Candidate } }
function Install-GlobalPython { $script:installs++; return 'C:\managed\python.exe' }
function Start-Process { throw 'Python selection must not elevate' }
function Read-Host { return $script:answer }
$script:installs = 0
$script:answer = 'n'
$cancelled = $false
try { Resolve-InstallerPython '' $false } catch { $cancelled = $_ -like '*cancelled*' }
Assert $cancelled 'N did not cancel'
Assert ($script:installs -eq 0) 'N installed global Python'
$script:answer = 'C:\chosen\python.exe'
Assert ((Resolve-InstallerPython '' $false) -eq $script:answer) 'Explicit Python path was not used'
Assert ($script:installs -eq 0) 'Path selection installed Python'
$script:answer = 'y'
Assert ((Resolve-InstallerPython '' $false) -eq 'C:\managed\python.exe') 'y did not select managed Python'
Assert ($script:installs -eq 1) 'y did not request exactly one global install'
function Read-Host { throw 'Unattended mode prompted' }
$rejected = $false
try { Resolve-InstallerPython '' $true } catch { $rejected = $_ -like '*Supply -Python*' }
Assert $rejected 'Unattended mode did not reject missing Python'
Assert ($script:installs -eq 1) 'Unattended mode installed Python'
''')

    def test_official_manager_install_commands(self):
        self.check_script(r'''
$script:managerInstalled = $false
$script:runtimeInstalled = $false
function Find-PythonManager { if ($script:managerInstalled) { return 'Mock-Manager' } }
function Get-Command { [CmdletBinding()]param($Name) if ($Name -eq 'winget') { return $null }; throw 'Unexpected command lookup' }
function Add-AppxPackage($AppInstallerFile) {
    Assert ($AppInstallerFile -eq 'https://www.python.org/ftp/python/pymanager/pymanager.appinstaller') 'Not the official Python manager feed'
    $script:managerInstalled = $true
}
function Mock-Manager {
    if ($args[0] -eq 'install') {
        Assert ($args[1] -eq '3.14') 'Unexpected runtime request'
        $script:runtimeInstalled = $true
    } elseif ($args[0] -eq 'list') {
        Assert ($args[1] -eq '--format=exe') 'Runtime path was not requested explicitly'
        return 'C:\managed\python.exe'
    } else { throw 'Unexpected manager command' }
    $global:LASTEXITCODE = 0
}
function Test-CompatiblePython($Candidate) { return $Candidate }
function Start-Process { throw 'Manager installation must not elevate' }
Assert ((Install-GlobalPython) -eq 'C:\managed\python.exe') 'Managed Python path was lost'
Assert $script:managerInstalled 'Official manager was not installed'
Assert $script:runtimeInstalled 'Runtime was not installed'
''')

    def test_probe_disables_implicit_install_and_restores_environment(self):
        self.check_script(r'''
$probe = Join-Path $work 'probe.cmd'
$state = Join-Path $work 'probe-state.txt'
$code = '@echo off' + "`r`n" + 'echo %PYTHON_MANAGER_AUTOMATIC_INSTALL%>"' + $state + '"' + "`r`nexit /b 1`r`n"
[IO.File]::WriteAllText($probe, $code)
$env:PYTHON_MANAGER_AUTOMATIC_INSTALL = 'true'
$env:PYLAUNCHER_ALLOW_INSTALL = '1'
Assert (-not (Test-CompatiblePython $probe)) 'Invalid Python was accepted'
Assert ((Get-Content -LiteralPath $state).Trim() -eq 'false') 'Probe permitted an implicit global install'
Assert ($env:PYTHON_MANAGER_AUTOMATIC_INSTALL -eq 'true') 'Probe changed caller environment'
Assert ($env:PYLAUNCHER_ALLOW_INSTALL -eq '1') 'Probe lost launcher configuration'
Assert (-not (Test-CompatiblePython 'C:\Users\test\AppData\Local\Microsoft\WindowsApps\python.exe')) 'Store stub was invoked'
''')

    def test_existing_zadig_decline_and_consent(self):
        self.check_script(r'''
$script:installed = $true
$script:installs = 0
function Test-Zadig { return $script:installed }
function Install-Zadig { $script:installs++ }
function Read-Host { return $script:answer }
Ensure-UsbDriver $false
Assert ($script:installs -eq 0) 'Existing Zadig was reinstalled'
$script:installed = $false
$script:answer = 'n'
Ensure-UsbDriver $false
Assert ($script:installs -eq 0) 'Declining installed Zadig'
$script:answer = 'y'
Ensure-UsbDriver $false
Assert ($script:installs -eq 1) 'Zadig consent was ignored'
$rejected = $false
try { Ensure-UsbDriver $true } catch { $rejected = $_ -like '*Zadig is unavailable*' }
Assert $rejected 'Unattended mode installed missing Zadig'
Assert ($script:installs -eq 1) 'Unattended mode installed Zadig'
''')

    def test_zadig_install_uses_only_winget(self):
        self.check_script(r'''
$script:installs = 0
function Get-Command { [CmdletBinding()]param($Name) if ($Name -eq 'winget') { return 'winget' }; throw 'Unexpected command lookup' }
function winget {
    Assert ($args[0] -eq 'install') 'Unexpected WinGet command'
    Assert (($args -join ' ') -like '*--id akeo.ie.Zadig --exact --source winget*') 'Not the upstream Zadig package'
    Assert ($args -contains '--no-upgrade') 'Existing Zadig could be upgraded unnecessarily'
    Assert ($args -contains '--disable-interactivity') 'WinGet may wait for hidden input'
    $script:installs++
    $global:LASTEXITCODE = 0
}
function Start-Process { throw 'The bootstrap must not elevate itself or launch another driver installer' }
function Invoke-InstallerHttp { throw 'The bootstrap must not download an alternative driver' }
Install-Zadig
Assert ($script:installs -eq 1) 'Expected one WinGet Zadig installation'
function winget { $global:LASTEXITCODE = 1 }
$failed = $false
try { Install-Zadig } catch { $failed = $_ -like '*Zadig with WinGet failed*' }
Assert $failed 'Failed WinGet installation was treated as success'
function Get-Command { [CmdletBinding()]param($Name) return $null }
$failed = $false
try { Install-Zadig } catch { $failed = $_ -like '*WinGet is unavailable*' }
Assert $failed 'Missing WinGet was not explained'
''')

    def test_detect_zadig_without_assuming_a_device_driver(self):
        self.check_script(r'''
$script:inPath = $true
function Get-Command {
    [CmdletBinding()]param($Name)
    if ($Name -eq 'zadig' -and $script:inPath) { return 'zadig' }
    if ($Name -eq 'winget') { return 'winget' }
}
function winget {
    Assert (($args -join ' ') -like 'list --id akeo.ie.Zadig --exact --source winget*') 'Unexpected package detection'
    $global:LASTEXITCODE = $script:packageStatus
}
function Get-PnpDevice { throw 'A fixed VID/PID must not be used as proof of USB readiness' }
Assert (Test-Zadig) 'Zadig in PATH was not detected'
$script:inPath = $false
$script:packageStatus = 0
Assert (Test-Zadig) 'WinGet-installed Zadig was not detected'
$script:packageStatus = 1
Assert (-not (Test-Zadig)) 'Missing Zadig was reported as present'
''')

    def test_archive_fallback_preserves_the_running_installer(self):
        self.check_script(r'''
$target = Join-Path $work 'install here'
$archiveRoot = Join-Path $work 'edl-master'
New-Item -ItemType Directory -Path $target, "$archiveRoot\edlclient" | Out-Null
[IO.File]::WriteAllText("$archiveRoot\pyproject.toml", "[project]`nname = 'edlclient'`n")
[IO.File]::WriteAllText("$archiveRoot\install.py", '# shared installer')
[IO.File]::WriteAllText("$archiveRoot\install_edl_win10_win11.ps1", '# archived copy')
$script:InstallerPath = Join-Path $target 'install_edl_win10_win11.ps1'
[IO.File]::WriteAllText($script:InstallerPath, '# running downloaded script')
Compress-Archive -Path $archiveRoot -DestinationPath "$work\fixture.zip"
function Get-Command { [CmdletBinding()]param($Name) if ($Name -eq 'git') { return $null }; throw 'Unexpected command lookup' }
function Invoke-InstallerHttp($Uri, $OutFile) {
    Assert ($Uri -eq 'https://github.com/bkerler/edl/archive/refs/heads/master.zip') 'Unexpected source download'
    Copy-Item -LiteralPath "$work\fixture.zip" -Destination $OutFile
}
Get-EdlCheckout $target 'https://github.com/bkerler/edl.git'
Assert (Test-Path -LiteralPath "$target\install.py") 'Archive contents were not installed in the current directory'
Assert ((Get-Content -LiteralPath $script:InstallerPath) -eq '# running downloaded script') 'Running installer was replaced'
Assert (-not (Get-ChildItem -LiteralPath $target -Filter '.edl-stage-*' -Force)) 'Staging directory was not cleaned'
''')

    def test_checkout_rolls_back_and_recovers_a_killed_publisher(self):
        self.check_script(r'''
$bootstrap = $InstallerPath
$target = Join-Path $work 'checkout target'
$archiveRoot = Join-Path $work 'edl-master'
New-Item -ItemType Directory -Path $target, "$archiveRoot\edlclient" | Out-Null
[IO.File]::WriteAllText("$archiveRoot\pyproject.toml", "[project]`nname = 'edlclient'`n")
[IO.File]::WriteAllText("$archiveRoot\install.py", '# installer')
[IO.File]::WriteAllText("$archiveRoot\zz-payload.bin", 'complete source')
$script:InstallerPath = Join-Path $target 'install_edl_win10_win11.ps1'
[IO.File]::WriteAllText($script:InstallerPath, '# running installer')
Compress-Archive -Path $archiveRoot -DestinationPath "$work\source.zip"
function Get-Command { [CmdletBinding()]param($Name) return $null }
function Invoke-InstallerHttp($Uri, $OutFile) { [IO.File]::Copy("$work\source.zip", $OutFile) }
$script:moves = 0
$script:failMove = $true
function Move-Item {
    [CmdletBinding()]param($LiteralPath, $Destination)
    Microsoft.PowerShell.Management\Move-Item -LiteralPath $LiteralPath -Destination $Destination
    if ((Split-Path -Parent $Destination) -eq $target) {
        $script:moves++
        if ($script:failMove -and $script:moves -eq 2) { $script:failMove = $false; throw 'Simulated move failure' }
    }
}
$failed = $false
try { Get-EdlCheckout $target 'https://github.com/bkerler/edl.git' } catch { $failure = $_; $failed = $_ -like '*Simulated move failure*' }
Assert $failed "Move failure was hidden: $failure"
Assert (@(Get-ChildItem -LiteralPath $target -Force).Count -eq 1) 'Failed publication left partial source or state'
Assert ((Get-Content -LiteralPath $script:InstallerPath) -eq '# running installer') 'Rollback changed the running installer'
$worker = @'
param($Installer, $Target, $Archive)
. $Installer
$script:InstallerPath = Join-Path $Target 'install_edl_win10_win11.ps1'
function Get-Command { [CmdletBinding()]param($Name) return $null }
function Invoke-InstallerHttp($Uri, $OutFile) { [IO.File]::Copy($Archive, $OutFile) }
function Move-Item {
    [CmdletBinding()]param($LiteralPath, $Destination)
    Microsoft.PowerShell.Management\Move-Item -LiteralPath $LiteralPath -Destination $Destination
    if ((Split-Path -Parent $Destination) -eq $Target -and (Test-EdlCheckout $Target)) {
        [Diagnostics.Process]::GetCurrentProcess().Kill()
    }
}
Get-EdlCheckout $Target 'https://github.com/bkerler/edl.git'
'@
[IO.File]::WriteAllText("$work\killed-publisher.ps1", $worker)
$process = Start-Process -FilePath powershell.exe -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$work\killed-publisher.ps1`"", "`"$bootstrap`"", "`"$target`"", "`"$work\source.zip`"") -WindowStyle Hidden -Wait -PassThru
Assert ($process.ExitCode -ne 0) 'Publisher was not killed'
Assert (Test-EdlCheckout $target) 'Fixture did not reach a valid-looking partial checkout'
Assert (Test-Path -LiteralPath "$target\.edl-checkout-state\plan.json") 'Killed publisher lost its recovery plan'
Get-EdlCheckout $target 'https://github.com/bkerler/edl.git'
Assert ((Get-Content -LiteralPath "$target\zz-payload.bin") -eq 'complete source') 'Retry did not publish complete source'
Assert (-not (Test-Path -LiteralPath "$target\.edl-checkout-state")) 'Retry left checkout state'
Assert ((Get-Content -LiteralPath $script:InstallerPath) -eq '# running installer') 'Recovery changed the running installer'
# Interrupted cleanup of a committed checkout must not roll its source back.
New-Item -ItemType Directory -Path "$target\.edl-checkout-state" | Out-Null
[IO.File]::WriteAllText("$target\.edl-checkout-state\committed", 'edl-checkout-v1')
[IO.File]::WriteAllText("$target\.edl-checkout-state\plan.json", '["pyproject.toml", "edlclient"]')
function Invoke-InstallerHttp { throw 'Committed checkout was downloaded again' }
Get-EdlCheckout $target 'https://github.com/bkerler/edl.git'
Assert (Test-EdlCheckout $target) 'Committed source was rolled back during cleanup recovery'
Assert (-not (Test-Path -LiteralPath "$target\.edl-checkout-state")) 'Committed state was not cleaned'
''')

    def test_invalid_target_rejected_before_python_selection(self):
        self.check_script(r'''
$target = Join-Path $work 'other project'
New-Item -ItemType Directory -Path $target | Out-Null
[IO.File]::WriteAllText("$target\keep.txt", 'original contents')
Set-Location -LiteralPath $target
$script:pythonChecks = 0
function Find-CompatiblePython { $script:pythonChecks++; return $null }
function Read-Host { throw 'A global Python install was offered for an invalid target' }
function Install-GlobalPython { throw 'Global Python install was attempted for an invalid target' }
function Get-EdlCheckout { throw 'Source download was attempted for an invalid target' }
$rejected = $false
try { Invoke-EdlInstaller } catch { $rejected = $_ -like '*contains other files*' }
Assert $rejected 'Invalid target was not rejected before Python selection'
Assert ($script:pythonChecks -eq 0) 'Python selection started for an invalid target'
Assert ((Get-Content -LiteralPath "$target\keep.txt") -eq 'original contents') 'Existing file was changed'
Assert (@(Get-ChildItem -LiteralPath $target -Force).Count -eq 1) 'Preflight created files'
''')

    def test_cancel_before_source_download(self):
        self.check_script(r'''
function Find-CompatiblePython { return $null }
function Read-Host { return 'n' }
function Get-EdlCheckout { throw 'Source download was attempted before Python consent' }
function Ensure-UsbDriver { throw 'Driver setup ran after cancellation' }
foreach ($name in @('empty', 'downloaded installer')) {
    $target = Join-Path $work $name
    New-Item -ItemType Directory -Path $target | Out-Null
    $script:InstallerPath = Join-Path $target 'install_edl_win10_win11.ps1'
    if ($name -eq 'downloaded installer') { [IO.File]::WriteAllText($script:InstallerPath, '# running installer') }
    $before = @(Get-ChildItem -LiteralPath $target -Force).Count
    Set-Location -LiteralPath $target
    $cancelled = $false
    try { Invoke-EdlInstaller } catch { $cancelled = $_ -like '*cancelled*' }
    Assert $cancelled 'An empty target or downloaded installer did not reach Python cancellation'
    Assert (@(Get-ChildItem -LiteralPath $target -Force).Count -eq $before) 'Python cancellation created files'
}
''')

    def test_loader_archive_retries_failed_copy_and_preserves_local_files(self):
        self.check_script(r'''
$target = Join-Path $work 'loader target'
$archiveRoot = Join-Path $work 'Loaders-main'
New-Item -ItemType Directory -Path "$target\Loaders", $archiveRoot | Out-Null
[IO.File]::WriteAllText("$target\Loaders\custom.bin", 'local loader')
[IO.File]::WriteAllText("$archiveRoot\first.bin", 'complete download')
Compress-Archive -Path $archiveRoot -DestinationPath "$work\loaders.zip"
$script:downloads = 0
$script:failCopy = $true
function Get-Command { [CmdletBinding()]param($Name) return $null }
function Invoke-InstallerHttp($Uri, $OutFile) {
    Assert ($Uri -eq 'https://github.com/bkerler/Loaders/archive/refs/heads/main.zip') 'Unexpected Loader source'
    [IO.File]::Copy("$work\loaders.zip", $OutFile)
    $script:downloads++
}
function Copy-Item {
    [CmdletBinding()]param($LiteralPath, $Destination, [switch]$Recurse, [switch]$Force,
                          [Parameter(ValueFromPipeline=$true)]$InputObject)
    process {
        if ($script:failCopy) {
            [IO.File]::WriteAllText("$Destination\first.bin", 'interrupted copy')
            throw 'Simulated interrupted copy'
        }
        Microsoft.PowerShell.Management\Copy-Item -LiteralPath $InputObject.FullName -Destination $Destination -Recurse -Force
    }
}
$failed = $false
try { Get-EdlLoaders $target } catch { $failed = $_ -like '*interrupted copy*' }
Assert $failed 'Copy failure was hidden or a nonempty partial directory was skipped'
Assert (-not (Test-Path -LiteralPath "$target\Loaders\.edl-download-complete")) 'Failed copy was marked complete'
[IO.File]::WriteAllText("$target\Loaders\.edl-download-complete", '')
$script:failCopy = $false
Get-EdlLoaders $target
Assert ($script:downloads -eq 2) 'Interrupted installation was not downloaded again'
Assert ((Get-Content -LiteralPath "$target\Loaders\first.bin") -eq 'complete download') 'Partial loader was not repaired'
Assert ((Get-Content -LiteralPath "$target\Loaders\custom.bin") -eq 'local loader') 'Local loader was removed'
Assert ((Get-Content -LiteralPath "$target\Loaders\.edl-download-complete") -eq 'edl-loaders-main-v1') 'Successful download was not marked complete'
Get-EdlLoaders $target
Assert ($script:downloads -eq 2) 'Complete archive was downloaded unnecessarily'
Assert (-not (Get-ChildItem -LiteralPath $target -Filter '.edl-stage-*' -Force)) 'Loader stage was not cleaned'
''')

    def test_git_loaders_keep_the_recorded_submodule_commit(self):
        self.check_script(r'''
New-Item -ItemType Directory -Path "$work\.git" | Out-Null
$script:calls = 0
function Get-Command { [CmdletBinding()]param($Name) return 'git' }
function git {
    Assert (($args -join ' ') -like '*submodule update --init --recursive --quiet') 'Not a pinned submodule update'
    Assert ($args -notcontains '--remote') 'Loader revision unexpectedly followed remote main'
    $script:calls++
    $global:LASTEXITCODE = 0
}
function Invoke-InstallerHttp { throw 'Git mode fetched a main archive' }
Get-EdlLoaders $work
Assert ($script:calls -eq 1) 'Submodule update was skipped'
''')

    def test_registered_python_without_path_or_launcher(self):
        self.check_script(r'''
$script:legacy = $false
function Get-ChildItem { [CmdletBinding()]param($LiteralPath) return [pscustomobject]@{PSPath = 'fixture-python'} }
function Get-Item {
    [CmdletBinding()]param($LiteralPath)
    $key = [pscustomobject]@{}
    $key | Add-Member -MemberType ScriptMethod -Name GetValue -Value {
        param($Name)
        if ($Name -eq 'ExecutablePath' -and -not $script:legacy) { return 'C:\existing\python.exe' }
        if ($Name -eq '') { return 'C:\existing' }
    }
    return $key
}
function Test-CompatiblePython($Candidate) { if ($Candidate -eq 'C:\existing\python.exe') { return $Candidate } }
Assert ((Find-RegisteredPython) -eq 'C:\existing\python.exe') 'Registered Python was not discovered'
$script:legacy = $true
Assert ((Find-RegisteredPython) -eq 'C:\existing\python.exe') 'Legacy InstallPath registration was not discovered'
''')

    def test_driver_only_does_not_clone_or_install_python(self):
        self.check_script(r'''
$script:DriversOnly = $true
$script:calls = 0
function Ensure-UsbDriver($Unattended) { $script:calls++ }
function Get-EdlCheckout { throw 'Driver-only mode tried to clone source' }
function Resolve-InstallerPython { throw 'Driver-only mode tried to install Python' }
Invoke-EdlInstaller
Assert ($script:calls -eq 1) 'Driver-only mode did not check the driver'
''')
