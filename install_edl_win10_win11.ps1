#Requires -Version 5.1
<#
.SYNOPSIS
Install EDL into the current directory, using a local .venv.
.DESCRIPTION
Missing Python: choose y to install a user-global Python with the official
Python Install Manager, N to cancel, or enter a Python 3.10+ executable path.
WinGet installs Zadig when requested; configure the device driver in Zadig.
#>
[CmdletBinding()]
param(
    [string]$Python,
    [string]$Extras,
    [string]$Repository = 'https://github.com/bkerler/edl.git',
    [switch]$SkipDrivers,
    [switch]$DriversOnly,
    [switch]$SkipLoaders,
    [switch]$NoInput,
    [switch]$Help
)

$ErrorActionPreference = 'Stop'
$InstallerPath = $PSCommandPath

function Invoke-InstallerHttp([string]$Uri, [string]$OutFile) {
    $previous = [Net.ServicePointManager]::SecurityProtocol
    try {
        [Net.ServicePointManager]::SecurityProtocol = $previous -bor [Net.SecurityProtocolType]::Tls12
        if ($OutFile) {
            Invoke-WebRequest -Uri $Uri -OutFile $OutFile -UseBasicParsing -TimeoutSec 300
        } else {
            Invoke-RestMethod -Uri $Uri -Headers @{'User-Agent' = 'edl-installer'} -TimeoutSec 60
        }
    } finally {
        [Net.ServicePointManager]::SecurityProtocol = $previous
    }
}

function Remove-InstallerStage([string]$Stage, [string]$Parent) {
    $resolved = (Resolve-Path -LiteralPath $Stage).Path
    $root = [IO.Path]::GetFullPath($Parent).TrimEnd('\') + '\'
    if (-not $resolved.StartsWith($root, [StringComparison]::OrdinalIgnoreCase) -or
        (Split-Path -Leaf $resolved) -notlike '.edl-stage-*' -or
        ((Get-Item -LiteralPath $resolved -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Refusing to clean unexpected staging directory: $resolved"
    }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}

function Get-EdlCheckout([string]$Target, [string]$Source) {
    if ((Test-Path -LiteralPath "$Target\pyproject.toml") -and
        (Test-Path -LiteralPath "$Target\edlclient" -PathType Container)) { return }
    foreach ($entry in Get-ChildItem -LiteralPath $Target -Force) {
        if ($entry.FullName -ne $InstallerPath) {
            throw 'The current directory is not an EDL checkout and contains other files. Choose an empty directory.'
        }
    }
    $stage = Join-Path $Target ('.edl-stage-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $stage | Out-Null
    try {
        $checkout = Join-Path $stage 'source'
        if (Get-Command git -ErrorAction SilentlyContinue) {
            & git clone --quiet --no-hardlinks -- $Source $checkout
            if ($LASTEXITCODE -ne 0) { throw 'Cloning EDL failed.' }
        } else {
            if ($Source -ne 'https://github.com/bkerler/edl.git') { throw 'Git is required for a custom repository.' }
            Invoke-InstallerHttp 'https://github.com/bkerler/edl/archive/refs/heads/master.zip' "$stage\source.zip"
            Expand-Archive -LiteralPath "$stage\source.zip" -DestinationPath "$stage\expanded"
            $checkout = Join-Path $stage 'expanded\edl-master'
        }
        # Check every destination before moving anything, including the running installer.
        foreach ($entry in Get-ChildItem -LiteralPath $checkout -Force) {
            $destination = Join-Path $Target $entry.Name
            if ((Test-Path -LiteralPath $destination) -and $destination -ne $InstallerPath) {
                throw "Refusing to overwrite $destination"
            }
        }
        foreach ($entry in Get-ChildItem -LiteralPath $checkout -Force) {
            $destination = [IO.Path]::GetFullPath((Join-Path $Target $entry.Name))
            if (-not $destination.StartsWith($Target.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) {
                throw 'Unexpected checkout destination.'
            }
            if ($destination -eq $InstallerPath) { continue }
            Move-Item -LiteralPath $entry.FullName -Destination $destination
        }
    } finally {
        Remove-InstallerStage $stage $Target
    }
}

function Get-EdlLoaders([string]$Target) {
    if ((Test-Path -LiteralPath "$Target\.git") -and (Get-Command git -ErrorAction SilentlyContinue)) {
        & git -C $Target submodule update --init --recursive --quiet
        if ($LASTEXITCODE -ne 0) { throw 'Loader download failed; use -SkipLoaders to configure loaders later.' }
    } elseif (-not (Get-ChildItem -LiteralPath "$Target\Loaders" -Force -ErrorAction SilentlyContinue)) {
        $stage = Join-Path $Target ('.edl-stage-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $stage | Out-Null
        try {
            Invoke-InstallerHttp 'https://github.com/bkerler/Loaders/archive/refs/heads/main.zip' "$stage\loaders.zip"
            Expand-Archive -LiteralPath "$stage\loaders.zip" -DestinationPath "$stage\expanded"
            New-Item -ItemType Directory -Path "$Target\Loaders" -Force | Out-Null
            Get-ChildItem -LiteralPath "$stage\expanded\Loaders-main" -Force |
                Copy-Item -Destination "$Target\Loaders" -Recurse
        } finally { Remove-InstallerStage $stage $Target }
    }
}

function Test-CompatiblePython([string]$Candidate) {
    if (-not $Candidate -or $Candidate -match '\\Microsoft\\WindowsApps\\python(?:3(?:\.[0-9]+)?)?\.exe$') { return $null }
    $automatic = $env:PYTHON_MANAGER_AUTOMATIC_INSTALL
    $legacyInstall = $env:PYLAUNCHER_ALLOW_INSTALL
    $legacyAlways = $env:PYLAUNCHER_ALWAYS_INSTALL
    try {
        $env:PYTHON_MANAGER_AUTOMATIC_INSTALL = 'false'
        Remove-Item Env:PYLAUNCHER_ALLOW_INSTALL, Env:PYLAUNCHER_ALWAYS_INSTALL -ErrorAction SilentlyContinue
        $output = @(& $Candidate -I -c 'import sys, venv, ensurepip; assert sys.version_info >= (3,10); print(sys.executable)' 2>$null)
        if ($LASTEXITCODE -eq 0 -and $output.Count -and (Test-Path -LiteralPath $output[-1] -PathType Leaf)) {
            return $output[-1].Trim()
        }
    } catch {
        return $null
    } finally {
        $env:PYTHON_MANAGER_AUTOMATIC_INSTALL = $automatic
        $env:PYLAUNCHER_ALLOW_INSTALL = $legacyInstall
        $env:PYLAUNCHER_ALWAYS_INSTALL = $legacyAlways
    }
    return $null
}

function Find-PythonManager {
    $command = Get-Command pymanager -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    foreach ($family in @('PythonSoftwareFoundation.PythonManager_3847v3x7pw1km',
                          'PythonSoftwareFoundation.PythonManager_qbz5n2kfra8p0')) {
        $candidate = Join-Path $env:LOCALAPPDATA "Microsoft\WindowsApps\$family\pymanager.exe"
        if (Test-Path -LiteralPath $candidate) { return $candidate }
    }
    return $null
}

function Find-CompatiblePython {
    $candidates = @((Join-Path (Get-Location).Path '.venv\Scripts\python.exe'))
    if ($env:VIRTUAL_ENV) { $candidates += Join-Path $env:VIRTUAL_ENV 'Scripts\python.exe' }
    if ($env:CONDA_PREFIX) { $candidates += Join-Path $env:CONDA_PREFIX 'python.exe' }
    if ($env:PYTHON) { $candidates += $env:PYTHON }
    foreach ($name in @('python', 'python3', 'python3.14', 'python3.13', 'python3.12', 'python3.11', 'python3.10')) {
        $candidates += @(Get-Command $name -All -CommandType Application -ErrorAction SilentlyContinue |
                         Select-Object -ExpandProperty Source)
    }
    foreach ($candidate in $candidates | Select-Object -Unique) {
        $found = Test-CompatiblePython $candidate
        if ($found) { return $found }
    }
    $found = Find-RegisteredPython
    if ($found) { return $found }
    $manager = Find-PythonManager
    if ($manager) {
        foreach ($candidate in @(& $manager list --format=exe '>=3.10' 2>$null)) {
            $found = Test-CompatiblePython $candidate
            if ($found) { return $found }
        }
    }
    if (Get-Command py -ErrorAction SilentlyContinue) {
        foreach ($line in @(& py -0p 2>$null)) {
            if ($line -match '([A-Za-z]:\\.*python(?:[0-9.]*)?\.exe)\s*$') {
                $found = Test-CompatiblePython $matches[1]
                if ($found) { return $found }
            }
        }
    }
    return $null
}

function Find-RegisteredPython {
    foreach ($root in @('HKCU:\Software\Python\PythonCore', 'HKLM:\Software\Python\PythonCore',
                        'HKLM:\Software\WOW6432Node\Python\PythonCore')) {
        foreach ($version in @(Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)) {
            $key = Get-Item -LiteralPath "$($version.PSPath)\InstallPath" -ErrorAction SilentlyContinue
            if (-not $key) { continue }
            $candidate = $key.GetValue('ExecutablePath')
            if (-not $candidate -and $key.GetValue('')) { $candidate = Join-Path ($key.GetValue('')) 'python.exe' }
            $found = Test-CompatiblePython $candidate
            if ($found) { return $found }
        }
    }
    if (Get-Command Get-AppxPackage -ErrorAction SilentlyContinue) {
        foreach ($package in @(Get-AppxPackage -Name 'PythonSoftwareFoundation.Python.3.*' -ErrorAction SilentlyContinue)) {
            $candidate = Join-Path $env:LOCALAPPDATA "Microsoft\WindowsApps\$($package.PackageFamilyName)\python.exe"
            $found = Test-CompatiblePython $candidate
            if ($found) { return $found }
        }
    }
    return $null
}

function Install-GlobalPython {
    $manager = Find-PythonManager
    if (-not $manager) {
        if (Get-Command winget -ErrorAction SilentlyContinue) {
            & winget install 9NQ7512CXL7T -e --source msstore --accept-package-agreements --accept-source-agreements --disable-interactivity
            if ($LASTEXITCODE -ne 0) { throw 'Python Install Manager installation failed.' }
        } else {
            Add-AppxPackage -AppInstallerFile 'https://www.python.org/ftp/python/pymanager/pymanager.appinstaller'
        }
        $manager = Find-PythonManager
        if (-not $manager) { throw 'Python Install Manager commands are unavailable. Reopen the terminal or enter an existing Python path.' }
    }
    & $manager install 3.14
    if ($LASTEXITCODE -ne 0) { throw 'Global Python installation failed.' }
    foreach ($candidate in @(& $manager list --format=exe '>=3.10' 2>$null)) {
        $found = Test-CompatiblePython $candidate
        if ($found) { return $found }
    }
    throw 'The installed Python runtime could not be located.'
}

function Resolve-InstallerPython([string]$ExplicitPython, [bool]$Unattended) {
    if ($ExplicitPython) { $found = Test-CompatiblePython $ExplicitPython }
    else { $found = Find-CompatiblePython }
    if ($found) { return $found }
    if ($Unattended) { throw 'Python 3.10+ with venv is unavailable. Supply -Python with its executable path.' }
    while ($true) {
        Write-Host 'No compatible Python 3.10+ was found.'
        Write-Host 'y installs the official Python Install Manager and a GLOBAL Python 3.14 for this Windows user.'
        Write-Host 'This changes the user-wide Python environment OUTSIDE the project .venv. It is not an all-users installation.'
        $answer = (Read-Host 'Install global Python, cancel, or enter python.exe path [y/N/path]').Trim().Trim('"')
        if (-not $answer -or $answer -ieq 'n') { throw 'Installation cancelled; no global Python was installed.' }
        if ($answer -ieq 'y') { return Install-GlobalPython }
        $found = Test-CompatiblePython $answer
        if ($found) { return $found }
        Write-Host 'That executable does not provide Python 3.10+, venv and ensurepip.'
    }
}

function Test-Zadig {
    if (Get-Command zadig -ErrorAction SilentlyContinue) { return $true }
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        & winget list --id akeo.ie.Zadig --exact --source winget --accept-source-agreements --disable-interactivity | Out-Host
        return $LASTEXITCODE -eq 0
    }
    return $false
}

function Install-Zadig {
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        throw 'WinGet is unavailable. Install/update App Installer, or install Zadig manually from https://zadig.akeo.ie/ and rerun.'
    }
    & winget install --id akeo.ie.Zadig --exact --source winget --no-upgrade --accept-package-agreements --accept-source-agreements --disable-interactivity
    if ($LASTEXITCODE -ne 0) { throw "Installing Zadig with WinGet failed: $LASTEXITCODE" }
}

function Ensure-UsbDriver([bool]$Unattended) {
    if (-not (Test-Zadig)) {
        if ($Unattended) { throw 'Zadig is unavailable. Run interactively or use -SkipDrivers if USB drivers are already configured or for serial mode.' }
        $answer = Read-Host 'Install Zadig with WinGet? Driver configuration in Zadig may require administrator privileges [y/N]'
        if ($answer.Trim() -ieq 'y') { Install-Zadig }
        else { Write-Host 'Zadig installation skipped; configure USB drivers manually or use serial mode.' }
    }
    Write-Host 'USB setup: connect the EDL device, open Zadig, select Options > List All Devices, select the EDL/QHSUSB_BULK device, then install WinUSB for that device.'
    Write-Host 'Having Zadig installed does not mean the device driver is configured. Zadig requests administrator privileges when needed.'
}

function Invoke-EdlInstaller {
    if ($Help) {
        Write-Host 'Install into the CURRENT directory (downloaded installer alone is supported).'
        Write-Host 'Options: -Python <exe> -Extras asm,qrcode -SkipDrivers -DriversOnly -SkipLoaders -NoInput -Repository <git-url>'
        return
    }
    if ($DriversOnly) { Ensure-UsbDriver ([bool]$NoInput); return }
    if ($Extras -and @($Extras.Split(',') | Where-Object { $_ -notin @('asm', 'qrcode') }).Count) {
        throw 'Choose asm, qrcode, or asm,qrcode.'
    }
    $target = (Get-Location).Path
    Write-Host "Installing EDL in $target"
    Get-EdlCheckout $target $Repository
    if (-not (Test-Path -LiteralPath "$target\install.py")) { throw 'This checkout is outdated: update it to include install.py.' }
    if (Test-Path -LiteralPath "$target\.venv") {
        if (-not (Test-Path -LiteralPath "$target\.venv\pyvenv.cfg") -or
            (Get-Content -LiteralPath "$target\.venv\pyvenv.cfg" -Raw) -notmatch '(?im)^\s*include-system-site-packages\s*=\s*false\s*$') {
            throw 'The existing .venv is not an isolated virtual environment. Move it aside before installing.'
        }
    }
    $interpreter = Resolve-InstallerPython $Python ([bool]$NoInput)
    Write-Host "Using Python: $interpreter"
    if (-not $SkipDrivers) { Ensure-UsbDriver ([bool]$NoInput) }
    if (-not $SkipLoaders) { Get-EdlLoaders $target }
    $arguments = @('-I', "$target\install.py", '--venv', "$target\.venv")
    if ($Extras) { $arguments += @('--extras', $Extras) }
    & $interpreter @arguments
    if ($LASTEXITCODE -ne 0) { throw 'Installing EDL in .venv failed.' }
    Write-Host 'Ready. Run .\edl.bat --help (or .\.venv\Scripts\edl.exe --help).'
}

if ($MyInvocation.InvocationName -ne '.') {
    try { Invoke-EdlInstaller; exit 0 }
    catch { Write-Error "Installation failed: $_" -ErrorAction Continue; exit 1 }
}
