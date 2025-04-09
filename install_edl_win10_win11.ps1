# Ensure script runs with elevated privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    echo "This script requires administrator privileges. Restarting as administrator..."
    Start-Process powershell "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

# Check if winget is available
while (!(gcm winget -ErrorAction SilentlyContinue)) {
    echo "The 'winget' command is unavailable. Please update 'App Installer' through Microsoft Store and then press Enter to continue."
    echo ''
    echo 'Microsoft Store will open automatically in 7 seconds.'
    sleep 7
    Start-Process "ms-windows-store://pdp?hl=en-us&gl=us&productid=9nblggh4nns1"
    $null = $host.UI.RawUI.ReadKey()
    echo ''
}

# Update winget sources
echo "Updating winget sources..."
winget source update

# Install required packages using winget
$packages = @(
    "akeo.ie.Zadig",
    "Git.Git",
    "Python.Python.3.9"
)

foreach ($package in $packages) {
    echo "Installing $package..."
    winget install --id=$package --accept-package-agreements --accept-source-agreements --disable-interactivity --scope machine
}

# Clone the edl repository
echo "Cloning edl repository..."
cd $env:ProgramFiles
git clone --recurse-submodules https://github.com/bkerler/edl.git

# Install Python dependencies
echo "Installing Python dependencies..."
& "${env:ProgramFiles}\Python39\Scripts\pip3" install -r "${env:ProgramFiles}\edl\requirements.txt"

# Add edl to the system PATH
echo "Adding edl to the system PATH..."
$currentPath = [Environment]::GetEnvironmentVariable("Path", [System.EnvironmentVariableTarget]::Machine)
$edlPath = Resolve-Path "${env:ProgramFiles}\edl"

if (-not ($currentPath -split ';' -contains $edlPath)) {
    [Environment]::SetEnvironmentVariable("Path", "$currentPath;$edlPath", [System.EnvironmentVariableTarget]::Machine)
	echo ''
    echo "Added $edlPath to the system PATH."
} else {
    echo "$edlPath is already in the system PATH."
}

echo ""
echo "'edl', 'zadig' installed successfully. You can now open a new PowerShell or Terminal window to use these tools."
echo ""
echo "Don't forget to run 'Zadig' to install the WinUSB driver for QHSUSB_BULK devices."
echo ""
echo "Setup completed successfully. Press any key to continue"
$null = $host.UI.RawUI.ReadKey()