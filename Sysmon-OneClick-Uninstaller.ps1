<#
.SYNOPSIS
    Uninstalls Sysmon and removes artifacts from the OneClick-Sysmon installation.
.DESCRIPTION
    This script uninstalls Sysmon, removes the Sysmon service, deletes Sysmon files,
    removes registry entries, and cleans up logs and directories created during installation.
.NOTES
    Version:        1.0
    Author:         [Your Name]
    Creation Date:  [Current Date]
    Purpose:        Sysmon uninstallation and cleanup
#>

# Define paths and variables
$SysmonLogDir = "C:\Windows\SYSMON-OneClick"
$keyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Sysmon"
$sysmonExePath = "C:\Windows\Sysmon64.exe"
$sysmon32ExePath = "C:\Windows\Sysmon.exe"
$sysmonARMExePath = "C:\Windows\Sysmon64a.exe"

# Function to write log
function Write-Log {
    param([string]$message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "$timestamp - $message"
}

# Uninstall Sysmon
Write-Log "Attempting to uninstall Sysmon..."
if (Test-Path $sysmonExePath) {
    & $sysmonExePath -u force
} elseif (Test-Path $sysmon32ExePath) {
    & $sysmon32ExePath -u force
} elseif (Test-Path $sysmonARMExePath) {
    & $sysmonARMExePath -u force
} else {
    Write-Log "Sysmon executable not found. It may already be uninstalled."
}

# Wait for uninstallation to complete
Start-Sleep -Seconds 10

# Remove Sysmon service if it still exists
$service = Get-Service -Name "Sysmon*" -ErrorAction SilentlyContinue
if ($service) {
    Write-Log "Removing Sysmon service..."
    Stop-Service $service.Name -Force
    sc.exe delete $service.Name
}

# Remove Sysmon files
$sysmonFiles = @($sysmonExePath, $sysmon32ExePath, $sysmonARMExePath)
foreach ($file in $sysmonFiles) {
    if (Test-Path $file) {
        Write-Log "Removing Sysmon file: $file"
        Remove-Item -Path $file -Force
    }
}

# Remove Sysmon registry entries
if (Test-Path $keyPath) {
    Write-Log "Removing Sysmon registry entries..."
    Remove-Item -Path $keyPath -Recurse -Force
}

# Remove Sysmon event log
$sysmonLog = Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational" -ErrorAction SilentlyContinue
if ($sysmonLog) {
    Write-Log "Removing Sysmon event log..."
    wevtutil.exe cl Microsoft-Windows-Sysmon/Operational
}

# Remove Sysmon-OneClick directory and its contents
if (Test-Path $SysmonLogDir) {
    Write-Log "Removing Sysmon-OneClick directory and its contents..."
    Remove-Item -Path $SysmonLogDir -Recurse -Force
}

# Final check
$remainingArtifacts = @(
    (Get-Service -Name "Sysmon*" -ErrorAction SilentlyContinue),
    (Get-Item -Path $sysmonExePath -ErrorAction SilentlyContinue),
    (Get-Item -Path $sysmon32ExePath -ErrorAction SilentlyContinue),
    (Get-Item -Path $sysmonARMExePath -ErrorAction SilentlyContinue),
    (Test-Path $keyPath),
    (Test-Path $SysmonLogDir)
)

if ($remainingArtifacts -notcontains $true) {
    Write-Log "Sysmon has been successfully uninstalled and all artifacts have been removed."
} else {
    Write-Log "Sysmon uninstallation completed, but some artifacts may remain. Please check manually."
}

Write-Log "Uninstallation and cleanup process completed."