# SysmonONECLICK Logger Installer

This repository contains the primary installer script for SysmonONECLICK Logger, a streamlined solution to deploy and configure Sysmon on Windows machines with minimal effort.

## Description

The `Sysmon-OneClick.ps1` script performs the following tasks:
- Checks the version of Windows and exits if the version is unsupported.
- Decodes and writes necessary files from Base64 to the local directory.
- Installs or updates Sysmon to the specified version.
- Configures Sysmon with a predefined configuration file.
- Sets the Sysmon Windows Event Log file size to 64MB.
- Logs all actions performed during the installation.
- Cleans up all temporary files and self-destructs the script after execution.

## Prerequisites

- Windows operating system.
- PowerShell with execution policy set to allow the script to run (e.g., `Bypass`).

## Usage

### Running the Script

#### NOTE: You MUST b64 encode the Sysmon.zip and a config file and paste them into the script. See my https://github.com/ACEThreat/Python-B64-Encoder for an easy b64 encoder. 

Paste the base64 in the following two variables:

$sysmonzip = 
$sysmonconfig = 


To run the installer script, use the following command in PowerShell:

```powershell
powershell.exe -ExecutionPolicy Bypass -File C:\path\Sysmon-OneClick.ps1
```

### Version: 1.00 
#### Author: @ACETHREAT
#### Update: 6/11/24
#### Purpose/Change: Updated for public release.
