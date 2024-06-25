<#
.SYNOPSIS
    [This script is the primary installer of OneClick-Sysmon logger]
.DESCRIPTION
    [ENTER A COMPLETE DESCRIPTION OF THE SCRIPT (i.e. checks version, updates config, installs sysmon, etc...)]
.NOTES
    Version:        1.04
    Author:         Github @ACETHREAT 
    Creation Date:  5/17/23 ||| Update: 6/24/2024
    Purpose/Change: OneClick-Sysmon updated
   
$binary = [convert]::ToBase64String((Get-Content -path "FILEPATH\FILENAME.ZIP" -Encoding byte))
$binary | Out-File ("FILEPATH\FILENAME.txt")
.EXAMPLE
    Sysmon-install.ps1
.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File C:\path\Sysmon-install.ps1
#>

$Logo = @"
                 #####  #     #  #####  #     # ####### #     #       ### #     #  #####  #######    #    #       #          
                #     #  #   #  #     # ##   ## #     # ##    #        #  ##    # #     #    #      # #   #       #          
                #         # #   #       # # # # #     # # #   #        #  # #   # #          #     #   #  #       #          
                 #####     #     #####  #  #  # #     # #  #  # #####  #  #  #  #  #####     #    #     # #       #          
                      #    #          # #     # #     # #   # #        #  #   # #       #    #    ####### #       #          
                #     #    #    #     # #     # #     # #    ##        #  #    ## #     #    #    #     # #       #          
                 #####     #     #####  #     # ####### #     #       ### #     #  #####     #    #     # ####### #######    


                                        
                                       
                                  = #Created By::::::::::ACETHREAT LINKEDIN: @SNSL::::::::::::::::::#   

"@

Write-Host $Logo -ForegroundColor Magenta

#Global variables
$StartTime = Get-Date
$LogDate = $StartTime.ToString('yyyMMdd_HHmmss')
$Name = $env:computername
$FQDN = $env:userdnsdomain
$OS64bit = [Environment]::Is64BitOperatingSystem
$ScriptDir = Split-Path $script:MyInvocation.MyCommand.Path
$SysmonLogDir = "C:\Windows\SYSMON-OneClick"
$LogFile =  "$SysmonLogDir\${LogDate}_${Name}_SYSMON.log"
$ScriptVersion = 1.0
$installsysmon = $True
$windowsSystemVersion = (Get-CimInstance -ClassName Win32_OperatingSystem).Version
$isARM = @(Get-WmiObject -Class Win32_Processor | Where-Object { $_.Name -match "ARM|Apple Silicon" }).Count -gt 0


#SYSMON Variables
$Sysmonversion = '15.14'
$Sysmon64Bin = "Sysmon64.exe"
$Sysmon32Bin = "Sysmon.exe"
$SysmonARM = "Sysmon64a.exe"
$SysmonConfig = "sysmon-config.xml"
$sysmonConfigversion = 1.0
$keyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Sysmon"
$valueName = "ConfigurationFile"

Function Log-Start{  
	[CmdletBinding()]

	Param ([Parameter(Mandatory=$true)][string]$LogPath, [Parameter(Mandatory=$true)][string]$ScriptVersion)

	Process{
		Add-Content -Path $LogPath -Value "***************************************************************************************************"
		Add-Content -Path $LogPath -Value "Running Sysmon-OneClick Installer."
		Add-Content -Path $LogPath -Value "Script executed."
		Add-Content -Path $LogPath -Value "Started processing at $([DateTime]::Now)."
		Add-Content -Path $LogPath -Value "Running script version [$ScriptVersion]."
		Add-Content -Path $LogPath -Value "---------------------------------------------------------------------------------------------------"
		Add-Content -Path $LogPath -Value ""
	}
}

Function Log-Write{
	[CmdletBinding()]

	Param ([Parameter(Mandatory=$true)][string]$LogPath, [Parameter(Mandatory=$true)][string]$LineValue)

	Process{
		$Stamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
		$Line = "$Stamp $LineValue"
		Add-Content -Path $LogPath -Value $Line
	}
}

Function Log-Finish{
	[CmdletBinding()]

	Param ([Parameter(Mandatory=$true)][string]$LogPath)

	Add-Content -Path $LogPath -Value ""
	Add-Content -Path $LogPath -Value "***************************************************************************************************"
	Add-Content -Path $LogPath -Value "Finished processing at $([DateTime]::Now)."
	Add-Content -Path $LogPath -Value "***************************************************************************************************"
	Add-Content -Path $LogPath -Value "Total processing time $(((Get-Date)-$StartTime).totalseconds) seconds."
	Add-Content -Path $LogPath -Value "***************************************************************************************************"
}

If (!(Test-Path $SysmonLogDir)){
	New-Item "$SysmonLogDir" -ItemType Directory | Out-Null
}

If (!(Test-Path "$SysmonLogDir\Tools")){
	New-Item "$SysmonLogDir\Tools" -ItemType Directory | Out-Null
}

Log-Start -LogPath $LogFile -ScriptVersion $ScriptVersion

Function windowsVersionCheck {
    $windowsSystemVersion = (Get-WmiObject -Class Win32_OperatingSystem).Version

    # Convert version string to a version object
    $version = [version]$windowsSystemVersion

    # Minimum version for Windows 10 is 10.0.10240.0
    $minimumVersion = [version]"10.0.10240.0"

    if ($version -lt $minimumVersion) {
        Log-Write -LogPath $LogFile -LineValue "Unsupported version of Windows found - Exiting!"
        EXIT
    } else {
        Log-Write -LogPath $LogFile -LineValue "Windows version looks good, time to install!"
    }
}

# Check if Windows is Windows 10 or greater, or Server 2016 or greater. If not, exits
windowsVersionCheck 

###############################################################################
# Region: Decode and Extract Sysmon Files
# This section decodes the base64 encoded Sysmon files, writes them to disk,
# and extracts them to the appropriate directories.
###############################################################################

Write-Host -ForegroundColor Yellow "Decoding and writing ZIP file 'Sysmon.zip' to current script directory '${ScriptDir}'."
Log-Write -LogPath $LogFile -LineValue "Decoding and writing ZIP file 'Sysmon.zip' to current script directory '${ScriptDir}'."

# Base64 encoded Sysmon ZIP file
$sysmonzip = 
# Base64 encoded Sysmon config file
$sysmonconfig = 
 

# Decode and write Sysmon ZIP file
$binary = [Convert]::FromBase64String($sysmonzip)
Set-Content -Path "$ScriptDir\Sysmon.zip" -Value $binary -Encoding Byte

Write-Host -ForegroundColor Green "COMPLETED: Decoded and wrote ZIP file 'Sysmon.zip' to current script directory '${ScriptDir}'."
Log-Write -LogPath $LogFile -LineValue "COMPLETED: Decoded and wrote ZIP file 'Sysmon.zip' to current script directory '${ScriptDir}'."

start-sleep -Seconds 10

# Decode and write Sysmon config file
$binaryconfig = [Convert]::FromBase64String($sysmonconfig)
Set-Content -Path "$SysmonLogDir\Tools\sysmon-config.xml" -Value $binaryconfig -Encoding Byte

Write-Host -ForegroundColor Green "COMPLETED: Decoded and wrote config file 'sysmon-config.zip' to current script directory '${ScriptDir}'."
Log-Write -LogPath $LogFile -LineValue "COMPLETED: Decoded and wrote config file 'sysmon-config.zip' to current script directory '${ScriptDir}'."

Start-Sleep -Seconds 5

# Check if the Sysmon ZIP file was successfully created
If (!(Test-Path "$ScriptDir\Sysmon.zip")){
    Write-Host -ForegroundColor Red "ERROR: The required tools ZIP file 'Sysmon.zip' does not exist and could not be decoded and extracted from script."
    Log-Write -LogPath $LogFile -LineValue "ERROR: The required tools ZIP file 'Sysmon.zip' does not exist and could not be decoded and extracted from script."
    Log-Finish -LogPath $LogFile
    EXIT(1)
}

# Extract Sysmon files
Write-Host -ForegroundColor Yellow "Extracting additional required tools from file Sysmon.zip to $SysmonLogDir\Tools."
Log-Write -LogPath $LogFile -LineValue "Extracting additional required tools from file Sysmon.zip to $SysmonLogDir\Tools."
Expand-Archive -Path "$ScriptDir\Sysmon.zip" -DestinationPath "$SysmonLogDir\Tools\" -Force
Log-Write -LogPath $LogFile -LineValue "COMPLETED: Copied config files to $SysmonLogDir\Tools."
Write-Host -ForegroundColor Green "COMPLETED: Copied config files to $SysmonLogDir\Tools."
Start-Sleep -Seconds 1
Log-Write -LogPath $LogFile -LineValue "COMPLETED: Extracted necessary files to $SysmonLogDir\Tools."
Write-Host -ForegroundColor Green "COMPLETED: Extracted necessary files to $SysmonLogDir\Tools."
Start-Sleep -Seconds 30

###############################################################################
# Region: Sysmon Version Check and Uninstallation
# This section checks for existing Sysmon installations, compares versions,
# and uninstalls outdated versions if necessary.
###############################################################################

$sysmonprocess = Get-Process 'Sysmon*' -ErrorAction SilentlyContinue
$sysmonsvc = Get-Service -Name 'Sysmon*' -ErrorAction SilentlyContinue

$sysmonfilepath = "C:\Windows\Sysmon64.exe"
if (Test-Path $sysmonfilepath) {
    $sysmonfileversion = (Get-Item -Path $sysmonfilepath).VersionInfo.FileVersion
} else {
    Write-Host "Sysmon64.exe not found. Continuing without version check."
    Log-Write -LogPath $LogFile -LineValue "Sysmon64.exe not found. Continuing without version check."
    $sysmonfileversion = $null 
    }


If ($sysmonprocess -Or $sysmonsvc) {
    Write-Host -ForegroundColor Yellow "SYSMON service was found or process is running."
    Log-Write -LogPath $LogFile -LineValue "SYSMON service was found or process is running."
    
    If(Test-Path $keypath){
        $sysmonver = (Get-ItemProperty $keypath)."$valueName"
        write-host -ForegroundColor DarkYellow "Registry Key Found!"
        
        If ($sysmonver -ge $sysmonConfigversion) {
            Write-Host -ForegroundColor Yellow "SYSMON Configuration File version is current $sysmonver."
            Log-Write -LogPath $LogFile -LineValue "SYSMON Configuration File version is current $sysmonver."
            $installsysmon = $False
        }ElseIf ($sysmonfileversion -eq $Sysmonversion){
            Write-Host -ForegroundColor Yellow "SYSMON installed and the current version is $sysmonfileversion. Updating configuration file to '$sysmonConfigversion'."
            Log-Write -LogPath $LogFile -LineValue "SYSMON installed and the current version is $sysmonfileversion. Updating configuration file to '$sysmonConfigversion'."
            New-ItemProperty -path $keyPath -Name $valueName -Value $sysmonConfigversion -PropertyType string -Force -ErrorAction SilentlyContinue
            If($OS64bit) {
                & "$SysmonLogDir\Tools\$Sysmon64Bin" -accepteula -c "$SysmonLogDir\Tools\sysmon-config.xml"
            }Else {
                & "$SysmonLogDir\Tools\$Sysmon32Bin" -accepteula -c "$SysmonLogDir\Tools\sysmon-config.xml"
            }
        
            $installsysmon = $False
        }Else {
            Write-Host -ForegroundColor Yellow "SYSMON service is installed and/or running, but the version is outdated. Current version installed is '${sysmonver}' compared to the new approved Sysmon version '${sysmonConfigversion}'."
            Log-Write -LogPath $LogFile -LineValue "SYSMON service is installed and/or running, but the version is outdated. Current version installed is '${sysmonver}' compared to the new approved Sysmon version '${sysmonConfigversion}'."
            Write-Host -ForegroundColor Yellow "Uninstalling older version of SYSMON."
            Log-Write -LogPath $LogFile -LineValue "Uninstalling older version of SYSMON."
            
            # Uninstall Sysmon and verify uninstallation
            If($OS64bit) {
                & "c:\windows\sysmon64.exe" -u
            }Else {
                & "c:\windows\sysmon.exe" -u
            }
            
            # Wait for uninstallation and verify
            $uninstallTimeout = 60 # seconds
            $uninstallSuccess = $false
            $timer = [Diagnostics.Stopwatch]::StartNew()
            
            while ($timer.Elapsed.TotalSeconds -lt $uninstallTimeout) {
                if (!(Get-Service -Name 'Sysmon*' -ErrorAction SilentlyContinue) -and !(Get-Process 'Sysmon*' -ErrorAction SilentlyContinue)) {
                    $uninstallSuccess = $true
                    break
                }
                Start-Sleep -Seconds 5
            }
            
            if ($uninstallSuccess) {
                Write-Host -ForegroundColor Green "COMPLETED: Successfully uninstalled older version of SYSMON."
                Log-Write -LogPath $LogFile -LineValue "COMPLETED: Successfully uninstalled older version of SYSMON."
            } else {
                Write-Host -ForegroundColor Red "ERROR: Failed to uninstall older version of SYSMON within the timeout period."
                Log-Write -LogPath $LogFile -LineValue "ERROR: Failed to uninstall older version of SYSMON within the timeout period."
                Log-Finish -LogPath $LogFile
                EXIT(1)
            }
        }
    }
}
#endregion

###############################################################################
#region SYSMON Version Check, Installer, and Updater                          #
###############################################################################
If($installsysmon){
    # Function to check if the system is ARM-based
    Function Is-ARMSystem {
        return @(Get-WmiObject -Class Win32_Processor | Where-Object { $_.Architecture -eq 12 }).Count -gt 0
    }

    # Determine the appropriate Sysmon executable
    If($OS64bit) {
        If(Is-ARMSystem) {
            $SysmonExe = $SysmonARM
            Write-Host -ForegroundColor Yellow "ARM64 system detected. Using Sysmon64a.exe."
            Log-Write -LogPath $LogFile -LineValue "ARM64 system detected. Using Sysmon64a.exe."
        } Else {
            $SysmonExe = $Sysmon64Bin
            Write-Host -ForegroundColor Yellow "x64 system detected. Using Sysmon64.exe."
            Log-Write -LogPath $LogFile -LineValue "x64 system detected. Using Sysmon64.exe."
        }
    } Else {
        $SysmonExe = $Sysmon32Bin
        Write-Host -ForegroundColor Yellow "x86 system detected. Using Sysmon.exe."
        Log-Write -LogPath $LogFile -LineValue "x86 system detected. Using Sysmon.exe."
    }

    # Install Sysmon
    & "$SysmonLogDir\Tools\$SysmonExe" -accepteula -i "$SysmonLogDir\Tools\sysmon-config.xml"

    $x = 0
    While (!(Get-Process Sysmon* -ErrorAction SilentlyContinue) -and $x -lt 6){
        Start-Sleep -Seconds 30
        $x += 1
    }

    # Checks if Sysmon is installed
    If(Get-Service -Name 'Sysmon*' -ErrorAction SilentlyContinue) {
        Write-Host -ForegroundColor Green "COMPLETED: SYSMON service was installed successfully."
        Log-Write -LogPath $LogFile -LineValue "COMPLETED: SYSMON service was installed successfully."

        # Sets registry version number for Sysmon installed
        Write-Host -ForegroundColor Yellow "Creating/Updating SYSMON registry value name 'ConfigurationFile' of version installed."
        Log-Write -LogPath $LogFile -LineValue "Creating/Updating SYSMON registry value name 'ConfigurationFile' of version installed."
        If(Test-Path $keypath){
            New-ItemProperty -path $keyPath -Name $valueName -Value $sysmonConfigversion -PropertyType string -Force -ErrorAction SilentlyContinue
        }Else {
            New-Item -Path $keyPath -Force -ErrorAction SilentlyContinue
            New-ItemProperty -path $keyPath -Name $valueName -Value $sysmonConfigversion -PropertyType string -Force -ErrorAction SilentlyContinue
        }
        Write-Host -ForegroundColor Green "COMPLETED: Created/Updated SYSMON registry value name 'ConfigurationFile' and set the version installed to '$sysmonConfigversion'."
        Log-Write -LogPath $LogFile -LineValue "COMPLETED: Created/Updated SYSMON registry value name 'ConfigurationFile' and set the version installed to '$sysmonConfigversion'."
        
        # Sets Sysmon Windows Event Log File Size to 64MB
        Write-Host -ForegroundColor Yellow "Setting SYSMON Windows Event Log File size to 64MB."
        Log-Write -LogPath $LogFile -LineValue "Setting SYSMON Windows Event Log File size to 64MB."
        
        $sysmonlog  = Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -Force -ErrorAction SilentlyContinue
        If($sysmonlog){
            $sysmonlog.MaximumSizeInBytes = 67108864 #64MB
            $sysmonlog.SaveChanges()
            Write-Host -ForegroundColor Green "COMPLETED: SYSMON Windows Event log maximum file size set to 64MB."
            Log-Write -LogPath $LogFile -LineValue "COMPLETED: SYSMON Windows Event log maximum file size set to 64MB."
        }Else {
            Write-Host -ForegroundColor Red "ERROR: SYSMON WINDOWS EVENT LOG COULD NOT BE FOUND."
            Log-Write -LogPath $LogFile -LineValue "ERROR: SYSMON WINDOWS EVENT LOG COULD NOT BE FOUND."
        }
    }Else {
        Write-Host -ForegroundColor Red "ERROR: FAILED TO INSTALL SYSMON. OS ARCHITECTURE: $Env:PROCESSOR_ARCHITECTURE"
        Log-Write -LogPath $LogFile -LineValue "ERROR: FAILED TO INSTALL SYSMON. OS ARCHITECTURE: $Env:PROCESSOR_ARCHITECTURE"
    }
}
    
#endregion

###############################################################################
#region Clean-up                                                              #
###############################################################################

Write-Host -ForegroundColor Yellow "Cleaning up dropped files and script."
Log-Write -LogPath $LogFile -LineValue "Cleaning up dropped files and script."

Remove-Item "$SysmonLogDir\Tools" -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item "$ScriptDir\Sysmon.zip" -Force -ErrorAction SilentlyContinue

#Self Destruct (Deletes itself)
Remove-Item -Path $MyInvocation.MyCommand.Source -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$ScriptDir\Sysmon-install.ps1" -Force -ErrorAction SilentlyContinue

Write-Host -ForegroundColor Green "COMPLETED: Removed all files and script."
Log-Write -LogPath $LogFile -LineValue "COMPLETED: Removed all files and script."

Log-Finish -LogPath $LogFile

EXIT(0)

#endregion
