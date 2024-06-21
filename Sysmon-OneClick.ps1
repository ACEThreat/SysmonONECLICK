<#
.SYNOPSIS
    [This script is the primary installer of SysmonONECLICK logger]
.DESCRIPTION
    [ENTER A COMPLETE DESCRIPTION OF THE SCRIPT (i.e. checks version, updates config, installs sysmon, etc...)]
.NOTES
    Version:        1.00
    Author:         @ACETHREAT
    Creation Date:  5/17/23 ||| Update: 6/11/24
    Purpose/Change: Updated for public release.
   
    Copyright 2024 ACEThreat

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
   
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

#SYSMON Variables
$Sysmonversion = '15.14'
$Sysmon64Bin = "Sysmon64.exe"
$Sysmon32Bin = "Sysmon.exe"
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
    if($windowsSystemVersion  -like "6.*")  {
        Log-Write -LogPath $LogFile -LineValue "Bad Version of Windows found - Exiting!"
        EXIT
    } Else{
        Log-Write -LogPath $LogFile -LineValue "Windows version looks good, time to install!"
    }

}
#Check if Windows Vista, Server 2008, Server 2012 #
windowsVersionCheck 
###############################################################################
#region Base64 decode SYSMON, write ZIP file to current script directory, and #
# extracts the ZIP files the directory C:\Windows\Sysmon-OneClick             #
###############################################################################

Write-Host -ForegroundColor Yellow "Decoding and writing ZIP file 'Sysmon.zip' to current script directory '${ScriptDir}'."
Log-Write -LogPath $LogFile -LineValue "Decoding and writing ZIP file 'Sysmon.zip' to current script directory '${ScriptDir}'."

$sysmonzip = 

$sysmonconfig = 

#Base64 decode variable $dfirtools and write ZIP file to current script directory
$binary = [Convert]::FromBase64String($sysmonzip)
Set-Content -Path "$ScriptDir\Sysmon.zip" -Value $binary -Encoding Byte

Write-Host -ForegroundColor Green "COMPLETED: Decoded and wrote ZIP file 'Sysmon.zip' to current script directory '${ScriptDir}'."
Log-Write -LogPath $LogFile -LineValue "COMPLETED: Decoded and wrote ZIP file 'Sysmon.zip' to current script directory '${ScriptDir}'."

start-sleep -Seconds 10

$binaryconfig = [Convert]::FromBase64String($sysmonconfig)
Set-Content -Path "$SysmonLogDir\Tools\sysmon-config.xml" -Value $binaryconfig -Encoding Byte

Write-Host -ForegroundColor Green "COMPLETED: Decoded and wrote config file 'sysmon-config.zip' to current script directory '${ScriptDir}'."
Log-Write -LogPath $LogFile -LineValue "COMPLETED: Decoded and wrote config file 'sysmon-config.zip' to current script directory '${ScriptDir}'."

Start-Sleep -Seconds 5

#Checks if the ZIP file 'Sysmon.zip' exists in the current script directory
If (!(Test-Path "$ScriptDir\Sysmon.zip")){
	Write-Host -ForegroundColor Red "ERROR: The required tools ZIP file 'Sysmon.zip' does not exists and could not be decoded and extracted from script."
	Log-Write -LogPath $LogFile -LineValue "ERROR:  The required tools ZIP file 'Sysmon.zip' does not exists and could not be decoded and extracted from script."
	Log-Finish -LogPath $LogFile
	EXIT(1)
}

#Extracts the files from ZIP file Sysmon.zip to the directory C:\Windows\Sysmon-OneClick\Tools
Write-Host -ForegroundColor Yellow "Extracting additional required tools from file Sysmon.zip to $SysmonLogDir\Tools."
Log-Write -LogPath $LogFile -LineValue "Extracting additional required tools from file Sysmon.zip to $SysmonLogDir\Tools."
Expand-Archive -Path "$ScriptDir\Sysmon.zip" -DestinationPath "$SysmonLogDir\Tools\" -Force
Log-Write -LogPath $LogFile -LineValue "COMPLETED: Copied config files to $SysmonLogDir\Tools."
Write-Host -ForegroundColor Green "COMPLETED: Copied config files to $SysmonLogDir\Tools."
Start-Sleep -Seconds 1
Log-Write -LogPath $LogFile -LineValue "COMPLETED: Extracted necessary files to $SysmonLogDir\Tools."
Write-Host -ForegroundColor Green "COMPLETED: Extracted necessary files to $SysmonLogDir\Tools."
Start-Sleep -Seconds 30

#endregion

###############################################################################
#region SYSMON version check and uninstall outdated versions                  #
###############################################################################

$sysmonprocess = Get-Process 'Sysmon*' -ErrorAction SilentlyContinue
$sysmonsvc = Get-Service -Name 'Sysmon*' -ErrorAction SilentlyContinue
$sysmonfileversion = (Get-Item -Path C:\Windows\Sysmon64.exe).VersionInfo.FileVersion

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
		    Write-Host -ForegroundColor Yellow "SYSMON service is installed and/or running, but the version is outdated. Current version installed is '${sysmonver}' compared the to new approved Sysmon version '${sysmonConfigversion}'."
		    Log-Write -LogPath $LogFile -LineValue "SYSMON service is installed and/or running, but the version is outdated. Current version installed is '${sysmonver}' compared the to new approved Sysmon version '${sysmonConfigversion}'."
            Write-Host -ForegroundColor Yellow "Uninstalling older version of SYSMON."
		    Log-Write -LogPath $LogFile -LineValue "Uninstalling older version of SYSMON."
		    If($OS64bit) {
			    & "c:\windows\sysmon64.exe" -u
		    }Else {
			    & "c:\windows\sysmon.exe" -u
		    }
	    }
    }
}
#endregion

###############################################################################
#region SYSMON Version Check, Installer, and Updater                          #
###############################################################################

If($installsysmon){
	#Checks if system is x64 or x86
	If($OS64bit) {
		& "$SysmonLogDir\Tools\$Sysmon64Bin" -accepteula -i "$SysmonLogDir\Tools\sysmon-config.xml" 
	}Else {
		& "$SysmonLogDir\Tools\$Sysmon32Bin" -accepteula -i "$SysmonLogDir\Tools\sysmon-config.xml"
	}

	$x = 0
	While (!(Get-Process Sysmon* -ErrorAction SilentlyContinue) -or !($x -eq 6)){
		Start-Sleep -Seconds 30
		$x += 1
	}

	#Checks if Sysmon is installed
	If(Get-Service -Name 'Sysmon*' -ErrorAction SilentlyContinue) {
		Write-Host -ForegroundColor Green "COMPLETED: SYSMON service was installed successfully."
		Log-Write -LogPath $LogFile -LineValue "COMPLETED:SYSMON service was installed successfully."

		#Sets registry version number for Sysmon installed
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
		
		#Sets Sysmon Windows Event Log File Size to 64MB
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
