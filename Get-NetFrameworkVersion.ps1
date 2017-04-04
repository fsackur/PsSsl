<#

Script Name	: Get-NetFrameworkVersion.ps1
Description	: This script reports the various .NET Framework versions installed on the local or a remote computer.
Author		: Martin Schvartzman
Last Update	: Aug-2016
Keywords	: NETFX, Registry
Reference   : https://msdn.microsoft.com/en-us/library/hh925568

#>

param($ComputerName = $env:COMPUTERNAME)

$dotNetRegistry  = 'SOFTWARE\Microsoft\NET Framework Setup\NDP'
$dotNet4Registry = 'SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full'
$dotNet4Builds = @{
	30319  =  '.NET Framework 4.0'
	378389 = '.NET Framework 4.5'
	378675 = '.NET Framework 4.5.1 (8.1/2012R2)'
	378758 = '.NET Framework 4.5.1 (8/7 SP1/Vista SP2)'
	379893 = '.NET Framework 4.5.2' 
	380042 = '.NET Framework 4.5 and later with KB3168275 rollup'
	393295 = '.NET Framework 4.6 (Windows 10)'
	393297 = '.NET Framework 4.6 (NON Windows 10)'
	394254 = '.NET Framework 4.6.1 (Windows 10)'
	394271 = '.NET Framework 4.6.1 (NON Windows 10)'
	394802 = '.NET Framework 4.6.2 (Windows 10 Anniversary Update)'
	394806 = '.NET Framework 4.6.2 (NON Windows 10)'
}

foreach($Computer in $ComputerName) {

	if($regKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $Computer)) {

		if ($netRegKey = $regKey.OpenSubKey("$dotNetRegistry")) {
			foreach ($versionKeyName in $netRegKey.GetSubKeyNames()) {
				if ($versionKeyName -match '^v[123]') {
					$versionKey = $netRegKey.OpenSubKey($versionKeyName)
					$version = [version]($versionKey.GetValue('Version', ''))
					New-Object -TypeName PSObject -Property @{
						ComputerName = $Computer
						NetFXBuild = $version.Build
						NetFXVersion = '.NET Framework ' + $version.Major + '.' + $version.Minor
					} | Select-Object ComputerName, NetFXVersion, NetFXBuild
				}
			}
		}

		if ($net4RegKey = $regKey.OpenSubKey("$dotNet4Registry")) {
			if(-not ($net4Release = $net4RegKey.GetValue('Release'))) {
				$net4Release = 30319
			}
			New-Object -TypeName PSObject -Property @{
				ComputerName = $Computer
				NetFXBuild = $net4Release
				NetFXVersion = $dotNet4Builds[$net4Release]
			} | Select-Object ComputerName, NetFXVersion, NetFXBuild
		}
	}
}
