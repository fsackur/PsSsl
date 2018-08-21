function Get-DotNetVersion {
    <#
        .SYNOPSIS
        Returns all the installed versions of .NET

        .DESCRIPTION
        Full description: Returns all the installed versions of .NET
        WHAM - supported: Yes
        WHAM - keywords: .NET,Version,framework
        WHAM - Prerequisites: No
        WHAM - Makes changes: No
        WHAM - Column Header: DotNetVersion
        WHAM - Script time out (min): 1
        WHAM - Isolate: Yes

        .EXAMPLE
        Full command: Get-DotNetVersion

        .OUTPUTS
        DisplayVersion Version        Release
        ---            -------        -------
        v2.0.50727     2.0.50727.4927
        v3.0           3.0.30729.4926
        v3.5           3.5.30729.4926
        v4.5.2         4.5.2          379893
        v4.5.2         4.5.2          379893
        v4.0           4.0.0.0

        .LINK
        https://docs.microsoft.com/en-us/dotnet/framework/migration-guide/how-to-determine-which-versions-are-installed

        .NOTES
        Last Updated: 27-JUL-2017
        Minimum OS: 2008 R2
        Minimum PoSh: 2.0

        Version Table:
        Version :: Author          :: Live Date   :: JIRA     :: QC             :: Description
        -----------------------------------------------------------------------------------------------------------
        1.1     :: Freddie Sackur  :: 27-JUL-2017 :: IAWW-1532::  :: Release
        1.0     :: Chester Beckett :: 22-MAR-2016 :: IAWW-000 :: Freddie Sackur :: Release
    #>

    try {
        #Ref: https://docs.microsoft.com/en-us/dotnet/framework/migration-guide/how-to-determine-which-versions-are-installed
        $dotNet4Builds = @{
            378389 = 'v4.5'
            378675 = 'v4.5.1'
            378758 = 'v4.5.1'
            379893 = 'v4.5.2'
            393295 = 'v4.6'
            393297 = 'v4.6'
            394254 = 'v4.6.1'
            394271 = 'v4.6.1'
            394802 = 'v4.6.2'
            394806 = 'v4.6.2'
            460798 = 'v4.7'
            460805 = 'v4.7'
        }

        $RegKey = 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP'

        $RawVersions = Get-ChildItem $RegKey -ErrorAction Stop |
                #Get the first level children (not all versions of GCI have the -Depth parameter)
                Get-ChildItem |
                Get-ItemProperty -name Version, Release -ErrorAction SilentlyContinue |
                Select Version, Release, @{Name='DisplayVersion'; Expression={Split-Path $_.PSParentPath -Leaf}}

        $CorrectVersions = $RawVersions | foreach {
            #v4.5 and above now uses the Release property to indicate installed version
            if ($_.Release) {
                $RealDisplayVersion = $dotNet4Builds[([int]$_.Release)]
                if ($null -eq $RealDisplayVersion) {$RealDisplayVersion = 'Unknown'}
                $_.DisplayVersion = $RealDisplayVersion

                $_.Version = $RealDisplayVersion -replace '[^\d\.]'  #Just the digits and full stops
            }

            #Convert version property to version object - any caller that uses this probably needs a version
            try {
                $_.Version = [version]$_.Version
            } catch {
                $_.Version = $null
            }

            return $_
        }

        return $CorrectVersions |
            select DisplayVersion, Version, Release, @{Name='Server'; Expression={$env:COMPUTERNAME}}


    } catch {
        $ErrorMsg = "Exception {0} at line {1}: {2}" -f (
            $_.Exception.GetType().Name,
            $LineNumber,
            $_.InvocationInfo.Line
        )

        return New-Object psobject -Property @{
            Server = $env:COMPUTERNAME
            DisplayVersion = $ErrorMsg
            Version = $null
            Release = $null
        }
    }
}
