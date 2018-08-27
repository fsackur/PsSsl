﻿function Get-Tls12RdpReadiness
{
    <#
        .SYNOPSIS
        Audits readiness for disabling TLS 1.0 and below.

        .DESCRIPTION
        Audits readiness for disabling TLS 1.0 and below.

        If updates are required, they will be reported in the output.

        .PARAMETER OperatingSystem
        To avoid a duplicate WMI query, provide an instance of the WMI class Win32_OperatingSystem.

        .PARAMETER Hotfixes
        To avoid a duplicate WMI query, provide all instances of the WMI class Win32_QuickFixEngineering.

        .OUTPUTS
        [psobject]

        .EXAMPLE
        Get-Tls12RdpReadiness
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param
    (
        [Parameter(Position = 0)]
        [ValidateScript({$_.__CLASS -eq 'Win32_OperatingSystem'})]
        [System.Management.ManagementObject]$OperatingSystem = (Get-WmiObject Win32_OperatingSystem),

        [Parameter(Position = 1)]
        [ValidateScript( {$_.__CLASS -eq 'Win32_QuickFixEngineering'})]
        [System.Management.ManagementObject[]]$Hotfixes = (Get-WmiObject Win32_QuickFixEngineering)
    )

    begin
    {
        Write-Verbose "[$(Get-Date)] Begin :: $($MyInvocation.MyCommand)"
    }

    process
    {
        $Output = New-ReadinessSpecObject

        $Version = [version]$OperatingSystem.version
        switch ($Version)
        {
            # 2012 RTM and above
            {$_ -ge [version]"6.2"}
            {
                $Output.SupportsTls12 = $true
                break
            }

            # 2008 R2
            {$_ -ge [version]"6.1"}
            {
                $KB3080079 = $Hotfixes | Where-Object {$_.HotfixID -eq 'KB3080079'}
                if ($KB3080079)
                {
                    $Output.SupportsTls12 = $true
                }
                else
                {
                    $Output.SupportsTls12    = $false
                    $Output.RequiredActions += "Install KB3080079 from https://www.catalog.update.microsoft.com/Search.aspx?q=KB3080079"
                }
                break
            }

            # 2008 RTM
            default
            {
                if ((Get-RdpSecurityLayer) -eq 'Rdp')
                {
                    $Output.SupportsTls12 = $true
                }
                else
                {
                    $Output.SupportsTls12    = $false
                    $Output.RequiredActions += (
                        "Set RDP security layer to 'Rdp'",
                        "Warn customer that RDP security will be reduced"
                    )
                }
                break
            }
        }

        Write-Output $Output
    }

    end
    {
        Write-Verbose "[$(Get-Date)] End   :: $($MyInvocation.MyCommand)"
    }
}
