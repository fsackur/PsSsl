function Get-Tls12RdpReadiness
{
    <#
        .SYNOPSIS
        Audits readiness for disabling TLS 1.0 and below.

        .DESCRIPTION
        Audits readiness for disabling TLS 1.0 and below.

        If updates are required, they will be reported in the output.

        .OUTPUTS
        [psobject]

        .EXAMPLE
        Get-Tls12RdpReadiness
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param ()

    begin
    {
        Write-Verbose "[$(Get-Date)] Begin :: $($MyInvocation.MyCommand)"
    }

    process
    {
        $OperatingSystem = Get-WmiOS
        $Hotfixes        = Get-WmiHotfixes
        $Output          = New-ReadinessSpecObject -AddMember RdpSecurityLayer
        $Version         = [version]$OperatingSystem.Version
        $Output.RdpSecurityLayer = Get-RdpSecurityLayer

        switch ($Version)
        {
            # 2012 RTM and above
            {$_ -ge [version]"6.2"}
            {
                break   # Supports TLS 1.2
            }

            # 2008 R2
            {$_ -ge [version]"6.1"}
            {
                $KB3080079 = $Hotfixes | Where-Object {$_.HotfixID -eq 'KB3080079'}
                if (-not $KB3080079)
                {
                    $Output.RequiredActions += "Install KB3080079 from https://www.catalog.update.microsoft.com/Search.aspx?q=KB3080079"
                }
                break
            }

            # 2008 RTM
            default
            {
                if ($Output.RdpSecurityLayer -ne 'Rdp')
                {
                    $Output.RequiredActions += (
                        "Set RDP security layer to 'Rdp'",
                        "Warn customer that RDP security will be reduced"
                    )
                }
                break
            }
        }

        $Output.SupportsTls12 = $Output.RequiredActions.Count -eq 0
        Write-Output $Output
    }

    end
    {
        Write-Verbose "[$(Get-Date)] End   :: $($MyInvocation.MyCommand)"
    }
}
