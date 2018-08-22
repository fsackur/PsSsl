function Get-Tls12RdpReadiness
{
    <#
        .SYNOPSIS
        Audits readiness for disabling TLS 1.0 and below.

        .DESCRIPTION
        Audits readiness for disabling TLS 1.0 and below.

        If updates are required, they will be reported in the output.

        .PARAMETER OperatingSystem
        To avoid a duplicate WMI query, provide an instance of the WMI class Win32_OperatingSystem.

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
        [System.Management.ManagementObject]$OperatingSystem = (Get-WmiObject Win32_OperatingSystem)
    )

    begin
    {
        Write-Verbose "[$(Get-Date)] Begin :: $($MyInvocation.MyCommand)"
    }

    process
    {
        $Output = New-Object PSObject -Property @{
            SupportsTls12   = $false
            RequiredUpdates = @()
        }

        $Version = [version]$OperatingSystem.version
        switch ($Version)
        {
            {$_ -ge 6.2}
            {
                $Output.SupportsTls12 = $true
                break
            }

            {$_ -lt 6.1}
            {
                if ((Get-RdpSecurityLayer) -eq 'Rdp')
                {
                    $Output.SupportsTls12 = $true
                }
                else
                {
                    $Output.SupportsTls12 = $false
                    $Output.RequiredUpdates += (
                        "Set RDP security layer to 'Rdp'",
                        "Warn customer that RDP security will be reduced"
                    )
                }
                break
            }

            default
            {
                $RdpHotfix = Get-WmiObject Win32_QuickFixEngineering -Filter "HotFixID LIKE 'KB3080079'"
                if ($RdpHotfix)
                {
                    $Output.SupportsTls12 = $true
                }
                else
                {
                    $Output.SupportsTls12 = $false
                    $Output.UpdatesRequired += "Install KB3080079 from https://www.catalog.update.microsoft.com/Search.aspx?q=KB3080079"
                }
            }
        }

        Write-Output $Output
    }

    end
    {
        Write-Verbose "[$(Get-Date)] End   :: $($MyInvocation.MyCommand)"
    }
}
