function Get-Tls12OSReadiness
{
    <#
        .SYNOPSIS
        Audits readiness for disabling TLS 1.0 and below.

        .DESCRIPTION
        Audits readiness for disabling TLS 1.0 and below.

        If updates are required, they will be reported in the output.

        .PARAMETER Property
        Specifies to add extra properties to the created object.

        .OUTPUTS
        [psobject]

        .EXAMPLE
        Get-Tls12OSReadiness
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param
    (
        [Parameter()]
        [string[]]$Property
    )

    begin
    {
        Write-Verbose "[$(Get-Date)] Begin :: $($MyInvocation.MyCommand)"

        $OutputProperties = (
            'SupportsTls12',
            'RequiredActions',
            'OS',
            'WikiLink',
            'ClientTls12Enabled'
        )
    }

    process
    {
        $Output            = New-ReadinessSpecObject -Property $OutputProperties
        $WmiOS             = Get-WmiOS
        $Output.OS         = $WmiOS.Caption
        $Output.WikiLink   = 'https://rax.io/Win-Disabling-TLS'


        # TLS hotfix for 2008 RTM
        $KB4019276         = Get-WmiHotfixes | Where-Object {$_.HotfixID -eq 'KB4019276'}

        if ([version]$WmiOS.Version -lt [version]"6.1" -and -not $KB4019276)
        {
            $Output.RequiredActions += "Install KB4019276 from https://www.catalog.update.microsoft.com/Search.aspx?q=KB4019276"
            $Output.RequiredActions += "Warn customer that KB4019276 is known to break FTP"
            $Output.RequiredActions += "Warn customer that KB4019276 does not add support for TLS 1.2 for RDP"
            $Output.RequiredActions += "Warn customer that KB4019276 is not recommended by Rackspace"
        }


        $Output.ClientTls12Enabled  = (Get-TlsProtocol 'TLS 1.2 Client').Enabled
        if (-not $Output.ClientTls12Enabled)
        {
            $Output.RequiredActions += 'Enable client-side TLS 1.2 protocol'
        }


        $Output.SupportsTls12 = $Output.RequiredActions.Count -eq 0
        Write-Output $Output
    }

    end
    {
        Write-Verbose "[$(Get-Date)] End   :: $($MyInvocation.MyCommand)"
    }
}
