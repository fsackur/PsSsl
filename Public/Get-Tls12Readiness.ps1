function Get-Tls12Readiness
{
    begin
    {
        Write-Verbose "[$(Get-Date)] Begin :: $($MyInvocation.MyCommand)"

        $OutputProperties = (
            'SupportsTls12',
            'RequiredUpdates',
            'OS',
            'WikiLink',
            'ClientTls11Enabled',
            'ClientTls12Enabled',
            'RdpReadiness',
            'AdoDotNetReadiness',
            'DbEngineReadiness',
            'MbuReadiness',
            'OdbcReadiness',
            'SnacReadiness'
        )
    }

    process
    {
        $Output          = New-ReadinessSpecObject -NoteProperty $OutputProperties

        $WmiOS           = Get-WmiObject Win32_OperatingSystem
        $Hotfixes        = (Get-WmiObject Win32_QuickFixEngineering)

        $RequiredUpdates = @()
        $Output.OS       = $WmiOS.Caption
        $Output.WikiLink = 'https://rax.io/Win-Disabling-TLS'


        $KB4019276       = $Hotfixes | Where-Object {$_.HotfixID -eq 'KB4019276'}

        if ([version]$WmiOS.Version -lt [version]"6.1" -and -not $KB4019276)
        {
            $Output.SupportsTls12 = $false
            $RequiredUpdates += "Install KB4019276 from https://www.catalog.update.microsoft.com/Search.aspx?q=KB4019276"
        }
        else
        {
            $Output.SupportsTls12 = $true
        }


        $Output.RdpReadiness        = Get-Tls12RdpReadiness -OperatingSystem $WmiOS -Hotfixes $Hotfixes
        $Output.AdoDotNetReadiness  = Get-Tls12AdoDotNetReadiness -Hotfixes $Hotfixes
        $Output.DbEngineReadiness   = Get-Tls12DbEngineReadiness
        $Output.MbuReadiness        = Get-Tls12MbuReadiness
        $Output.OdbcReadiness       = Get-Tls12OdbcReadiness
        $Output.SnacReadiness       = Get-Tls12SnacReadiness


        $FeaturesSupportTls12 = $true
        foreach ($Property in ($OutputProperties -match 'Readiness$'))
        {
            # Perform cumulative '-and'; will be false if even one subproperty is false
            $FeaturesSupportTls12 = $FeaturesSupportTls12 -and $Output.$Property.SupportsTls12

            $RequiredUpdates += $Output.$Property.RequiredUpdates
        }

        $Output.SupportsTls12   = $Output.SupportsTls12 -and $FeaturesSupportTls12
        $Output.RequiredUpdates = $RequiredUpdates
    }

    end
    {
        Write-Output $Output

        Write-Verbose "[$(Get-Date)] End   :: $($MyInvocation.MyCommand)"
    }
}
