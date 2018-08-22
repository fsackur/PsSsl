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

        $WikiLink = 'https://rax.io/Win-Disabling-TLS'
    }

    process
    {
        $Output = New-Object PSObject
        foreach ($Property in $OutputProperties)
        {
            Add-Member -InputObject $Output NoteProperty -Name $Property -Value $null
        }

        $RequiredUpdates = @()

        $WmiOS           = Get-WmiObject Win32_OperatingSystem
        $Output.OS       = $WmiOS.Caption

        $Output.WikiLink = $WikiLink


        $Output.RdpReadiness        = Get-Tls12RdpReadiness
        $Output.AdoDotNetReadiness  = Get-Tls12AdoDotNetReadiness
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
    }

    end
    {
        Write-Output $Output

        Write-Verbose "[$(Get-Date)] End   :: $($MyInvocation.MyCommand)"
    }
}
