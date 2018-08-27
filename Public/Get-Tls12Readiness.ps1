function Get-Tls12Readiness
{
    <#
    .SYNOPSIS
    Reports on the readiness for TLS 1.2 to be enforced on a system.

    .DESCRIPTION
    Provides a report for a single machine on the supportability of TLS 1.2. You can use this report
    to prepare for disabling SSL and TLS protocols below TLS 1.1.

    This command provides a list of all updates or changes that are required before a typical Windows
    stack of IIS / .NET / MS SQL Server can safely have TLS 1.0 disabled.

    .OUTPUTS
    [psobject]

    .EXAMPLE
    Get-Tls12Readiness

    SupportsTls12      : False
    RequiredUpdates    : {Install KB3106994 from https://support.microsoft.com/en-us/help/3106994, Apply SP3 from http://www.microsoft.com/en-us/download/details.aspx?id=44271, Apply TLS hotfix from https://support.microsoft.com/en-us/hot
                         fix/kbhotfix?kbnum=3144114&kbln=en-us, Apply intermittent service termination hotfix from https://support.microsoft.com/en-us/kb/3146034...}
    OS                 : Microsoft Windows Server 2008 R2 Standard
    WikiLink           : https://rax.io/Win-Disabling-TLS
    ClientTls12Enabled : True
    RdpReadiness       : Ready
    AdoDotNetReadiness : Required updates: 1
    DbEngineReadiness  : Required updates: 3
    MbuReadiness       : Ready
    OdbcReadiness      : Required updates: 1
    SnacReadiness      : Required updates: 1

    Reports on the readiness for TLS 1.2 to be enforced on a system.

    .NOTES
    Do not run this script in isolation. You should run this report on all the servers in an application
    stack. For example, this report may indicate that the database server is ready for TLS 1.2 to be
    enforced, but if the web servers do not support TLS 1.2 on the client side, the application will be
    brought down. It is the application owner's responsibility to advise which servers may be affected.

    It is possible that the application stack pins certain versions. For example:

    - .NET apps hosted in IIS may be targeting an earlier .NET version that the latest version installed
    - Database clients may be using a driver older than the latest version installed

    This report cannot assess these risks. It is the application owner's responsibility to plan for these
    risks.

    It is possible that the application has external clients that require TLS 1.0. This report cannot
    assess this risk. It is the application owner's responsibility to plan for this risk.

    Changes to enabled TLS protocols should be done in an outage window; all changed servers should be
    rebooted; the application should be tested. At a minimum, the testing plan should include:

    - Connecting to SQL through SQL Server Management Studio
    - Loading the application and performing an action that queries the database

    Relevant events are often flagged in the Application log from source SCHANNEL.

    .LINK
    https://rax.io/Win-Disabling-TLS
    #>
    begin
    {
        Write-Verbose "[$(Get-Date)] Begin :: $($MyInvocation.MyCommand)"

        $OutputProperties = (
            'SupportsTls12',
            'RequiredActions',
            'OS',
            'WikiLink',
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
        $Output                 = New-ReadinessSpecObject -Property $OutputProperties

        $WmiOS                  = Get-WmiObject Win32_OperatingSystem
        $Hotfixes               = (Get-WmiObject Win32_QuickFixEngineering)
        $InstalledSoftware      = Software\Get-InstalledSoftware
        $InstalledSqlFeatures   = $InstalledSoftware | Where-Object {$_.DisplayName -match 'SQL'}

        $RequiredActions        = @()
        $Output.OS              = $WmiOS.Caption
        $Output.WikiLink        = 'https://rax.io/Win-Disabling-TLS'


        $KB4019276              = $Hotfixes | Where-Object {$_.HotfixID -eq 'KB4019276'}

        if ([version]$WmiOS.Version -lt [version]"6.1" -and -not $KB4019276)
        {
            $OSSupportsTls12 = $false
            $RequiredActions += "Install KB4019276 from https://www.catalog.update.microsoft.com/Search.aspx?q=KB4019276"
        }
        else
        {
            $OSSupportsTls12 = $true   # so far. Can still be set to false.
        }


        $Output.ClientTls12Enabled  = (Get-TlsProtocol 'TLS 1.2 Client').Enabled
        if (-not $Output.ClientTls12Enabled)
        {
            $RequiredActions += 'Enable client-side TLS 1.2 protocol'
        }

        $Output.RdpReadiness        = Get-Tls12RdpReadiness -OperatingSystem $WmiOS -Hotfixes $Hotfixes
        $Output.AdoDotNetReadiness  = Get-Tls12AdoDotNetReadiness -Hotfixes $Hotfixes
        $Output.DbEngineReadiness   = Get-Tls12DbEngineReadiness -InstalledSqlFeatures $InstalledSqlFeatures
        $Output.MbuReadiness        = Get-Tls12MbuReadiness
        $Output.OdbcReadiness       = Get-Tls12OdbcReadiness -InstalledSqlFeatures $InstalledSqlFeatures
        $Output.SnacReadiness       = Get-Tls12SnacReadiness -InstalledSqlFeatures $InstalledSqlFeatures


        $FeaturesSupportTls12 = $true
        foreach ($Property in ($OutputProperties -match 'Readiness$'))
        {
            # Perform cumulative '-and'; will be false if even one subproperty is false
            $FeaturesSupportTls12 = $FeaturesSupportTls12 -and $Output.$Property.SupportsTls12

            $RequiredActions += $Output.$Property.RequiredActions
        }

        $Output.SupportsTls12   = $OsSupportsTls12 -and $FeaturesSupportTls12 -and $Output.ClientTls12Enabled
        $Output.RequiredActions = $RequiredActions | Where-Object {$_}  # Filter out nulls


        Write-Output $Output
    }

    end
    {
        Write-Verbose "[$(Get-Date)] End   :: $($MyInvocation.MyCommand)"
    }
}
