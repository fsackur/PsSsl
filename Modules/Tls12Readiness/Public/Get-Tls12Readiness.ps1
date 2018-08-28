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
    RequiredActions    : {Install KB3106994 from https://support.microsoft.com/en-us/help/3106994, Apply SP3 from http://www.microsoft.com/en-us/download/details.aspx?id=44271, Apply TLS hotfix from https://support.microsoft.com/en-us/hot
                         fix/kbhotfix?kbnum=3144114&kbln=en-us, Apply intermittent service termination hotfix from https://support.microsoft.com/en-us/kb/3146034...}
    OS                 : Microsoft Windows Server 2008 R2 Standard
    WikiLink           : https://rax.io/Win-Disabling-TLS
    ClientTls12Enabled : True
    RdpReadiness       : Ready
    AdoDotNetReadiness : Required actions: 1
    DbEngineReadiness  : Required actions: 3
    MbuReadiness       : Ready
    OdbcReadiness      : Required actions: 1
    SnacReadiness      : Required actions: 1

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
        $Output                     = Get-Tls12OSReadiness
        $NestedProperties           = $OutputProperties -match 'Readiness$'

        foreach ($Property in $NestedProperties)
        {
            Add-Member -InputObject $Output 'NoteProperty' -Name $Property -Value $null
        }

        # The nested properties
        $Output.RdpReadiness        = Get-Tls12RdpReadiness
        $Output.AdoDotNetReadiness  = Get-Tls12AdoDotNetReadiness
        $Output.DbEngineReadiness   = Get-Tls12DbEngineReadiness
        $Output.MbuReadiness        = Get-Tls12MbuReadiness
        $Output.OdbcReadiness       = Get-Tls12OdbcReadiness
        $Output.SnacReadiness       = Get-Tls12SnacReadiness


        foreach ($Property in $NestedProperties)
        {
            # Perform cumulative '-and'; will end up false if even one subproperty is false
            $Output.SupportsTls12 = $Output.SupportsTls12 -and $Output.$Property.SupportsTls12

            if ($Output.$Property.RequiredActions)
            {
                $Output.RequiredActions += $Output.$Property.RequiredActions
            }
        }

        Write-Output $Output
    }

    end
    {
        Write-Verbose "[$(Get-Date)] End   :: $($MyInvocation.MyCommand)"
    }
}
