function Get-Tls12SnacReadiness
{
    <#
        .SYNOPSIS
        Audits readiness for disabling TLS 1.0 and below.

        .DESCRIPTION
        Audits readiness for disabling TLS 1.0 and below.

        If updates are required, they will be reported in the output.

        .PARAMETER InstalledSqlFeatures
        To avoid a duplicate function call, provide all instances of installed SQL features.

        .OUTPUTS
        [psobject]

        .EXAMPLE
        Get-Tls12SnacReadiness

    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param
    (
        [Parameter(Position = 0)]
        [psobject[]]$InstalledSqlFeatures = (Software\Get-InstalledSoftware | Where-Object {$_.DisplayName -match 'SQL'})
    )

    begin
    {
        Write-Verbose "[$(Get-Date)] Begin :: $($MyInvocation.MyCommand)"
    }

    process
    {
        $Output = New-ReadinessSpecObject -Property InstalledSqlNativeClient

        $Output.InstalledSqlNativeClient = $InstalledSqlFeatures |
            Where-Object {$_.DisplayName -match 'Native Client'} |
            Sort-Object Version |
            Select-Object -Last 1


        switch ($Output.InstalledSqlNativeClient.Version)
        {
            #2012, 2014 (all SNAC versions from 2012 are called 2012 / v11)
            {$_.Major -eq 11 -and $_.Build -lt 6538}
            {
                $Output.RequiredActions += 'Update the SQL Server Native Client from https://www.microsoft.com/en-us/download/details.aspx?id=50402'
            }

            #2008 R2
            {$_.Major -eq 10 -and $_.Minor -ge 50 -and $_.Build -lt 6537}
            {
                $Output.RequiredActions += 'Update the SQL Server Native Client from https://support.microsoft.com/en-us/hotfix/kbhotfix?kbnum=3098860&kbln=en-us'
            }

            #2008
            {$_.Major -eq 10 -and $_.Minor -lt 50 -and $_.Build -lt 6543}
            {
                $Output.RequiredActions += 'Update the SQL Server Native Client from https://support.microsoft.com/en-us/hotfix/kbhotfix?kbnum=3098869&kbln=en-us'
            }

            #2005
            {$_.Major -lt 10}
            {
                $Output.RequiredActions += 'Version not known; newer version may be required'
            }

            default
            {
                # Implies $_.Major -gt 11, so if that ever happens it will support TLS 1.2
            }
        }


        $Output.SupportsTls12 = -not $Output.RequiredActions

        return $Output
    }

    end
    {
        Write-Verbose "[$(Get-Date)] End   :: $($MyInvocation.MyCommand)"
    }
}
