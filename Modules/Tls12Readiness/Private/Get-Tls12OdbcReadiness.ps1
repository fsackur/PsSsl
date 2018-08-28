function Get-Tls12OdbcReadiness
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
        Get-Tls12OdbcReadiness
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
        $InstalledSqlFeatures = Get-InstalledSqlFeatures
        $Output = New-ReadinessSpecObject -AddMember InstalledOdbcDriver

        $Output.InstalledOdbcDriver = $InstalledSqlFeatures |
            Where-Object {$_.DisplayName -match 'ODBC'} |
            Sort-Object Version |
            Select-Object -Last 1

        if ($Output.InstalledOdbcDriver.Version -lt [version]"12.0.4219")
        {
            $Output.RequiredActions += 'Update SQL ODBC driver from https://www.microsoft.com/en-us/download/details.aspx?id=36434'
        }
        else
        {
            $Output.SupportsTls12 = $true
        }

        return $Output
    }

    end
    {
        Write-Verbose "[$(Get-Date)] End   :: $($MyInvocation.MyCommand)"
    }
}
