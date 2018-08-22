function Get-Tls12MbuReadiness
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
        Get-Tls12MbuReadiness

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
        $Output = New-Object PSObject -Property @{
            SupportsTls12   = $false
            RequiredUpdates = @()
        }
    }

    end
    {
        Write-Verbose "[$(Get-Date)] End   :: $($MyInvocation.MyCommand)"
    }
}

