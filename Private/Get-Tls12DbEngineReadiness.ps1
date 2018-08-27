﻿function Get-Tls12DbEngineReadiness
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
        Get-Tls12DbEngineReadiness

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
        $InstalledSqlFeatures = Get-InstalledSqlFeatures
        $Output = New-ReadinessSpecObject -AddMember InstalledDbEngineFeatures, Instances

        $Output.InstalledDbEngineFeatures = $InstalledSqlFeatures |
            Where-Object {$_.DisplayName -match 'Database Engine'} |
            Sort-Object * -Unique

        $Output.Instances = @()

        # Bail early if no relevant features
        if (-not $Output.InstalledDbEngineFeatures)
        {
            $Output.SupportsTls12 = $true
            return $Output
        }

        $WmiDbEngineServices = Get-WmiObject -Query "SELECT DisplayName, PathName FROM Win32_Service WHERE PathName LIKE '%sqlservr.exe%'"
        $DbEngineServices    = $WmiDbEngineServices | Select-Object (
            @{Name = 'InstanceName'; Expression = {$_.DisplayName -replace '.*\(' -replace '\)'}},
            'PathName'
        )

        foreach ($Service in $DbEngineServices)
        {
            $Instance      = New-ReadinessSpecObject -AddMember Name, Version
            $Instance.Name = $Service.InstanceName

            #Strip out the CLI switches from the WMI Service PathName property
            if ($Service.PathName -match '^"(?<Path>.*?)"')
            {
                $Path = $Matches.Path
            }
            else
            {
                #If the path is unquoted, then it contains no whitespace, and anything after a whitespace must be an argument
                $Path = $Service.PathName -replace '\s.*'
            }

            # Get the SQL version from the service binary
            $Instance.Version         = [version](Get-Item $Path).VersionInfo.ProductVersion
            $Instance.RequiredActions = Get-Tls12DbEngineRequiredActions -SqlVersion $Instance.Version
            $Instance.SupportsTls12   = $Instance.RequiredActions.Count -eq 0

            $Output.Instances += $Instance
        }


        $Output.SupportsTls12   = $null -eq ($Output.Instances | Where-Object {-not $_.SupportsTls12})
        $Output.RequiredActions = $Output.Instances | Select-Object -ExpandProperty RequiredActions -Unique

        Write-Output $Output
    }

    end
    {
        Write-Verbose "[$(Get-Date)] End   :: $($MyInvocation.MyCommand)"
    }
}
