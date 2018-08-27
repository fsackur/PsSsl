function Get-Tls12DbEngineReadiness
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
        Get-Tls12DbEngineReadiness

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
        $Output = New-ReadinessSpecObject -Property InstalledDbEngineFeatures, Instances

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
            $Instance      = New-ReadinessSpecObject -Property Name, Version
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
            $Instance.Version = [version](Get-Item $Path).VersionInfo.ProductVersion
            $RequiredActions  = Get-Tls12DbEngineRequiredActions -Version $Instance.Version


            if ($RequiredActions)
            {
                $Instance.SupportsTls12    = $false
                $Instance.RequiredActions += $RequiredActions
            }
            else
            {
                $Instance.SupportsTls12 = $true
            }

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
