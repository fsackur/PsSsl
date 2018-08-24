function Get-Tls12DbEngineReadiness
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
    param (
        [Parameter(Position = 0)]
        [psobject[]]$InstalledSqlFeatures = (Software\Get-InstalledSoftware | Where-Object {$_.DisplayName -match 'SQL'})
    )

    begin
    {
        Write-Verbose "[$(Get-Date)] Begin :: $($MyInvocation.MyCommand)"
    }

    process
    {
        $Output = New-ReadinessSpecObject -NoteProperty InstalledDbEngineFeatures, Instances

        $Output.InstalledDbEngineFeatures = $InstalledDbEngineFeatures = $InstalledSqlFeatures |
            Where-Object {$_.DisplayName -match 'Database Engine'} |
            Select-Object * -Unique

        $Output.Instances = @()

        # Bail early if no relevant features
        if (-not $InstalledDbEngineFeatures)
        {
            $Output.SupportsTls12 = $true
            return $Output
        }

        $DbEngineServices = Get-WmiObject Win32_Service -Filter "PathName LIKE '%sqlservr.exe%'" |
            Select-Object (
                @{Name='Instance'; Expression={$_.DisplayName -replace '.*\(' -replace '\)'}},
                'PathName'
            )

        foreach ($Service in $DbEngineServices)
        {
            $Instance = New-ReadinessSpecObject -NoteProperty Name, Version
            $Instance.Name = $Service.Instance

            #Strip out the CLI switches from the WMI Service PathName property
            if ($Service.PathName -match '^"(?<Path>.*?)"')
            {
                $Path = $Matches.Path
            }
            else
            {
                #If the path is unquoted, then it contains no whitespace, and anything after a whitespace is an argument
                $Path = $Service.PathName -replace '\s.*'
            }

            # Get the SQL version from the service binary
            $Instance.Version = [version](Get-Item $Path).VersionInfo.ProductVersion
            $Updates = Get-SqlTlsUpdatesRequired -Version $Instance.Version

            if ($Updates)
            {
                $Instance.SupportsTls12 = $false
                $Instance.RequiredUpdates += $Updates
            }
            else
            {
                $Instance.SupportsTls12 = $true
            }

            $Output.Instances += $Instance
        }

        $Output.SupportsTls12 = $null -eq ($Output.Instances | Where-Object {-not $_.SupportsTls12})
        $Output.RequiredUpdates = $Output.Instances | Select-Object -ExpandProperty RequiredUpdates -Unique
        Write-Output $Output
    }

    end
    {
        Write-Verbose "[$(Get-Date)] End   :: $($MyInvocation.MyCommand)"
    }
}
