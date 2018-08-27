function Get-Tls12AdoDotNetReadiness
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
        Get-Tls12AdoDotNetReadiness
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
        $OperatingSystem = Get-WmiOS
        $Hotfixes        = Get-WmiHotfixes
        $Output          = New-ReadinessSpecObject -Property 'DotNetVersion'

        $OSVersion       = [version]$OperatingSystem.Version
        $DotNetVersion   = Software\Get-DotNetVersion | Sort-Object | Select-Object -Last 1

        if ($DotNetVersion)
        {
            $Output.DotNetVersion = $DotNetVersion
        }
        else
        {
            $Output.SupportsTls12 = $true
            Write-Warning "No .NET Framework version detected. This is unusual. Please manually verify whether any version of the .NET Framework is installed and, if so, report a bug."
            return $Output
        }


        switch ($DotNetVersion)
        {
            {$_ -ge [version]"4.6"}
            {
                $Output.SupportsTls12 = $true
                break
            }

            {$_ -ge [version]"4.5"}
            {
                # Because 2016 ships with .NET 4.6 and 2003 is out of support, we know that OS major version -eq 6
                switch ($OSVersion.Minor)
                {
                    3       # 2012 R2
                    {
                        $KB3099842 = $Hotfixes | Where-Object {$_.HotfixID -eq 'KB3099842'}
                        if ($KB3099842)
                        {
                            $Output.SupportsTls12 = $true
                        }
                        else
                        {
                            $Output.RequiredActions += 'Apply KB3099842 from https://support.microsoft.com/en-us/help/3099842'
                        }
                        break
                    }

                    2       # 2012 RTM
                    {
                        $KB3099844 = $Hotfixes | Where-Object {$_.HotfixID -eq 'KB3099844'}
                        if ($KB3099844)
                        {
                            $Output.SupportsTls12 = $true
                        }
                        else
                        {
                            $Output.RequiredActions += 'Apply KB3099844 from https://support.microsoft.com/en-us/help/3099844'
                        }
                        break
                    }

                    default # 2008 RTM & R2
                    {
                        switch ($DotNetVersion)
                        {
                            {$_ -ge [version]"4.5.3"}
                            {
                                $Output.SupportsTls12 = $true
                                break
                            }

                            {$_ -ge [version]"4.5.1"}
                            {
                                if ($Hotfixes | Where-Object {$_.HotfixID -eq 'KB3099845'})
                                {
                                    $Output.SupportsTls12 = $true
                                }
                                else
                                {
                                    $Output.RequiredActions += 'Apply KB3099845 from https://support.microsoft.com/en-us/help/3099845'
                                }
                                break
                            }

                            {$_ -ge [version]"4.5"}
                            {
                                $Output.RequiredActions += 'Install .NET 4.5.1 or higher from https://www.microsoft.com/en-gb/download/details.aspx?id=40779'
                                $Output.RequiredActions += 'Rerun TLS 1.2 readiness checks'
                                break
                            }
                        }
                    }
                }

                break
            }

            {$_ -ge [version]"4.0"}
            {
                $Output.RequiredActions += 'Install KB3106994 from https://support.microsoft.com/en-us/help/3106994'
                break
            }

            {$_ -lt [version]"4.0"}
            {
                $Output.RequiredActions += 'Assessment of .NET framework below 4 must be done manually'
                $Output.RequiredActions += 'Refer to https://support.microsoft.com/en-us/help/3135244/tls-1-2-support-for-microsoft-sql-server'
                $Output.RequiredActions += 'Suggest customer migrate to more recent version of the .NET framework'
                break
            }
        }


        Write-Output $Output
    }

    end
    {
        Write-Verbose "[$(Get-Date)] End   :: $($MyInvocation.MyCommand)"
    }
}
