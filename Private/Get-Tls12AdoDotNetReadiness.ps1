﻿function Get-Tls12AdoDotNetReadiness
{
    <#
        .SYNOPSIS
        Audits readiness for disabling TLS 1.0 and below.

        .DESCRIPTION
        Audits readiness for disabling TLS 1.0 and below.

        If updates are required, they will be reported in the output.

        .PARAMETER InstalledDotNetVersion
        To avoid a duplicate function call, provide one or more installed .NET versions.

        .PARAMETER Hotfixes
        To avoid a duplicate WMI query, provide all instances of the WMI class Win32_QuickFixEngineering.

        .OUTPUTS
        [psobject]

        .EXAMPLE
        Get-Tls12AdoDotNetReadiness

    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param
    (
        [Parameter(Position = 0)]
        [psobject[]]$InstalledDotNetVersion = (Get-DotNetVersion),

        [Parameter(Position = 1)]
        [ValidateScript( {$_.__CLASS -eq 'Win32_QuickFixEngineering'})]
        [System.Management.ManagementObject]$Hotfixes = (Get-WmiObject Win32_QuickFixEngineering)
    )

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

        $OSVersion = [version]$OperatingSystem.Version
        $DotNetVersion = $InstalledDotNetVersion |
            Sort-Object Version |
            Select-Object -ExpandProperty Version -Last 1

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
                            $Output.RequiredUpdates += 'Apply KB3099842 from https://support.microsoft.com/en-us/help/3099842'
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
                            $Output.RequiredUpdates += 'Apply KB3099844 from https://support.microsoft.com/en-us/help/3099844'
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
                                    $Output.RequiredUpdates += 'Apply KB3099845 from https://support.microsoft.com/en-us/help/3099845'
                                }
                                break
                            }

                            {$_ -ge [version]"4.5"}
                            {
                                $Output.RequiredUpdates += 'Install .NET 4.5.1 or higher from https://www.microsoft.com/en-gb/download/details.aspx?id=40779'
                                $Output.RequiredUpdates += 'Rerun TLS 1.2 readiness checks'
                                break
                            }
                        }
                    }
                }

                break
            }

            {$_ -ge [version]"4.0"}
            {
                $Output.RequiredUpdates += 'Install KB3106994 from https://support.microsoft.com/en-us/help/3106994'
                break
            }

            {$_ -lt [version]"4.0"}
            {
                $Output.RequiredUpdates += 'Assessment of .NET framework below 4 must be done manually'
                $Output.RequiredUpdates += 'Refer to https://support.microsoft.com/en-us/help/3135244/tls-1-2-support-for-microsoft-sql-server'
                $Output.RequiredUpdates += 'Suggest customer migrate to more recent version of the .NET framework'
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
