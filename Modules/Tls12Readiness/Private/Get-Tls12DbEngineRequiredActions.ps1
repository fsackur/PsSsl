function Get-Tls12DbEngineRequiredActions
{
    <#
        .SYNOPSIS
        Given a SQL version, returns the updates that must be applied before disabling TLS 1.0

        .DESCRIPTION
        This is just a big switch statement based on the info at https://sqlserverbuilds.blogspot.co.uk/

        Output is an array of strings; one per update

        Strings are human readable, and tell you what to install and what URL to download it from

        .PARAMETER SqlVersion
        SQL version to check

        .OUTPUTS
        [string[]]

        .EXAMPLE
        Get-Tls12DbEngineRequiredActions 10.50.0.4000

        Apply SP3 from http://www.microsoft.com/en-us/download/details.aspx?id=44271
        Apply TLS hotfix from https://support.microsoft.com/en-us/hotfix/kbhotfix?kbnum=3144113&kbln=en-us
        Apply intermittent service termination hotfix from https://support.microsoft.com/en-us/kb/3146034

        .LINK
        https://sqlserverbuilds.blogspot.co.uk/
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]   # Function name makes more sense as a plural
    [CmdletBinding()]
    [OutputType([string[]])]
    param
    (
        [Parameter(Mandatory=$true, Position=0)]
        [version]$SqlVersion
    )

    $KBs = @()

    switch ($SqlVersion)
    {
        #2008 RTM
        {$_.Major -eq 10 -and $_.Minor -lt 50}
        {
            switch ($SqlVersion.Build)
            {
                {$_ -lt 6547}   {$KBs += 'Apply intermittent service termination hotfix from https://support.microsoft.com/en-us/kb/3146034'} #Intermittent service terminations
                {$_ -lt 6543}   {$KBs += 'Apply TLS hotfix from https://support.microsoft.com/en-us/hotfix/kbhotfix?kbnum=3144113&kbln=en-us'} #TLS Update https://support.microsoft.com/en-gb/help/3135244/tls-1.2-support-for-microsoft-sql-server
                {$_ -lt 6000}   {$KBs += 'Apply SP4 from http://www.microsoft.com/en-us/download/details.aspx?id=44278'} #SP4
            }
            break
        }

        #2008 R2
        {$_.Major -eq 10 -and $_.Minor -ge 50}
        {
            switch ($SqlVersion.Build)
            {
                {$_ -lt 6542}   {$KBs += 'Apply intermittent service termination hotfix from https://support.microsoft.com/en-us/kb/3146034'}
                {$_ -lt 6537}   {$KBs += 'Apply TLS hotfix from https://support.microsoft.com/en-us/hotfix/kbhotfix?kbnum=3144114&kbln=en-us'}
                {$_ -lt 6000}   {$KBs += 'Apply SP3 from http://www.microsoft.com/en-us/download/details.aspx?id=44271'}
            }
            break
        }

        #2012
        {$_.Major -eq 11}
        {
            #If we're below SP3 but on or above SP2 CU10, then no change
            if ($SqlVersion.Build -lt 6020 -and $SqlVersion.Build -ge 5644) {break}

            #Below 6518, apply SP3 & at least CU1
            switch ($SqlVersion.Build)
            {
                {$_ -lt 6518}   {$KBs += 'Apply CU1 (or later) from https://support.microsoft.com/en-us/kb/3123299'}
                {$_ -lt 6020}   {$KBs += 'Apply SP3 from https://www.microsoft.com/en-us/download/details.aspx?id=49996'}
            }
            break
        }

        #2014
        {$_.Major -eq 12}
        {
            #If we're above SP2, then no change
            if ($SqlVersion.Build -ge 5000) {break}

            #If we're below SP2 but on or above SP1 CU5, then no change
            if ($SqlVersion.Build -lt 5000 -and $SqlVersion.Build -ge 4439) {break}

            #If we're below SP1 but on or above RTM CU12, then no change
            if ($SqlVersion.Build -lt 4050 -and $SqlVersion.Build -ge 2564) {break}

            #Otherwise, recommend SP2
            $KBs += 'Apply SP2 from https://www.microsoft.com/en-us/download/details.aspx?id=53168'

            break
        }

        #2016 and up
        {$_.Major -ge 13}
        {
            break
        }


        Default
        {
            $Message = "SQL version '$SqlVersion' not known by the SQL TLS compatibility calculator."
            $KBs     += $Message
            Write-Error $Message
        }
    }


    [array]::Reverse($KBs)
    return $KBs
}
