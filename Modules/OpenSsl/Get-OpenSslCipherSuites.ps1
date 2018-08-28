function Get-OpenSslCipherSuites
{
    [CmdletBinding()]
    param
    (
        [Parameter(Position = 0)]
        [string]$OpenSslPath = $PSScriptRoot
    )

    if (Test-Path $OpenSslPath -PathType Container)
    {
        $OpenSslPath = Join-Path $OpenSslPath 'openssl.exe'
    }

    if (-not (Test-Path $OpenSslPath))
    {
        throw New-Object System.Management.Automation.ItemNotFoundException (
            "Could not find openssl.exe at $OpenSslPath"
        )
    }

    
    $Iana = Import-PowerShellDataFile (Join-Path $PSScriptRoot 'IanaCipherSuites.psd1')
    $OpenSslCipherSuiteStrings = (& $OpenSslPath ciphers -V 2>$null)



    $IanaPattern = '(?<IanaCode>0x[0-9A-F]{2},0x[0-9A-F]{2})\s*(?<IanaName>\S*)\s*(?<DtlsOk>Y|N)\s*(?<Recommended>Y|N)\s*(?<Reference>\S*)'
    $IanaCipherSuites = @{}

    foreach ($IanaCipherSuiteString in $Iana.IanaCipherSuites)
    {
        if ($IanaCipherSuiteString -match $IanaPattern)
        {
            $Matches.Remove(0)
            $Matches.DtlsOk = $Matches.DtlsOk -like 'Y'
            $Matches.Recommended = $Matches.Recommended -like 'Y'
            $Matches.Reference = $Matches.Reference -split '\]\[' -replace '\[|\]'
            $IanaCipherSuite = [hashtable]$Matches
            $IanaCipherSuites.Add($IanaCipherSuite.IanaCode, $IanaCipherSuite)
        }
        else
        {
            #Unassigned and reserved iana codes will not parse. That's expected.
            Write-Debug "Could not parse Iana cipher suite: $IanaCipherSuiteString"
        }

    }



    $OpenSslCSPattern = '(?<IanaCode>0x[0-9A-F]{2},0x[0-9A-F]{2}) - (?<OpenSslName>\S*)\s*(?<Protocol>\S*)\s*Kx=(?<KeyExchange>\S*)\s*Au=(?<Authentication>\S*)\s*Enc=(?<Encryption>\S*)\s*Mac=(?<MessageAuthentication>\S*)'
    $CipherSuites = New-Object System.Collections.Generic.List[psobject]

    foreach ($OpenSslCipherSuiteString in $OpenSslCipherSuiteStrings)
    {
        if ($OpenSslCipherSuiteString -match $OpenSslCSPattern)
        {
            $Matches.Remove(0)
            $Matches.Protocol = $Matches.Protocol -replace 'v', ' '
            $IanaCipherSuite = $IanaCipherSuites[$Matches.IanaCode]
            $Matches.Remove('IanaCode')
            $Matches += $IanaCipherSuite
            $CipherSuite = [pscustomobject]$Matches
            $CipherSuites.Add($CipherSuite)
        }
        else
        {
            Write-Error "Could not parse OpenSsl cipher suite: $OpenSslCipherSuiteString"
        }
    }


    return $CipherSuites
}