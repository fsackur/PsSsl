function Get-OpenSslClientCipherSuites
{
    [CmdletBinding()]
    param (
        [Parameter(Position = 0)]
        [ValidateSet(
            'SSL 2.0'
            'SSL 3.0'
            'TLS 1.0'
            'TLS 1.1'
            'TLS 1.2'
        )]
        [string]$Protocol
    )

    $ProtocolSwitchLookup = @{
        'SSL 2.0' = '-ssl2'
        'SSL 3.0' = '-ssl3'
        'TLS 1.0' = '-tls1'
    }

    $ArgumentList = @("ciphers ALL:eNULL")
    if ($PSBoundParameters.ContainsKey('Protocol') -and $ProtocolSwitchLookup.ContainsKey($Protocol))
    {
        $ArgumentList += $ProtocolSwitchLookup[$Protocol]
    }
    $OpenSslText = Invoke-OpenSsl -ArgumentList $ArgumentList
    $CipherSuites = $OpenSslText -split ':'

    return $CipherSuites
}