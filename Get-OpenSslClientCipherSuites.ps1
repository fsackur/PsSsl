function Get-OpenSslClientCipherSuites
{
    [CmdletBinding()]
    param ()

    $OpenSslText = Invoke-OpenSsl -ArgumentList "ciphers", 'ALL:eNULL'
    $CipherSuites = $OpenSslText -split ':'

    return $CipherSuites
}