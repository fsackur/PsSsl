function Test-OpenSslCipherSuites
{
    <#
        Sadly, the following seems to need admin:
        $env:ChocolateyInstall = (New-Item Packages -ItemType Directory)
        choco install openssl.light -y

        Register-PackageSource -Name NuGetv2 -ProviderName NuGet -Location https://www.nuget.org/api/v2
        Install-Package openssl-vc141 -Source NuGetv2 -RequiredVersion 1.1.0 -Path Packages -Scope CurrentUser
    #>
    [CmdletBinding()]
    param ()
    
    $Protocols = 'TLS 1.0'
    $ProtocolSwitchLookup = @{
        'TLS 1.0' = '-tls1'
        'TLS 1.1' = '-tls1_1'
        'TLS 1.2' = '-tls1_2'
    }
    $ProtocolResults = @{}

    foreach ($Protocol in $Protocols)
    {
        $CipherSuites = Get-OpenSslClientCipherSuites -Protocol $Protocol

        $ProtocolSwitch = $ProtocolSwitchLookup[$Protocol]

        foreach ($CipherSuite in $CipherSuites[0..1])
        {
            $TextOutput = Invoke-OpenSsl -ArgumentList "s_client -connect localhost:5986", $ProtocolSwitch


            <#Example output:
                SSL-Session:
                    Protocol  : TLSv1.1
                    Cipher    : ECDHE-RSA-AES256-SHA
                    Session-ID: CA1A0000B15...
                    Session-ID-ctx: 
                    Master-Key: 27987D8A8E1...
                    Key-Arg   : None
                    PSK identity: None
                    PSK identity hint: None
                    SRP username: None
                    Start Time: 1530631597
                    Timeout   : 7200 (sec)
                    Verify return code: 18 (self signed certificate)
            #>

            $Pattern = 'SSL-Session:\s*Protocol  : (?<Protocol>\S*)\s*Cipher    : (?<Cipher>\S*)'

            $Match = [regex]::Match(
                $TextOutput,
                $Pattern,
                [System.Text.RegularExpressions.RegexOptions]::Singleline
            )

            $ProtocolResult = New-Object psobject

            foreach ($Group in $Match.Groups)
            {
                if ($Group.Name -eq 0) {continue}
                $ProtocolResult | Add-Member 'NoteProperty' -Name $Group.Name -Value $Group.Value
            }

            $ProtocolResults[$Protocol] = $ProtocolResult
        }
    }

    $ProtocolResults
}

Test-OpenSslCipherSuites