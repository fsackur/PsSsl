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
    param
    (
        #[Parameter(Mandatory, Position = 0)]
        #[psobject]$CipherSuite,

        [Parameter(Position = 0)]
        [string]$OpenSslPath = $PSScriptRoot
    )

    #$OpenSslPath = Join-Path $PSScriptRoot 'Packages\openssl\openssl.exe'

    $Protocols = 'TLS 1.0', 'TLS 1.1', 'TLS 1.2'
    
    $ProtocolResults = @{}

    foreach ($Protocol in $Protocols)
    {
        <#
            openssl is a pig because, on successful connection with the s_client option, it waits for input.
            It listens for input on the console, not on the stdin.

            You can use ProcessInfo.StandardInput.Write("Q") when running in a powershell console, but not an
            intergrate editor, because then openssl will be in a separate window and StdIn in your editor
            won't go to the console of openssl's console host.

            You can't use ProcessInfo.StandardOutput.ReadToEnd(), or it hangs the script until openssl times
            out (far too long). If you use .ReadToEndAsync(), kill the process, then invoke the async result,
            you get nothing.
        #>
        $OutputChars = New-Object System.Collections.Generic.List[char]
        $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
        $Process     = New-Object System.Diagnostics.Process

        $ProcessInfo.FileName               = $OpenSslPath
        $ProcessInfo.RedirectStandardError  = $true
        $ProcessInfo.RedirectStandardOutput = $true
        $ProcessInfo.RedirectStandardInput  = $true
        $ProcessInfo.UseShellExecute        = $false
        $ProcessInfo.Arguments = (
            "s_client",
            "-connect",
            "localhost:5986",
            '-' + ($Protocol -replace ' ' -replace '\.', '_').ToLower()    #-tls1_2
        )

        $Process.StartInfo = $ProcessInfo
        $null = $Process.Start()
        Start-Sleep -Milliseconds 100


        while ($Process.StandardOutput.Peek() -gt 0)
        {
            $OutputChars.Add(([char]$Process.StandardOutput.Read()))
        }

        $OpenSslOutput = $OutputChars -join ''
        #$Process.Kill()  #access denied...?
        $Process.Dispose()



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
            $ProtocolResult | Add-Member -Name $Group.Name -Value $Group.Value
        }

        $ProtocolResults[$Protocol] = $ProtocolResult
    }

    $ProtocolResults
}