function Test-OpenSslCipherSuites
{
    <#
        Sadly, the following seems to need admin:
        $env:ChocolateyInstall = (New-Item Packages -ItemType Directory)
        choco install openssl.light -y
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory, Position = 0)]
        [psobject]$CipherSuite,

        [Parameter(Position = 0)]
        [string]$OpenSslPath = $PSScriptRoot
    )

    #Don't use this, it hangs for ages because, on successful connection, openssl s_client waits for input
    # (& $OpenSslPath s_client connect localhost:5986 2>$null)


    
    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = $OpenSslPath
    $pinfo.RedirectStandardError = $true
    $pinfo.RedirectStandardOutput = $true
    $pinfo.RedirectStandardInput = $true
    $pinfo.UseShellExecute = $false
    $pinfo.Arguments = ("s_client", "-connect", "localhost:5986", "-tls1_2")
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $pinfo
    $p.Start()

    #Openssl s_client does not listen to stdin, it listens directly to the console
    #$p.StandardInput.Write("Q")
    #$p.StandardInput.Write("`n")
    #$Task = $P.StandardOutput.ReadToEndAsync()
    $Chars = New-Object System.Collections.Generic.List[char]
    while ($P.StandardOutput.Peek() -gt 0)
    {
        $Chars += [char]$P.StandardOutput.Read()
    }
    $P.Kill()
    $P.Dispose()

    $Output = $Chars -join ''

    $Output
}


