function Invoke-OpenSsl
{
    <#
        Sadly, the following seems to need admin:
        $env:ChocolateyInstall = (New-Item Packages -ItemType Directory)
        choco install openssl.light -y

        Register-PackageSource -Name NuGetv2 -ProviderName NuGet -Location https://www.nuget.org/api/v2
        Install-Package openssl-vc141 -Source NuGetv2 -RequiredVersion 1.1.0 -Path Packages -Scope CurrentUser


        openssl is a pig because, on successful connection with the s_client option, it waits for input.
        It listens for input on the console, not on the stdin.

        You can use ProcessInfo.StandardInput.Write("Q") when running in a powershell console, but not an
        integrated editor, because then openssl will be in a separate window and StdIn in your editor
        won't go to the console of openssl's console host.

        You can't use ProcessInfo.StandardOutput.ReadToEnd(), or it hangs the script until openssl times
        out (far too long). If you use .ReadToEndAsync(), kill the process, then invoke the async result,
        you get nothing.
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Position = 0)]
        [string]$OpenSslPath = $PSScriptRoot,

        [Parameter(Mandatory = $true, Position = 1)]
        [string[]]$ArgumentList
    )

    if (-not (Test-Path $OpenSslPath))
    {
        throw New-Object System.ArgumentException (
            "The value '$OpenSslPath' provided to parameter 'OpenSslPath' is invalid."
        )
    }
    if (Test-Path $OpenSslPath -PathType Leaf)
    {
        $OpenSslConfigPath = Join-Path $OpenSslPath 'openssl.cfg'
    }
    else
    {
        $OpenSslConfigPath = Join-Path $OpenSslPath 'openssl.cfg'
        $OpenSslPath = Join-Path $OpenSslPath 'openssl.exe'
    }

    $env:OPENSSL_CONF = $OpenSslConfigPath


    $OutputChars = New-Object System.Collections.Generic.List[char]
    $ErrorChars  = New-Object System.Collections.Generic.List[char]
    $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
    $Process     = New-Object System.Diagnostics.Process

    $ErrorRunspace = [runspacefactory]::CreateRunspace()
    $ErrorRunspace.Open()
    $ErrorRunspace.SessionStateProxy.SetVariable('ErrorChars', $ErrorChars)
    $ErrorRunspace.SessionStateProxy.SetVariable('Process', $Process)
    $ErrorPS = [powershell]::Create()
    $ErrorPS.Runspace = $ErrorRunspace
    $null = $ErrorPS.AddScript(
        'while ($Process.StandardError.Peek() -gt 0)
        {
            $ErrorChars.Add(([char]$Process.StandardError.Read()))
        }'
    )

    $ProcessInfo.FileName               = $OpenSslPath
    $ProcessInfo.RedirectStandardError  = $true
    $ProcessInfo.RedirectStandardOutput = $true
    $ProcessInfo.RedirectStandardInput  = $true
    $ProcessInfo.UseShellExecute        = $false
    $ProcessInfo.Arguments = $ArgumentList

    $Process.StartInfo = $ProcessInfo
    $null = $Process.Start()

    $ErrorAsyncResult = $ErrorPS.BeginInvoke()

    while ($Process.StandardOutput.Peek() -gt 0)
    {
        $OutputChars.Add(([char]$Process.StandardOutput.Read()))
    }


    $Exited = $Process.WaitForExit(1000)
    if (-not $Exited)
    {
        Write-Warning "Timed out waiting for exit"
        & {
            $ErrorActionPreference = 'Ignore'
            $Process.Kill()  #access denied...?
        }
    }


    $ErrorPS.EndInvoke($ErrorAsyncResult)

    if ($ErrorChars)
    {
        Write-Error ($ErrorChars -join '')
    }
    if ($OutputChars)
    {
        Write-Output ($OutputChars -join '')
    }

    $Process.Dispose()
}

Invoke-OpenSsl -ArgumentList "ciphers", 'ALL:eNULL'
#Invoke-OpenSsl -ArgumentList "s_client -connect localhost:5986", '-tls1_2'