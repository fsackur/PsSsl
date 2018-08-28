function Invoke-OpenSsl
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
    $OpenSslPath = Join-Path $PSScriptRoot 'openssl.exe'
    $OpenSslConfigPath = Join-Path $PSScriptRoot 'openssl.cfg'

    
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
    $ErrorChars  = New-Object System.Collections.Generic.List[char]
    $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
    $Process     = New-Object System.Diagnostics.Process

    $ErrorRunspace = [runspacefactory]::CreateRunspace()
    $ErrorRunspace.Open()
    $ErrorRunspace.SessionStateProxy.SetVariable('ErrorChars', $ErrorChars)
    $ErrorRunspace.SessionStateProxy.SetVariable('Process', $Process)
    $ErrorPS = [powershell]::Create()
    $ErrorPS.Runspace = $ErrorRunspace
    #$null = $ErrorPS.AddScript('$Process.StandardError.ReadToEnd()')
    $null = $ErrorPS.AddScript(
        'while ($Process.StandardError.Peek() -gt 0)
        {
            $ErrorChars.Add(([char]$Process.StandardError.Read()))
        }'
    )

    $OutputRunspace = [runspacefactory]::CreateRunspace()
    $OutputRunspace.Open()
    $OutputRunspace.SessionStateProxy.SetVariable('OutputChars', $OutputChars)
    $OutputRunspace.SessionStateProxy.SetVariable('Process', $Process)
    $OutputPS = [powershell]::Create()
    $OutputPS.Runspace = $OutputRunspace
    #$null = $OutputPS.AddScript('$Process.StandardOutput.ReadToEnd()')
    $null = $OutputPS.AddScript(
        'while ($Process.StandardOutput.Peek() -gt 0)
        {
            $OutputChars.Add(([char]$Process.StandardOutput.Read()))
        }'
    )

    $ProcessInfo.FileName               = $OpenSslPath
    $ProcessInfo.RedirectStandardError  = $true
    $ProcessInfo.RedirectStandardOutput = $true
    $ProcessInfo.RedirectStandardInput  = $true
    $ProcessInfo.UseShellExecute        = $false
    $ProcessInfo.Arguments = (
        #"-config",
        #$OpenSslConfigPath,
        "s_clientaasf -connect localhost:5986",
        #"s_client",
        #"-connect",
        #"localhost:5986",
        '-tls1_2' #'-' + ($Protocol -replace ' ' -replace '\.', '_').ToLower()    #-tls1_2
    )

    $Process.StartInfo = $ProcessInfo
    $null = $Process.Start()
    #Start-Sleep -Milliseconds 100

        
    <#
    if (-not $Process.StandardError.EndOfStream)
    {
        $ErrorChars.Add(([char]$Process.StandardError.Read()))
    }
    #>
    $ErrorAsyncResult = $ErrorPS.BeginInvoke()
    #$OutputAsyncResult = $OutputPS.BeginInvoke()

    
    while ($Process.StandardOutput.Peek() -gt 0)
    {
        $OutputChars.Add(([char]$Process.StandardOutput.Read()))
    }
    

    <#
    while ($Process.StandardError.Peek() -gt 0)
    {
        $ErrorChars.Add(([char]$Process.StandardError.Read()))
    }
    #>

    $Exited = $Process.WaitForExit(1000)
    #$OpenSslOutput = $OutputChars -join ''
    if (-not $Process.HasExited)
    {
        try
        {
            $Process.Kill()  #access denied...?
        }
        catch {}
    }
    #

    #$OutputPS.EndInvoke($OutputAsyncResult)
    $ErrorPS.EndInvoke($ErrorAsyncResult)
    #return $OpenSslOutput
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

Invoke-OpenSsl