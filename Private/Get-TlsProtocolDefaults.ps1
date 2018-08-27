function Get-TlsProtocolDefaults
{
    <#
        .SYNOPSIS
        Gets the defaults for TLS protocol versions.

        .DESCRIPTION
        Gets the defaults for TLS protocol versions.

        .PARAMETER OSVersion
        To avoid a duplicate WMI call, provide the semantic version of the operating system.

        .OUTPUTS
        [psobject]

        .EXAMPLE
        Get-TlsProtocolDefaults

        SSL 2.0 Client  : Not supported
        SSL 2.0 Server  : Not supported
        SSL 3.0 Client  : Disabled
        SSL 3.0 Server  : Disabled
        TLS 1.0 Client  : Enabled
        TLS 1.0 Server  : Enabled
        TLS 1.1 Client  : Enabled
        TLS 1.1 Server  : Enabled
        TLS 1.2 Client  : Enabled
        TLS 1.2 Server  : Enabled
        DTLS 1.0 Client : Enabled
        DTLS 1.0 Server : Enabled
        DTLS 1.2 Client : Enabled
        DTLS 1.2 Server : Enabled

        Gets the defaults for TLS protocol versions for the current machine's OS version.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]   # We are returning the defaults for every protocol type, not a single protocol.
    [CmdletBinding()]
    [OutputType([psobject])]
    param
    (
        [Parameter(Position = 0)]
        [version]$OSVersion = ([version](Get-WmiObject -Query "SELECT Version FROM Win32_OperatingSystem").Version)
    )

    begin
    {
        # Scraped from https://docs.microsoft.com/en-us/windows/desktop/secauthn/protocols-in-tls-ssl--schannel-ssp-
        $DefaultsByOS = '
            "OSVersion"  ,"SSL 2.0 Client" ,"SSL 2.0 Server" ,"SSL 3.0 Client" ,"SSL 3.0 Server" ,"TLS 1.0 Client" ,"TLS 1.0 Server" ,"TLS 1.1 Client" ,"TLS 1.1 Server" ,"TLS 1.2 Client" ,"TLS 1.2 Server" ,"DTLS 1.0 Client" ,"DTLS 1.0 Server" ,"DTLS 1.2 Client" ,"DTLS 1.2 Server"
            "6.0"        ,"Disabled"       ,"Enabled"        ,"Enabled"        ,"Enabled"        ,"Enabled"        ,"Enabled"        ,"Not supported"  ,"Not supported"  ,"Not supported"  ,"Not supported"  ,"Not supported"   ,"Not supported"   ,"Not supported"   ,"Not supported"
            "6.0.6002"   ,"Disabled"       ,"Enabled"        ,"Enabled"        ,"Enabled"        ,"Enabled"        ,"Enabled"        ,"Disabled"       ,"Disabled"       ,"Disabled"       ,"Disabled"       ,"Not supported"   ,"Not supported"   ,"Not supported"   ,"Not supported"
            "6.1"        ,"Disabled"       ,"Enabled"        ,"Enabled"        ,"Enabled"        ,"Enabled"        ,"Enabled"        ,"Disabled"       ,"Disabled"       ,"Disabled"       ,"Disabled"       ,"Enabled"         ,"Enabled"         ,"Not supported"   ,"Not supported"
            "6.2"        ,"Disabled"       ,"Disabled"       ,"Enabled"        ,"Enabled"        ,"Enabled"        ,"Enabled"        ,"Enabled"        ,"Enabled"        ,"Enabled"        ,"Enabled"        ,"Enabled"         ,"Enabled"         ,"Not supported"   ,"Not supported"
            "6.3"        ,"Disabled"       ,"Disabled"       ,"Enabled"        ,"Enabled"        ,"Enabled"        ,"Enabled"        ,"Enabled"        ,"Enabled"        ,"Enabled"        ,"Enabled"        ,"Enabled"         ,"Enabled"         ,"Not supported"   ,"Not supported"
            "10.0"       ,"Disabled"       ,"Disabled"       ,"Enabled"        ,"Enabled"        ,"Enabled"        ,"Enabled"        ,"Enabled"        ,"Enabled"        ,"Enabled"        ,"Enabled"        ,"Enabled"         ,"Enabled"         ,"Not supported"   ,"Not supported"
            "10.0.14393" ,"Not supported"  ,"Not supported"  ,"Disabled"       ,"Disabled"       ,"Enabled"        ,"Enabled"        ,"Enabled"        ,"Enabled"        ,"Enabled"        ,"Enabled"        ,"Enabled"         ,"Enabled"         ,"Enabled"         ,"Enabled"
        '.Trim() | ConvertFrom-Csv
    }

    process
    {
        $DefaultsByOS | Where-Object {[version]$_.OSVersion -le $OSVersion} | Select-Object -First 1 -ExcludeProperty 'OSVersion'   # Leave out OSVersion; it's potentially misleading.
    }
}
