function Get-TlsProtocol
{
    <#
        .SYNOPSIS
        Gets a version of a TLS protocol.

        .DESCRIPTION
        Gets a version of a TLS protocol.

        .PARAMETER Protocol
        Specify the SSL / TLS / DTLS protocol.

        .PARAMETER OSVersion
        To avoid a duplicate WMI call, provide the semantic version of the operating system.

        .OUTPUTS
        [psobject]

        .EXAMPLE
        Get-TlsProtocol 'TLS 1.2 Client'

        Protocol       Enabled OsDefaultIsEnabled
        --------       ------- ------------------
        TLS 1.2 Client    True               True

        Gets the TLS 1.2 Client protocol.

        .LINK
        https://docs.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateSet(
            'SSL 2.0 Client',
            'SSL 2.0 Server',
            'SSL 3.0 Client',
            'SSL 3.0 Server',
            'TLS 1.0 Client',
            'TLS 1.0 Server',
            'TLS 1.1 Client',
            'TLS 1.1 Server',
            'TLS 1.2 Client',
            'TLS 1.2 Server',
            'DTLS 1.0 Client',
            'DTLS 1.0 Server',
            'DTLS 1.2 Client',
            'DTLS 1.2 Server'
        )]
        [string]$Protocol,

        [Parameter()]
        [version]$OSVersion = ([version](Get-WmiObject -Query "SELECT Version FROM Win32_OperatingSystem").Version)
    )

    begin
    {
        $OutputProperties = 'Protocol', 'Enabled', 'OsDefaultIsEnabled'

        $DefaultsForOS    = Get-TlsProtocolDefaults -OSVersion $OSVersion
        $SchannelKey      = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL"
        $ProtocolsKey     = "$SchannelKey\Protocols"
    }

    process
    {
        $Output = New-Object psobject
        foreach ($Property in $OutputProperties)
        {
            Add-Member -InputObject $Output -MemberType 'NoteProperty' -Name $Property -Value $null
        }

        $Output.Protocol           = $Protocol

        $DefaultForOs              = $DefaultsForOS.$Protocol
        $OsDefaultIsEnabled        = $DefaultForOS -eq 'Enabled'
        $Output.OsDefaultIsEnabled = $OsDefaultIsEnabled


        $SubKey    = $Protocol -replace ' (?=(Client|Server)$)', '\'
        $RegKeyObj = Registry\Get-RegKey "$ProtocolsKey\$SubKey"

        if ($null -eq $RegKeyObj)
        {
            $Output.Enabled = $OsDefaultIsEnabled
        }
        else
        {
            $Output.Enabled = (
                $RegKeyObj.DisabledByDefault -eq 0 -and
                ($RegKeyObj.Enabled -band 1) -eq 1      # Check the right-most bit, instead of simple numeric equality, due to community confusion around 0xffffffff versus 1
            )
        }


        return $Output
    }
}
