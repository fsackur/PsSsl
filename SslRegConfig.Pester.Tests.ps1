Import-Module $PSScriptRoot\SSlRegConfig.psm1

$Global:RegParentPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL'

Describe 'Reg functions' {
    Mock 'Get-ItemProperty' -ModuleName SslRegConfig -MockWith {
        switch ($LiteralPath) {
            "$RegParentPath\Protocols\SSL 3.0\Server"
                {return New-Object psobject -Property @{Enabled=0}}
            "$RegParentPath\Protocols\TLS 1.0\Server"
                {return New-Object psobject -Property @{Enabled=1}}
            "$RegParentPath\Protocols\TLS 1.1\Server"
                {throw New-Object System.Management.Automation.ItemNotFoundException (
                    "Cannot find path '$RegParentPath\Protocols\TLS 1.1\Server' because it does not exist."
                )}
        }
    }
    
    
    $Ssl30Enable  = {$LiteralPath -eq "$RegParentPath\Protocols\SSL 3.0\Server" -and $Value -eq 1}
    $Tls10Enable  = {$LiteralPath -eq "$RegParentPath\Protocols\TLS 1.0\Server" -and $Value -eq 1}
    $Tls10Disable = {$LiteralPath -eq "$RegParentPath\Protocols\TLS 1.0\Server" -and $Value -eq 0}
    $Tls11Disable = {$LiteralPath -eq "$RegParentPath\Protocols\TLS 1.1\Server" -and $Value -eq 0}

    Mock 'Set-ItemProperty' -ModuleName SslRegConfig -MockWith {}
    Mock 'Set-ItemProperty' -ModuleName SslRegConfig -MockWith {} -ParameterFilter $Ssl30Enable
    Mock 'Set-ItemProperty' -ModuleName SslRegConfig -MockWith {} -ParameterFilter $Tls10Enable
    Mock 'Set-ItemProperty' -ModuleName SslRegConfig -MockWith {} -ParameterFilter $Tls10Disable
    Mock 'Set-ItemProperty' -ModuleName SslRegConfig -MockWith {} -ParameterFilter $Tls11Disable

    Context 'Getting reg values' {
        It 'Returns reg value if present, or null if not present' {
            $RegValues = Get-SslRegValues
            Assert-MockCalled 'Get-ItemProperty' -ModuleName SslRegConfig
            $RegValues['TLS1.0'] | Should BeExactly 1
            $RegValues['SSL3.0'] | Should BeExactly 0
            $RegValues['TLS1.1'] | Should Be $null

        }
    }

    Context 'Getting reg report' {
        It 'Returns reg value if present, or null if not present' {
            $RegValues = Get-SslRegValues
            Assert-MockCalled 'Get-ItemProperty' -ModuleName SslRegConfig
            $RegValues['TLS1.0'] | Should BeExactly 1
            $RegValues['SSL3.0'] | Should BeExactly 0
            $RegValues['TLS1.1'] | Should Be $null

        }
    }

    Context 'Setting reg values' {

        It 'Sets reg values if provided' {
            Set-SslRegValues -Enable 'SSL3.0' -Disable 'TLS1.1'
            Assert-MockCalled 'Set-ItemProperty' -ModuleName SslRegConfig -Times 1 -ParameterFilter $Ssl30Enable
            Assert-MockCalled 'Set-ItemProperty' -ModuleName SslRegConfig -Times 1 -ParameterFilter $Tls11Disable
        }
        
        It 'Gives precedence to Enable values over Disable' {
            Set-SslRegValues -Enable 'TLS1.0' -Disable 'TLS1.0'
            Assert-MockCalled 'Set-ItemProperty' -ModuleName SslRegConfig -Times 0 -ParameterFilter $Tls10Disable
            Assert-MockCalled 'Set-ItemProperty' -ModuleName SslRegConfig -Times 1 -ParameterFilter $Tls10Enable
        }
        
        It 'Creates new reg key if needed' {
            Mock 'reg.exe' -ModuleName SslRegConfig -MockWith {
                throw "hi"
            }
            #Set-SslRegValues -Enable 'TLS1.1'
            #Assert-MockCalled 'reg.exe' -ModuleName SslRegConfig -Times 1
        }
    }
    



}