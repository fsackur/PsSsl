Import-Module $PSScriptRoot\SSlRegConfig.psm1 -Force

$Global:RegParentPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL'
$Global:NotFoundException = New-Object System.Management.Automation.ItemNotFoundException ("Cannot find path '$RegParentPath\Protocols\TLS 1.1\Server' because it does not exist.")
$Global:MOCK_TLS_11_REGKEY_EXISTS = $false

Describe 'Reg functions' {
    Mock 'Get-ItemProperty' -ModuleName SslRegConfig -MockWith {
        switch ($LiteralPath) {
            "$RegParentPath\Protocols\SSL 3.0\Server"
                {return New-Object psobject -Property @{Enabled=0}}
            "$RegParentPath\Protocols\TLS 1.0\Server"
                {return New-Object psobject -Property @{Enabled=1}}
            "$RegParentPath\Protocols\TLS 1.1\Server"
                {throw $NotFoundException}
        }
    }
    
    
    $Ssl30Enable  = {$LiteralPath -eq "$RegParentPath\Protocols\SSL 3.0\Server" -and $Value -eq 1}
    $Tls10Enable  = {$LiteralPath -eq "$RegParentPath\Protocols\TLS 1.0\Server" -and $Value -eq 1}
    $Tls10Disable = {$LiteralPath -eq "$RegParentPath\Protocols\TLS 1.0\Server" -and $Value -eq 0}
    $Tls11Enable  = {$LiteralPath -eq "$RegParentPath\Protocols\TLS 1.1\Server" -and $Value -eq 1}
    $Tls11Disable = {$LiteralPath -eq "$RegParentPath\Protocols\TLS 1.1\Server" -and $Value -eq 0}

    Mock 'Set-ItemProperty' -ModuleName SslRegConfig -MockWith {}
    Mock 'Set-ItemProperty' -ModuleName SslRegConfig -ParameterFilter $Ssl30Enable -MockWith {}
    Mock 'Set-ItemProperty' -ModuleName SslRegConfig -ParameterFilter $Tls10Enable -MockWith {}
    Mock 'Set-ItemProperty' -ModuleName SslRegConfig -ParameterFilter $Tls10Disable -MockWith {}
    Mock 'Set-ItemProperty' -ModuleName SslRegConfig -ParameterFilter $Tls11Disable -MockWith {if (-not $MOCK_TLS_11_REGKEY_EXISTS) {throw $NotFoundException}}
    Mock 'Set-ItemProperty' -ModuleName SslRegConfig -ParameterFilter $Tls11Enable -MockWith {if (-not $MOCK_TLS_11_REGKEY_EXISTS) {throw $NotFoundException}}

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

        $MockWmiCreateRegKey = {
            #https://msdn.microsoft.com/en-us/library/aa389385(v=vs.85).aspx
            $HKEY_LOCAL_MACHINE = 2147483650
            $Path = "$Global:RegParentPath\Protocols\TLS 1.1\Server".Replace('HKLM:\', '')
            if ($args[0] -eq 2147483650 -and  $args[1] -like $Path) {
                $GLobal:MOCK_TLS_11_REGKEY_EXISTS = $true
                return New-Object psobject -Property @{ReturnValue=0}
            } else {
                throw "Pester mock failed creating TLS 1.1 reg key: invalid args supplied to CreateKey method"
            }
        }
        
        $Global:MockWmiProvider = New-Object psobject -Property @{Name = 'StdRegProv'}
        $MockWmiProvider | Add-Member ScriptMethod -Name 'CreateKey' -Value $MockWmiCreateRegKey
        Mock 'Get-WmiObject' -ModuleName SslRegConfig -ParameterFilter {$List -and $Namespace -eq "ROOT\DEFAULT"} -MockWith {return $MockWmiProvider}

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

            Set-SslRegValues -Enable 'TLS1.1'
            Assert-MockCalled 'Get-WmiObject' -ModuleName SslRegConfig -Times 1
        }
    }
    



}