
$ModuleName = 'Ps-Ssl'
Import-Module $PSScriptRoot\..\$ModuleName -Force -ErrorAction Stop

$Global:RegParentPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL'
$Global:Tls11NotFoundException = New-Object System.Management.Automation.ItemNotFoundException ("Cannot find path '$RegParentPath\Protocols\TLS 1.1\Server' because it does not exist.")
$Global:MOCK_TLS_11_REGKEY_EXISTS = $false




Describe 'Function help' {
    Context 'Correctly-formatted help' {
    
        foreach (
            $Command in (
                Get-Module $ModuleName | 
                select -ExpandProperty ExportedCommands
                ).Keys
            ) 
            {
                $Help = Get-Help $Command

                It "$Command has one or more help examples" {
                    $Help.examples.example | Should Not Be $null
                }

                #Test only the parameters? Mock it and see if it throws
                Mock $Command -MockWith {}

                It "$Command examples are syntactically correct" {
                    foreach ($Example in $Help.examples.example) {
                        [Scriptblock]::Create($Example.code) | Should Not Throw
                    }
                }

            } #end foreach

    }
}

Describe 'Parameter validation' {
    Context 'Enable and Disable parameters' {

        Mock 'Set-ItemProperty' -ModuleName $ModuleName {}

        It 'Rejects garbage' {
            {Set-SslRegValues -Disable 'asdgasgasgasfasf'} | Should Throw "Cannot validate argument on parameter"
        }

        InModuleScope $ModuleName {
            It 'Accepts any key from lookup table of supported elements' {
                $RegLookup = Get-SslRegLookupTable
                foreach ($Key in $RegLookup.Keys) {
                    {Enable-Ssl -Protocol $Key} | Should Not Throw
                }
            }
        }

        It 'Explicitly lists allowed values' {
            $Command = (Get-Command Set-SslRegValues)
            $EnableAttributes = $Command.Parameters['Enable'].Attributes
            $ValidateSet = $EnableAttributes | where {$_.GetType() -eq [System.Management.Automation.ValidateSetAttribute]}
            $ValidateSet | Should Not Be $null
        }
    }
}