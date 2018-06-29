@{

    ModuleToProcess   = 'PsSsl.psm1'
    ModuleVersion     = '1.0.0.0'
    GUID              = '070633f1-45bd-48eb-9756-4f1194f83735'

    Description       = 'Configuration of SSL protocols and ciphers'

    Author            = 'Freddie Sackur'
    CompanyName       = 'dustyfox.uk'
    Copyright         = 'Copyright (c) 2017 Freddie Sackur'

    PowerShellVersion = '2.0'
    RequiredModules   = @()

    FunctionsToExport = @(
        'Enable-Ssl',
        'Get-SqlTls12Report',
        'Get-SslRegReport',
        'Get-SslRegValues',
        'New-SslRegValues',
        'Set-SslRegValues',
        'Export-SslRegBackup'
    )

    CmdletsToExport   = @()
    VariablesToExport = ''
    AliasesToExport   = @()
    FileList          = @()

    PrivateData       = @{
        PSData = @{
            Tags = @(
                'SSL',
                'TLS',
                'Schannel',
                'Cipher',
                'CipherSuite',
                'Protocol'
            )
            LicenseUri = 'https://raw.githubusercontent.com/fsackur/PsSsl/master/LICENSE'

            OSVersion = '6.0'
        }
    }
}
