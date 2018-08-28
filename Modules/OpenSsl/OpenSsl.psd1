@{

    ModuleToProcess   = 'OpenSsl.psm1'
    ModuleVersion     = '1.0.0.0'
    GUID              = '070633f1-45bd-48eb-9756-4f1194f83735'

    Description       = 'Wrapper for OpenSsl'

    Author            = 'Freddie Sackur'
    CompanyName       = 'dustyfox.uk'
    Copyright         = 'Copyright (c) 2017 Freddie Sackur'

    PowerShellVersion = '2.0'
    RequiredModules   = @()

    FunctionsToExport = @(
        '*'
    )

    CmdletsToExport   = @()
    VariablesToExport = ''
    AliasesToExport   = @()
    FileList          = @()

    PrivateData       = @{
        PSData = @{
            Tags = @(
                'OpenSsl'
            )
            LicenseUri = 'https://raw.githubusercontent.com/fsackur/PsSsl/master/LICENSE'

            OSVersion = '6.0'
        }
    }
}
