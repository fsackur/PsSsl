function Join-ModuleFiles
{
    param
    (
        [Parameter(Mandatory, Position = 0)]
        [string]$Path,

        [string]$OutputFile,

        [string[]]$Exclude
    )

    if (-not (Test-Path $Path -PathType Container))
    {
        throw "Where are these silly files supposed to be then?"
    }

    $Path = (Resolve-Path $Path).Path

    $OutputFolder = Split-Path $OutputFile
    $null = New-Item $OutputFolder -ItemType Directory -Force

    if (Test-Path $OutputFile -PathType Leaf)
    {
        Remove-Item $OutputFile -Force
    }

    
    $ExcludePattern = (
        $Exclude | ForEach-Object {[regex]::Escape($_)}
    ) -join '|'

    $Filenames = (Get-ChildItem $Path -Recurse -File |
        Select-Object -ExpandProperty FullName
    ) -notmatch $ExcludePattern

    foreach ($Filename in $Filenames)
    {

        $ScriptblockAst = [System.Management.Automation.Language.Parser]::ParseFile(
            $Filename,
            [ref]$null,
            [ref]$null
        )

        $FunctionAsts = $ScriptblockAst.FindAll(
            {$args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst]},
            $true
        )

        foreach ($FunctionAst in $FunctionAsts)
        {
            (
                #[System.Environment]::NewLine,
                "#region $($FunctionAst.Name) function",
                $FunctionAst.Extent.Text,
                "#endregion $($FunctionAst.Name) function"
                #[System.Environment]::NewLine

            ) | Out-String | Out-File $OutputFile -Append -Encoding unicode
        }
    }
}

Join-ModuleFiles $PSScriptRoot -OutputFile (Join-Path $PSScriptRoot "OutputModule.psm1") -Exclude (
    'build.ps1',
    'SqlChecks.psm1',
    'Get-NetFrameworkVersion.ps1'
)