Function New-FunctionTemplate
{
    <#
        .SYNOPSIS
        Brief description

        .DESCRIPTION
        Detailed descriptions

        .PARAMETER Example
        Description of parameter

        .OUTPUTS
        Output type / description
        [string]

        .EXAMPLE
        Example usage of function
        Get-Template -Example 'My example'
        Returns an example template
    #>

    [CmdletBinding()]
    [OutputType(PsObject)]

    #Description why we should be suppressing a rule from PSSA
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingPlainTextForPassword", "")]

    Param
    (
        [Parameter(Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter(Position = 1,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false)]
        [ValidateNotNullOrEmpty()]
        [int]$Example

    )

    Begin
    {
        Write-Verbose "[$(Get-Date)] Begin :: $($MyInvocation.MyCommand)"
        Write-Verbose "[$(Get-Date)] List of Parameters :: $($PSBoundParameters.GetEnumerator() | Out-String)"
    }

    Process
    {
        #Main code goes here
    }

    End
    {
        Write-Verbose "[$(Get-Date)] End   :: $($MyInvocation.MyCommand)"
    }
}
