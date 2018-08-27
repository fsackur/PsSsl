function New-ReadinessSpecObject
{
    <#
        .SYNOPSIS
        Creates an object for components to report their TLS 1.2 readiness.

        .DESCRIPTION
        Creates an object for components to report their TLS 1.2 readiness.

        Created objects always have a 'SupportsTls12' property and a 'RequiredActions' property. 'SupportsTls12'
        will be initialised as false. 'RequiredActions' will be initialised as an empty array.

        .PARAMETER AddMember
        Specifies to add extra properties to the created object.

        .OUTPUTS
        [psobject]

        .EXAMPLE
        New-ReadinessSpecObject

        SupportsTls12 RequiredActions
        ------------- ---------------
                False {}

        Creates an object with 'SupportsTls12' and 'RequiredActions' properties. 'SupportsTls12' is initialised
        as false; 'RequiredActions' is initialised as an empty array.

        .EXAMPLE
        New-ReadinessSpecObject -AddMember 'SqlFeatures'

        SupportsTls12 RequiredActions SqlFeatures
        ------------- --------------- -----------
                False {}

        Creates an object with 'SupportsTls12', 'RequiredActions' and 'SqlFeatures' properties. 'SupportsTls12'
        is initialised as false; 'RequiredActions' is initialised as an empty array; 'SqlFeatures' is initialised
        as null.
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param
    (
        [Parameter()]
        [string[]]$AddMember
    )

    $Properties = 'SupportsTls12', 'RequiredActions'
    if ($AddMember)
    {
        $Properties = $Properties + $AddMember | Select-Object -Unique
    }

    $Output = New-Object PSObject
    foreach ($P in $Properties)
    {
        Add-Member -InputObject $Output -MemberType 'NoteProperty' -Name $P -Value $null
    }
    $Output.SupportsTls12   = $false
    $Output.RequiredActions = @()

    Add-Member -InputObject $Output -MemberType 'ScriptMethod' -Name 'ToString' -Force -Value {
        if ($this.SupportsTls12)
        {
            "Ready"
        }
        elseif ($this.RequiredActions)
        {
            "Required actions: $($this.RequiredActions.Count)"
        }
        else
        {
            "Not ready"
        }
    }

    return $Output
}
