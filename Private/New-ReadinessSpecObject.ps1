function New-ReadinessSpecObject
{
    <#
        .SYNOPSIS
        Creates an object for components to report their TLS 1.2 readiness.

        .DESCRIPTION
        Creates an object for components to report their TLS 1.2 readiness.

        Created objects always have a 'SupportsTls12' property and a 'RequiredUpdates' property. 'SupportsTls12'
        will be initialised as false. 'RequiredUpdates' will be initialised as an empty array.

        .PARAMETER NoteProperty
        Specifies to add extra properties to the created object.

        .OUTPUTS
        [psobject]

        .EXAMPLE
        New-ReadinessSpecObject

        SupportsTls12 RequiredUpdates
        ------------- ---------------
                False {}

        Creates an object with 'SupportsTls12' and 'RequiredUpdates' properties. 'SupportsTls12' is initialised
        as false; 'RequiredUpdates' is initialised as an empty array.

        .EXAMPLE
        New-ReadinessSpecObject -NoteProperty 'SqlFeatures'

        SupportsTls12 RequiredUpdates SqlFeatures
        ------------- --------------- -----------
                False {}

        Creates an object with 'SupportsTls12', 'RequiredUpdates' and 'SqlFeatures' properties. 'SupportsTls12'
        is initialised as false; 'RequiredUpdates' is initialised as an empty array; 'SqlFeatures' is initialised
        as null.
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param
    (
        [Parameter()]
        [string[]]$NoteProperty
    )

    $Properties = 'SupportsTls12', 'RequiredUpdates'
    if ($NoteProperty)
    {
        $Properties = $Properties + $NoteProperty | Select-Object -Unique
    }

    $Output = New-Object PSObject
    foreach ($Property in $Properties)
    {
        Add-Member -InputObject $Output -MemberType 'NoteProperty' -Name $Property -Value $null
    }
    $Output.SupportsTls12   = $false
    $Output.RequiredUpdates = @()

    Add-Member -InputObject $Output -MemberType 'ScriptMethod' -Name 'ToString' -Force -Value {
        if ($this.SupportsTls12)
        {
            "Ready"
        }
        elseif ($this.RequiredUpdates)
        {
            "Required updates: $($this.RequiredUpdates.Count)"
        }
        else
        {
            "Not ready"
        }
    }

    return $Output
}
