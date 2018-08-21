function Get-InstalledSoftware
{
    #Requires -version 2.0

    try
    {
        #collect 32 bit software
        $32KeyPath = "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        if(Test-Path $32KeyPath)
        {
            Try
            {
                $key32 = $null
                $key32 = Get-ChildItem $32KeyPath -Recurse -ErrorAction Stop
            }
            catch
            {
                if ($_ -notlike "*Cannot find path*")
                {
                    $software32 = New-Object PSObject -Property @{
                        Server = $env:COMPUTERNAME
                        Name = "Error: $_"
                        Version = "Error"
                        InstallDate = "Error"
                    }
                }
            }
        }
        $software32 = $key32 | ForEach-Object {Get-ItemProperty $_.pspath -ErrorAction SilentlyContinue}

        #collect 64 bit software
        $64KeyPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
        if(Test-Path $64KeyPath)
        {
            Try
            {
                $key64 = $null
                $key64 = Get-ChildItem $64KeyPath -Recurse -ErrorAction Stop
            }
            catch
            {
                if ($_ -notlike "*Cannot find path*")
                {
                    $software64 = New-Object PSObject -Property @{
                        Server = $env:COMPUTERNAME
                        Name = "Error: $_"
                        Version = "Error"
                        InstallDate = "Error"
                    }
                }
            }
        }
        $software64 = $key64 | ForEach-Object {Get-ItemProperty $_.pspath -ErrorAction SilentlyContinue}
        $installedSoftware = $null
        $installedSoftware = $software32 + $software64 | Where-Object {$_.DisplayName}

        #create output object
        $output = @()
        foreach ($item in $installedSoftware)
        {
            $Version = $InstallDate = $null

            #use the display version as it looks the nicest, if not that, use the version
            if($item.DisplayVersion)
            {
                $Version = $item.DisplayVersion
            }
            else
            {
                if($item.Version)
                {
                    $Version = $item.Version
                }
                else
                {
                    $Version =  "-"
                }
            }

            #check for blank installdate fields
            if($item.InstallDate)
            {
                $InstallDate = $item.InstallDate
            }
            else
            {
                $InstallDate = "-"
            }

            $softwareObject = New-Object PSObject -Property @{
                Server = $env:COMPUTERNAME
                Name = "$($item.DisplayName)"
                Version = "$Version"
                InstallDate = "$InstallDate"
            }
            [array]$output += $softwareObject
        }

        return $output
    }
    catch
    {
        Return New-Object PSObject -Property @{
            Server = $env:COMPUTERNAME
            Name = "Error: $_"
            Version = "Error"
            InstallDate = "Error"
        }
    }
}
