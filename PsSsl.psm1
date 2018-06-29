
$Script:RegParentPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL'

Get-ChildItem (Join-Path $PSScriptRoot "Modules") | ForEach-Object {Import-Module $_.FullName}
Get-ChildItem (Join-Path $PSScriptRoot "Private") | ForEach-Object {. $_.FullName}
Get-ChildItem (Join-Path $PSScriptRoot "Public")  | ForEach-Object {. $_.FullName}
