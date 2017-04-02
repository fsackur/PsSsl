# SslRegConfig

A PS module to manage server-side SSL (schannel) configuration on Windows
 - disable or enable SSL / TLS protocols
 - disable or enable SSL ciphers (RC4 / Triple-DES / AES, etc)
 - disable or enable key exchange algorithms (Diffie-Hellman, etc)
 - check required hotfix levels and prevent breaking changes

For compliance and security reasons, it's frequently necessary to enable and disable protocols used for secure communications. For example: 
 - BEAST attack:
  - standard mitigation is to disable SSL protocols up to and including TLS 1.0
  - alternately, disable ciphers up to and including RC2
 - POODLE attack standard mitigation:
  - standard mitigation is to disable SSL protocols up to and including TLS 1.0
  - alternately, disable ciphers up to and including RC2

This module aims to be:
 - feature-complete
 - backwards-compatible with Server 2008 RTM / Vista
 - backwards-compatible with PowerShell v2.0
 - easy to use
 - easy to roll back
 - safe
 - amenable to automation
 
# How to use

Download the module to $env:USERPROFILE\Documents\WindowsPowerShell\Modules\

    PS C:\> Import-Module $env:USERPROFILE\Documents\WindowsPowerShell\Modules\SslRegConfig
    
    PS C:\> Set-SslRegValues -Enable 'TLS1.1', 'TLS1.2' -Disable 'SSL3.0', 'TLS1.0'

For full help, see the function help for each function.

Functions exported from this module:
 - Get-SslRegReport
 - Get-SslRegValues
 - New-SslRegValues
 - Set-SslRegValues
