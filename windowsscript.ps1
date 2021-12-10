#firewall stuff

New-NetFirewallRule -DisplayName "Block Incoming FTP" -Direction Inbound -Protocol TCP -Action Block -LocalPort 21
Write-host 'Blocking incoming FTP'

New-NetFirewallRule -DisplayName "Block Incoming SSH" -Direction Inbound -Protocol TCP -Action Block -LocalPort 22
Write-host 'Blocking incoming SSH'

New-NetFirewallRule -DisplayName "Block Incoming Telnet" -Direction Inbound -Protocol TCP -Action Block -LocalPort 23
Write-host 'Blocking incoming Telnet'

New-NetFirewallRule -DisplayName "Block Incoming NFS (TCP)" -Direction Inbound -Protocol TCP -Action Block -LocalPort 2049
Write-host 'Blocking incoming NFS (TCP)'

New-NetFirewallRule -DisplayName "Block Incoming NFS (UDP)" -Direction Inbound -Protocol UDP -Action Block -LocalPort 2049
Write-host 'Blocking incoming NFS (UDP)'

#New-NetFirewallRule -DisplayName "Block Incoming RDP" -Direction Inbound -Protocol TCP -Action Block -LocalPort 2049
#Write-host 'Blocking incoming RDP' (Does not want RDP blocked)


#login stuff (group policy object)
$maxpwage = 30
$minpwage = 7
$minpwlen = 9

$lockoutduration = 30
$lockoutthreshold = 5
$lockoutwindow = 20

net accounts /maxpwage:$maxpwage
Write-host "Set max password age to $maxpwage"

net accounts /minpwage:$minpwage
Write-host "Set minimum password age to $minpwage"

net accounts /minpwlen:$minpwlen
Write-host "Set min password length to $minpwlen"

net accounts /lockoutduration:$lockoutduration
Write-host "Set lockout duration to $lockoutduration"

net accounts /lockoutthreshold:$lockoutthreshold
Write-host "Set lockout threshold to $lockoutthreshold"

net accounts /lockoutwindow:$lockoutwindow
Write-host "Set lockout window to $lockoutwindow"

#enable password complexity
secedit /export /cfg c:\secpol.cfg
(GC C:\secpol.cfg) -Replace "PasswordComplexity = 0","PasswordComplexity = 1" | Out-File C:\secpol.cfg
secedit /configure /db c:\windows\security\local.sdb /cfg c:\secpol.cfg /areas SECURITYPOLICY
Remove-Item C:\secpol.cfg -Force
Write-host "Enabled password complexity rules"


#registry stuff
$cool = 0
echo 'please back up registry and when ready type poopsock and press enter'
while ($cool -ne 'poopsock') {
  $cool = Read-host
}

#Enable User Account Control
reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t Reg_DWORD /d 1 /f
Write-host 'Enabled UAC'

#Enable Windows Defender Antivirus
reg delete "HKLM\Software\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t Reg_DWORD /d 0 /f
Write-host 'Enabled Windows Defender'

#Enable Automatic Updates
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\AU" /v NoAutoUpdate /t Reg_DWORD /d 0 /f
Write-host 'Disabled No Automatic Updates'

#Automatically download and notify of install for updates
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\AU" /v AUOptions /t Reg_DWORD /d 3 /f
Write-host 'Enabled Automatic Download and Updates'

#Restrict anonymous access
reg add HKLM\System\CurrentControlSet\Control\Lsa\  /v restrictanonymous /t Reg_DWORD /d 1 /f
Write-host 'Disabled anonymous access'

#Block anonymous enumeration of SAM accounts and shares
reg add HKLM\System\CurrentControlSet\Control\Lsa\  /v restrictanonymoussam /t Reg_DWORD /d 1 /f
Write-host 'Disabled anonymous account enum (hackers could enumerate usernames and bruteforce passwords)'

#Send NTLMv2 response only; refuse LM & NTLM
reg add HKLM\System\CurrentControlSet\Control\Lsa\ /v lmcompatibilitylevel /t Reg_DWORD /d 5 /f
Write-host 'Disabled insecure NTLM and LM'

#Disable admin autologon
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t Reg_DWORD /d 0 /f
Write-host 'Disabled Administrator Autologin'

#Prevent the inclusion of the Everyone security group SID in the anonymous user's access token
reg add HKLM\System\CurrentControlSet\Control\Lsa\  /v everyoneincludesanonymous /t Reg_DWORD /d 0 /f
Write-host 'Disabled possible information leak from token response'

#Disable EnablePlainTextPassword
reg add HKLM\System\CurrentControlSet\services\LanmanWorkstation\Parameters /v EnablePlainTextPassword /t Reg_DWORD /d 0 /f
Write-host 'Disabled Plain Text Password Storage'

#Disable IPv6
#reg add HKLM\System\CurrentControlSet\services\TCPIP6\Parameters /v DisabledComponents /t Reg_DWORD /d 255 /f
#Write-host 'Disabled IPv6'

#Disable Remote Desktop Protocol (RDP) (Does not want RDP disabled)
#reg add "HKLM\System\CurrentControlSet\Control\Terminal Server" /f /v fDenyTSConnections /t Reg_DWORD /d 1
#Write-host 'Disabled RDP' 


#STIG stuff (https://www.stigviewer.com/stig/windows_10/2019-01-04/finding/V-63797)
Write-host 'Now following STIGs Windows 10 Security Technical Implementation Guide (https://www.stigviewer.com/stig/windows_10/2019-01-04/finding/V-63797)'
Write-host 'Addressing HIGH severity issues...'

#Disable LAN Manager Password storage because LAN Manager has a weak hashing algorithm
reg add HKLM\System\CurrentControlSet\Control\Lsa\ /v NoLMHash /t Reg_DWORD /d 1 /f
Write-host 'Disabled LAN Manager Password Storage'

#Disable Solicited Remote Assistance
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" /v fAllowToGetHelp /t Reg_DWORD /d 0 /f
Write-host 'Disabled Solicited Remote Assistance'

#Disable escalating privileges when Windows Installer is run
reg add HKLM\Software\Policies\Microsoft\Windows\Installer\ /v AlwaysInstallElevated /t Reg_DWORD /d 0 /f
Write-host 'Disabled escalating privileges when Windows Installer is run'

#Disable Autoplay for nonvolumn devices
reg add HKLM\Software\Policies\Microsoft\Windows\Explorer\ /v NoAutoplayfornonVolumn /t Reg_DWORD /d 1 /f
Write-host 'Disabled Autoplay for nonvolumn devices'

#Disable Anonymous access to Named Pipes
reg add HKLM\System\CurrentControlSet\Services\LanManServer\Parameters\ /v RestictNullSessAccess /t Reg_DWORD /d 1 /f
Write-host 'Disabled Anonymous access to Named Pipes'

#Disable Autoplay for all drives
reg add HKLM\Software\Microsoft\Windows\CurrentVersion\policies\Explorer\ /v NoDriveTypeAutoRun /t Reg_DWORD /d 255 /f 
Write-host 'Disabled Autoplay for all drives'

#Disable Autorun commands 
reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\ /v NoAutorun /t Reg_DWORD /d 1 /f
Write-host 'Disabled Autorun Commands'

#Enable SEHOP, which can prevent certain types of buffer overflows
reg add "HKLM\Software\CurrentControlSet\Control\Session Manager\kernel" /v DisableExceptionChainValidation /t Reg_dword /d 0 /f
Write-host 'Enable SEHOP, which stops a very common buffer overflow attack'

#Configures Data Execution Prevention to be OptOut
BCDEdit /set "{current}" nx OptOut
Write-host 'Configured DEP to run in OptOut mode'

#Disables Basic auth (plain text password storage) on Windows Remote Management Service
reg add HKLM\software\policies\Microsoft\windows\Winrm\Service\ /v AllowBasic /t Reg_DWORD /d 0 /f
Write-host 'Disabled Basic Auth for the Windows Remove Management Service'

#Disables Basic auth (plain text password storage) on Windows Remote Management Client
reg add HKLM\software\policies\Microsoft\windows\Winrm\Client\ /v AllowBasic /t Reg_DWORD /d 0 /f
Write-host 'Disabled Basic Auth for the Windows Remove Management Client'


#Prevents Data Execution Prevention from being turned off by Fil Explorer
reg add HKLM\software\policies\windows\explorer\ /v NoDataExecutionPrevention /t Reg_DWORD /d 0 /f
Write-host 'Enabled Data Execution Prevention, prevents DEP from being turned off by File Explorer'

#Enhanced anti-spoofing for facial recognition
reg add HKLM\software\policies\microsoft\biometrics\facialfeatures\ /v EnhancedAntiSpoofing /t Reg_DWORD /d 1 /f
Write-host 'Enhanced Anti Spoofing for facialrecognition'

#Enables Defender SmartScreen for explorer
reg add HKLM\software\policies\microsoft\windows\system\ /v EnableSmartScreen / t Reg_DWORD /d 1 /f
Write-host 'Enabled Windows Defender SmartScreen for Explorer, prevents users from running malicious programs'

#Windows Telemetery must not be configured to full
reg add HKLM\software\policies\microsoft\windows\datacollection\ /v AllowTelemetry /t Reg_DWORD /d 0 /f 
Write-host 'Windows Telemetry

#Limits Enhanced Diagnostic data to the minimum to support Windows Analytics
reg add HKLM\software\policies\microsoft\windows\datacollection\ /v LimitEnhancedDiagnosticDataWindowsAnalytics /t Reg_DWORD /d 1 /f
Write-host 'Limited Enhanced Diagnostic Data

#Configures Kerberos encryption types
reg add HKLM\software\microsoft\windows\currentversion\policies\system\kerberos\parameters\ /v SupportedEncryptionTypes /t Reg_DWORD /d 2147483640 /f
Write-host 'Allowed kerberos encryption types'


#Turns on Credential Guard 
reg add HKLM\software\policies\microsoft\windows\deviceguard\ /v LsaCfgFlags /t Reg_DWORD /d 1 /f
Write-host 'Turned on credential guard'
