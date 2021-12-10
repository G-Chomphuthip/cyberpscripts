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

New-NetFirewallRule -DisplayName "Block Incoming RDP" -Direction Inbound -Protocol TCP -Action Block -LocalPort 2049
Write-host 'Blocking incoming RDP'


#login stuff (group policy object)
$maxpwage = 30
$minpwage = 7
$minpwlen = 9

$lockoutduration = 30
$lockoutthreshold = 5
$lockoutwindow = 10

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

#disable reversible encryption of passwords
Get-ADUser -Filter * | Set-ADUser -AllowReversiblePasswordEncryption $false

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

#Disable Remote Desktop Protocol (RDP)
reg add "HKLM\System\CurrentControlSet\Control\Terminal Server" /f /v fDenyTSConnections /t Reg_DWORD /d 1
Write-host 'Disabled RDP'
