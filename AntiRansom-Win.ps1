# Enable Firewall Profiles & Disable Local Firewall Rules
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -AllowLocalFirewallRules False

# Block SMB
netsh advfirewall firewall set rule group=”File and Printer Sharing” new enable=no

# Block RDP
netsh advfirewall firewall set rule group=”Remote Desktop” new enable=no

# Block WMI
netsh advfirewall firewall set rule group=”Windows Management Instrumentation” new enable=no

# Block WinRM / PS Remoting
Disable-PSRemoting -Force
Stop-Service WinRM
Set-Service WinRM -StartupType Disabled
Set-NetFirewallRule -DisplayGroup ‘Windows Remote Management’ -Enabled False
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\system -Name LocalAccountTokenFilterPolicy -Value 0

# Disable Admin & Hidden Shares WKS/Server
Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters -Name AutoShareWks -value 0
Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters -Name AutoShareServer -value 0

# Disable LanmanServer
Stop-Service LanmanServer
Set-Service LanmanServer -StartupType Disabled

# Set RDP NLA to Enabled
(Get-WmiObject -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-tcp'").SetUserAuthenticationRequired(1)

# Disable SMBv1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB1 -Value 0

# Cred Exposure and Credential Hardening
Set-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name LocalAccountTokenFilterPolicy -Value 0
Set-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name FilterAdministratorToken -Value 1
Set-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableLUA -Value 1

# Cleartext Password Protection
Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest -Name UseLogonCredential -Value 0
Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name TokenLeakDetectDelaySecs -Value 30