::(reg query “<regpath>” /v <reg_name>) #replace with reg delete to delete
::(reg query “<regpath>” /s) #replace with reg delete <> /v to delete all
@echo off
SET LOGFILE=RegistryResults.txt

echo  ######################

###########################################  >> %LOGFILE% 2>&1
echo  ###                 Registry Keys of Interest                 ###  >> %LOGFILE% 2>&1
echo  #################################################################  >> %LOGFILE% 2>&1
echo . >> %LOGFILE% 2>&1
echo  This script will comb through the registry in search of common persistance techniques and submit the results to a text file >> %LOGFILE% 2>&1
echo . >> %LOGFILE% 2>&1
echo  !!!!!!!!!!!!!!!!!!!!!!!!  High Priority  !!!!!!!!!!!!!!!!!!!!!!!!  >> %LOGFILE% 2>&1
echo . >> %LOGFILE% 2>&1
echo  #################################################################  >> %LOGFILE% 2>&1
echo  ###                       Autoboot Keys                       ###  >> %LOGFILE% 2>&1
echo  #################################################################  >> %LOGFILE% 2>&1
echo  Remove anything found in these keys >> %LOGFILE% 2>&1
echo . >> %LOGFILE% 2>&1
echo  ###                     Computer Profiles                     ###  >> %LOGFILE% 2>&1
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute" /s >> %LOGFILE% 2>&1
reg query "HKLM\System\CurrentControlSet\Services" /s >> %LOGFILE% 2>&1
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce" /s >> %LOGFILE% 2>&1
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices" /s >> %LOGFILE% 2>&1
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify" /s >> %LOGFILE% 2>&1
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit" /s >> %LOGFILE% 2>&1
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell" /s >> %LOGFILE% 2>&1
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad" /s >> %LOGFILE% 2>&1
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce" /s >> %LOGFILE% 2>&1
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnceEx" /s >> %LOGFILE% 2>&1
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /s >> %LOGFILE% 2>&1
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run" /s >> %LOGFILE% 2>&1
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows" /s >> %LOGFILE% 2>&1
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler" /s >> %LOGFILE% 2>&1
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs" /s >> %LOGFILE% 2>&1
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /s >> %LOGFILE% 2>&1
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /s >> %LOGFILE% 2>&1
echo . >> %LOGFILE% 2>&1
echo  ###                       User Profiles                       ###  >> %LOGFILE% 2>&1
reg query "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows\Load" /s >> %LOGFILE% 2>&1
reg query "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows" /s >> %LOGFILE% 2>&1
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /s >> %LOGFILE% 2>&1
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /s >> %LOGFILE% 2>&1
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run" /s >> %LOGFILE% 2>&1
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /s >> %LOGFILE% 2>&1
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce" /s >> %LOGFILE% 2>&1
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices" /s >> %LOGFILE% 2>&1
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce" /s >> %LOGFILE% 2>&1
echo . >> %LOGFILE% 2>&1
echo . >> %LOGFILE% 2>&1
echo  !!!!!!!!!!!!!!!!!!!!!!!!  Medium Priority  !!!!!!!!!!!!!!!!!!!!!!!!  >> %LOGFILE% 2>&1
echo  #################################################################  >> %LOGFILE% 2>&1
echo  ###                       Scheduled Tasks                     ###  >> %LOGFILE% 2>&1
echo  #################################################################  >> %LOGFILE% 2>&1
echo  Rename These Keys  >> %LOGFILE% 2>&1
echo .  >> %LOGFILE% 2>&1
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\Taskcache\Tasks" /s >> %LOGFILE% 2>&1
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\Taskcache\Tree" /s >> %LOGFILE% 2>&1
echo . >> %LOGFILE% 2>&1
echo . >> %LOGFILE% 2>&1
echo  !!!!!!!!!!!!!!!!!!!!!!!!!!  Low Priority  !!!!!!!!!!!!!!!!!!!!!!!!  >> %LOGFILE% 2>&1
echo  #################################################################  >> %LOGFILE% 2>&1
echo  ###                         AppInit DLLS                      ###  >> %LOGFILE% 2>&1
echo  #################################################################  >> %LOGFILE% 2>&1
echo  Clear anything inside these values >> %LOGFILE% 2>&1
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLL >> %LOGFILE% 2>&1
reg query "HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows"  /v AppInit_DLL >> %LOGFILE% 2>&1
echo . >> %LOGFILE% 2>&1
echo  #################################################################  >> %LOGFILE% 2>&1
echo  ###                     Image File Execution                  ###  >> %LOGFILE% 2>&1
echo  #################################################################  >> %LOGFILE% 2>&1
echo  Delete these keys >> %LOGFILE% 2>&1
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" /v Debugger >> %LOGFILE% 2>&1
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" /v GlobalFlag >> %LOGFILE% 2>&1
echo . >> %LOGFILE% 2>&1
echo  #################################################################  >> %LOGFILE% 2>&1
echo  ###                     Application Shimming                  ###  >> %LOGFILE% 2>&1
echo  #################################################################  >> %LOGFILE% 2>&1
echo  Should be empty by default: delete anything in here >> %LOGFILE% 2>&1
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom" >> %LOGFILE% 2>&1
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB" >> %LOGFILE% 2>&1
echo . >> %LOGFILE% 2>&1
echo  #################################################################  >> %LOGFILE% 2>&1
echo  ###                    Authentication Package                 ###  >> %LOGFILE% 2>&1
echo  #################################################################  >> %LOGFILE% 2>&1
echo . >> %LOGFILE% 2>&1
echo  ###                         RID Hijacks                       ###  >> %LOGFILE% 2>&1
echo  Change possible 0x1f4 entry to a normal RID like 0x3eb >> %LOGFILE% 2>&1
reg query "HKLM\SAM\SAM\Domains\Account\Users\" /s >> %LOGFILE% 2>&1
echo . >> %LOGFILE% 2>&1
echo   ###                        Domain Keys                       ### >> %LOGFILE% 2>&1
echo Should only have: kerberos msv1_0 schannel wdigest tspkg pku2u
reg query "HKLM\System\CurrentControlSet\Control\Lsa\Security Packages\ /s >> %LOGFILE% 2>&1
EXIT /B 0
