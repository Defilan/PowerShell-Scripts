# Program			: ## ServerScan AD Patching Script
# Author			: Christopher P. Maher
# Organization		: ##
# Description		: This utility will parse out the information that is important for the Wintel team from a security scan.
# Date Created		: 04-28-2015
# Date Modified		: 04-29-2015
Param
(
	[Parameter(Mandatory=$True,Position=1)]
	[string]$inputfile,
	[Parameter(Mandatory=$True,Position=2)]
	[string]$outputCSV
)
#$tempDir = $env:temp
#$outputCSV = $tempDir + "\tempdata.txt"
if(![System.IO.File]::Exists($outputCSV))
{
	New-Item $outputCSV -type file
}

If (Test-Path $inputfile){
                $servers = get-content $inputfile | sort-object | get-unique
}
else {
                echo "No server list found.  Please verify the server list is in the same directory and called servers.txt"
}
Clear-Content $outputCSV
Add-Content -path $outputCSV -Value "Server,Last Reboot Date,Registry Status"
foreach($server in $servers)
{
	$wmiTime
	$regMessage
	try
	{
		$tempTime = Get-WmiObject Win32_OperatingSystem -ComputerName $server | select -ExpandProperty LastBootupTime
		$wmiTime = [System.Management.ManagementDateTimeConverter]::ToDateTime($tempTime)
	}
	catch
	{
		$wmitime = "Could not connect to " + $server + " with WMI,"
	}
	try
	{
		$Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine',$server)
		$RegKey = $Reg.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\Schannel\\Protocols\\SSL 3.0\\Server",$true)
		if(!$RegKey)
		{
			$regmessage = "Registry key does not exist"
		}		
		if($RegKey.GetValue("Enabled") -eq "0")
		{
			$RegMessage = "Registry Settings Correct"
			#add-content -value ($server + ":     Registry Settings Correct") -path $outputCSV 			 
		}
		else
		{
			$regeMessage = "Registry value does not exist"
		}	
	}
	catch
	{
		$Regmessage = "Registry key does not exist"
	}
	$passedMessage = $server + " was last rebooted on: " + $wmitime + ". Registry Status: " + $regMessage
	$passVar = $server + "," + $wmitime + "," + $regmessage
	add-content -value $passvar -path $outputCSV
}
cls
Start-Process "excel" -ArgumentList $outputcsv

