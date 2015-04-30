# Program			: ## ServerScan AD Patching Script
# Author			: Christopher P. Maher
# Organization		: ##
# Description		: This utility will parse out the information that is important for the Wintel team from a security scan.
# Date Created		: 04-28-2015
# Date Modified		: 04-30-2015
(
	[Parameter(Mandatory=$True,Position=1)]
	[string]$inputfile,
	[Parameter(Mandatory=$True,Position=2)]
	[string]$outputCSV
)
function nMaper ($serverName)
{
	$tempArg = "-p 443 --script +ssl-enum-ciphers " + $servername
	$proc = New-Object System.Diagnostics.ProcessStartInfo
	$path = "\\tac-app273\E$\Scripts\SSL Registry Check TimeUp\Nmap\nmap.exe"
	$proc.FileName = $path
	$proc.RedirectStandardOutput = $True
	$proc.UseShellExecute = $false
	$proc.Arguments = $tempArg
	$p = New-Object System.Diagnostics.Process
	$p.StartInfo = $proc
	$p.Start() 
	$p.WaitForExit()
	$output = $p.StandardOutput.ReadToEnd() > tempStream.txt
	$inputOne = Get-Content tempStream.txt
	foreach($line in $inputOne)
	{
		if($line.StartsWith("443"))
		{
			return $line
		}
	}	
}
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
Add-Content -path $outputCSV -Value "Server,Last Reboot Date,Registry Status,NMAP Status"
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
	$nMapOutput = nMaper($server)	
	$passVar = $server + "," + $wmitime + "," + $regmessage + "," + $nMapOutput
	add-content -value $passvar -path $outputCSV	
}
cls
Start-Process "excel" -ArgumentList $outputcsv

