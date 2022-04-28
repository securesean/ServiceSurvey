# Sean Pierce
# @secure_sean 
# May 2021
# I know this is trash and I'm sorry

# CS:
# powershell-import /home/kali/Desktop/Get-ListeningServices.ps1
# powershell Get-ListeningServices

# Ripped from https://superuser.com/questions/1609746/how-to-sort-registry-entries-by-last-write-time-last-modified-time-in-powershell
# Note: In my testing, all of the service registry key write timestamps get touched on reboot
function Add-RegKeyLastWriteTime {
[CmdletBinding()]
param(
    [Parameter(Mandatory, ParameterSetName="ByKey", Position=0, ValueFromPipeline)]
    # Registry key object returned from Get-ChildItem or Get-Item
    [Microsoft.Win32.RegistryKey] $RegistryKey,
    [Parameter(Mandatory, ParameterSetName="ByPath", Position=0)]
    # Path to a registry key
    [string] $Path
)

 begin {
    # Define the namespace (string array creates nested namespace):
    $Namespace = "HeyScriptingGuy"

    # Make sure type is loaded (this will only get loaded on first run):
    Add-Type @"
        using System;
        using System.Text;
        using System.Runtime.InteropServices;

        $($Namespace | ForEach-Object {
            "namespace $_ {"
        })
            public class advapi32 {
                [DllImport("advapi32.dll", CharSet = CharSet.Auto)]
                public static extern Int32 RegQueryInfoKey(
                    Microsoft.Win32.SafeHandles.SafeRegistryHandle hKey,
                    StringBuilder lpClass,
                    [In, Out] ref UInt32 lpcbClass,
                    UInt32 lpReserved,
                    out UInt32 lpcSubKeys,
                    out UInt32 lpcbMaxSubKeyLen,
                    out UInt32 lpcbMaxClassLen,
                    out UInt32 lpcValues,
                    out UInt32 lpcbMaxValueNameLen,
                    out UInt32 lpcbMaxValueLen,
                    out UInt32 lpcbSecurityDescriptor,
                    out System.Runtime.InteropServices.ComTypes.FILETIME lpftLastWriteTime
                );
            }
        $($Namespace | ForEach-Object { "}" })
"@
   
    # Get a shortcut to the type:   
    $RegTools = ("{0}.advapi32" -f ($Namespace -join ".")) -as [type]
}
 process {
    switch ($PSCmdlet.ParameterSetName) {
        "ByKey" {
            # Already have the key, no more work to be done 
        }
        "ByPath" {
            # We need a RegistryKey object (Get-Item should return that)
            $Item = Get-Item -Path $Path -ErrorAction Stop
 
            # Make sure this is of type [Microsoft.Win32.RegistryKey]
            if ($Item -isnot [Microsoft.Win32.RegistryKey]) {
                throw "'$Path' is not a path to a registry key!"
            }
            $RegistryKey = $Item
        }
    }
 
    # Initialize variables that will be populated:
    $ClassLength = 255 # Buffer size (class name is rarely used, and when it is, I've never seen
                        # it more than 8 characters. Buffer can be increased here, though.
    $ClassName = New-Object System.Text.StringBuilder $ClassLength  # Will hold the class name
    $LastWriteTime = New-Object System.Runtime.InteropServices.ComTypes.FILETIME 
           
    switch ($RegTools::RegQueryInfoKey($RegistryKey.Handle,
        $ClassName,
        [ref] $ClassLength,
        $null,  # Reserved
        [ref] $null, # SubKeyCount
        [ref] $null, # MaxSubKeyNameLength
        [ref] $null, # MaxClassLength
        [ref] $null, # ValueCount
        [ref] $null, # MaxValueNameLength
        [ref] $null, # MaxValueValueLength
        [ref] $null, # SecurityDescriptorSize
        [ref] $LastWriteTime
    )) {
         0 { # Success
            # Convert to DateTime object:
            $UnsignedLow = [System.BitConverter]::ToUInt32([System.BitConverter]::GetBytes($LastWriteTime.dwLowDateTime), 0)
            $UnsignedHigh = [System.BitConverter]::ToUInt32([System.BitConverter]::GetBytes($LastWriteTime.dwHighDateTime), 0)
            # Shift high part so it is most significant 32 bits, then copy low part into 64-bit int:
            $FileTimeInt64 = ([Int64] $UnsignedHigh -shl 32) -bor $UnsignedLow
            # Create datetime object
            $LastWriteTime = [datetime]::FromFileTime($FileTimeInt64)
 
            # Add properties to object and output them to pipeline
            $RegistryKey | Add-Member -NotePropertyMembers @{
                LastWriteTime = $LastWriteTime
                ClassName = $ClassName.ToString()
            } -PassThru -Force
        }
        122  { # ERROR_INSUFFICIENT_BUFFER (0x7a)
            throw "Class name buffer too small"
            # function could be recalled with a larger buffer, but for
            # now, just exit
        }
        default {
            throw "Unknown error encountered (error code $_)"
        }
    }
}
}

New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null

function GetBinPathFromCommandLine()
{
    param([string]$commandLine)

    $slices = $commandLine.split()

    $output = ""
    foreach( $part in $slices ){
        $output = $output + $part
        if(($output -match '.dll$') -or ($output -match '.exe$') -or ($output -match '.sys$') ){
            break
        } else {
            $output = $output + " "
        }
    }

    return $output
}

function GetServiceBinInfoByKey()
{  
    param([string]$regKey)
    # Comes in the form of HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TrustedInstaller
    # Needs to be Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TrustedInstaller


	$ServiceKey = Get-ItemProperty ("Registry::" + $regKey)
    
    if(!($ServiceKey -eq $null ))
    {
        $registryBinPathArray = @()
        if ($ServiceKey.ImagePath -ne $null){
            $output = "`t" + $ServiceKey.ImagePath
            $ImagePath = $ServiceKey.ImagePath
            $registryBinPathArray = $registryBinPathArray + $ServiceKey.ImagePath
		    Write-Output $output
	    } elseif ($ServiceKey.ServiceDll -ne $null){
            $output = "`t" + $ServiceKey.ServiceDll
            $ServiceDll = $ServiceKey.ServiceDll
            $registryBinPathArray = $registryBinPathArray + $ServiceKey.ServiceDll
		    Write-Output $output
	    } elseif ($ServiceKey.MofImagePath -ne $null){
            $output = "`t" + $ServiceKey.MofImagePath
            $MofImagePath = $ServiceKey.MofImagePath
            $registryBinPathArray = $registryBinPathArray + $ServiceKey.MofImagePath
		    Write-Output $output
	    } else {
            $output = "`t" + "Interesting: No binary for this service"
            Write-Output $output
            return $null
        }
    } else {
        $output = "`t" + "Error: No Service information exists for: " + $regKey
        #Write-Output $output
        return $null
    }

    # What do I want to know? 
    # If there is only one non-null return that
    # If there is more than one then write an error and choose one
	if($registryBinPathArray.Length -eq 1){
        return $registryBinPathArray[0]
    } else 
    {
            $output = "`t" + "Interesting: There are multiple bianries for this serivce: $registryBinPathArray"
            Write-Output $output
            return $registryBinPathArray[0]
    }
}

function GetServiceBinInfoByName()
{  
    param([string]$name)
    # Comes in the form of TrustedInstaller
    # Needs to be Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TrustedInstaller

    if($name -eq "service"){
        return
    }

    $path = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\" + $name
    if(Test-Path $path )
    {
        $ServiceKey = Get-ItemProperty ($path)
	    if ($ServiceKey.ImagePath -ne $null){
            $output = "`t" + $ServiceKey.ImagePath
		    Write-Output $output
	    } elseif ($ServiceKey.ServiceDll -ne $null){
            $output = "`t" + $ServiceKey.ServiceDll
		    Write-Output $output
	    } else {
            $output = "`t" + "Interesting: No binary for this service"
            # Write-Output $output
        }
    } else {
        #$output = "`t" + "Error: No Service with that name exists"
        # Write-Output $output
    }
}


$SrvRunningWmi = Get-WmiObject -Namespace "root\cimv2" -Class "Win32_Service" | Where-Object {$_.State -eq "Running"}
function GetServiceBinInfoByPidWmi()
{  
    param([string]$processId)
    # Comes in the form of TrustedInstaller
    # Needs to be Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TrustedInstaller

    foreach($service in $SrvRunningWmi){
        if($service.ProcessId -eq $processId){
            #Write-Output "Found by PID: "
            GetServiceBinInfoByName($service.Name)
        }
    }
}


$SrvRunningTaskList=Tasklist /svc /fo csv | convertfrom-csv
function GetServiceBinInfoByPidTaskList()
{  
    param([string]$processId)

    foreach($task in $SrvRunningTaskList){
        if($task.pid -eq $processId){
            #Write-Output "Found by PID: "
            # The "services" property here looks like "BrokerInfrastructure,DcomLaunch,Power,SystemEventsBroker"
            if($task -ne "N/A"){
                $serviceArray = $task.Services.Split(",")
                foreach($service in $serviceArray){
                    # Write-Output "`tFound by Task PID: "
                    GetServiceBinInfoByName($service)
                }
            } 
            
        }
    }
}

# Last 10 Written Services
# doesn't work: | Where-Object LastWriteTime -gt (Get-Date).AddDays(-1) | 
Write-Output "`n`n=========== Last 10 Services (Reg Time Stamp) ==========="
#Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Services | Add-RegKeyLastWriteTime |  Select-Object Name, LastWriteTime |  Sort-object LastWriteTime | Select-Object -Last 10  |  Sort-object -Descending LastWriteTime
$SrvArr = Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Services | Add-RegKeyLastWriteTime |  Select-Object Name, LastWriteTime |  Sort-object LastWriteTime | Select-Object -Last 10  |  Sort-object -Descending LastWriteTime
foreach($item in $SrvArr){ 
    $message = $item.LastWriteTime.ToString() + " - " + $item.Name 
    Write-Output $message
	GetServiceBinInfoByKey( $item.Name ) 
}

Write-Output "`n`n=========== Last 10 Installed Services (File Time Stamp) ==========="
$SrvArr = Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Services 
$binpathes = @()
foreach($item in $SrvArr){ 
    # $message = $item.LastWriteTime.ToString() + " - " + $item.Name 
    # Write-Output $message
	$binpathes += GetServiceBinInfoByKey( $item.Name ) 
}

$CorrectedBinpathes = @()
foreach($binpath in $binpathes){
    if( ($binpath -ne "") -and !($binpath -eq $null)){
        $Corrected = $binpath.Trim()
        $Corrected = $Corrected -replace "\\SystemRoot", "%SystemRoot%"
        $Corrected = $Corrected -replace "^System32", "%SystemRoot%\System32"
        $Corrected = $Corrected -replace "^SysWOW64", "%SystemRoot%\SysWOW64"
        $Corrected = $Corrected -replace "^\\\?\?\\"  # To remove \??\C:\Strings
        $Corrected = $Corrected -replace '"'
        $Corrected = GetBinPathFromCommandLine($Corrected)
        $Corrected = [System.Environment]::ExpandEnvironmentVariables($Corrected)
        if(!($Corrected -match "^Interesting"))  # I have no idea how this keeps getting into the pipe
        {
            $CorrectedBinpathes = $CorrectedBinpathes +  $Corrected
        }
    }

}
$CorrectedBinpathes | Get-Item | Sort-object CreationTime -Descending | Select-Object -Last 10 
#foreach ($correctBinPath in $CorrectedBinpathes){
#    
#    try{
#        Get-Item -ErrorAction Stop -Path $correctBinPath
#    } catch [System.Exception]{
#        Write-Host "Alert: File does not exist. Checking if location is writable..."
#        #Try { [io.file]::OpenWrite($correctBinPath).close() }
#        #Catch { Write-Warning "Unable to write to output file $outputfile" }
#    }
#}

#Write-Output "`n`n=========== All Running Services (PS) ==========="
#$SrvRunning = Get-Service | Where-Object {$_.Status -eq "Running"}   # Note: doesn't return process ID
#foreach($item in $SrvRunning){ 
#    Write-Output $item.Name 
#	GetServiceBinInfoByName( $item.Name ) 
#}


Write-Output "`n`n=========== Ports and the services binaries ==========="
# From: https://superuser.com/questions/1215093/powershell-one-liner-to-show-process-on-same-line-as-port-using-netstat-issue
$processOnPortList = get-nettcpconnection | select local*,remote*,state,OwningProcess,@{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).ProcessName}} | sort-object LocalPort
foreach($item in $processOnPortList){ 
    if(($item.State -eq "Listen") -and ($item.LocalAddress -ne "127.0.0.1") -and ($item.LocalAddress -ne "::1"))
    {
        $message = $item.LocalPort.ToString() + " - (PID: " + $item.OwningProcess + ") " + $item.Process # + " listing on " + $item.LocalAddress
        Write-Output $message
	    GetServiceBinInfoByName( $item.Process ) 
	    GetServiceBinInfoByPidWmi( $item.OwningProcess ) 
        GetServiceBinInfoByPidTaskList($item.OwningProcess ) 
    }
    
}

