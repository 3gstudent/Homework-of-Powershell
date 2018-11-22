function Delete-Amcache
{
#Requires -Version 3.0
<#
.SYNOPSIS
This script loads the AMCache hive from the default Windows location and delete the seleted data.
You can use Get-Amcache.ps1 to list the data of AMCache hive,then use this to delete the seleted data.
The new AMCache hive will be saved as new.hve
.Reference 
https://github.com/yoda66/GetAmCache/blob/master/Get-Amcache.ps1
Author: 3gstudent
.PARAMETER RegHive
The Amcache registry hive file to load.  Defaults to \Windows\AppCompat\Programs\Amcache.hve
.PARAMETER DestRegKey
The destination registry key to load the registry hive to.  Defaults to HKLM:\amcache
.PARAMETER Filename
The filename to be deleted.
.EXAMPLE
PS C:\> Delete-Amcache -Filename putty.exe
#>

    [CmdletBinding()]
        Param (
            [Parameter(HelpMessage="Location of Amcache.hve file")]
            [String]$RegHive = $env:SYSTEMROOT + "\AppCompat\Programs\Amcache.hve",

            [Parameter(HelpMessage="Destination registry key to load amcache hive to")]
            [String]$DestRegKey = "HKLM\amcache",

            [Parameter(HelpMessage="Specify a filename to match,then remove the registry.")]
            [String]$Filename=""
        )
    $output = &"whoami"
    if($output -notmatch "nt authority\\system")
    {
	   Write-Error "Script must be run as nt authority\system" -ErrorAction Stop
    }
    try {
        #Load AMCache hive
        reg.exe load $DestRegKey $RegHive | Out-Null
        #Backup the AMCache hive
        Write-Host "[+]The AMCache hive will be backuped as backup.hve"
        reg.exe save $DestRegKey "backup.hve" /y| Out-Null

        $rootfile = $DestRegKey.replace("\", ":") + "\Root\File"

        Get-ChildItem -Recurse -Path $rootfile | Get-ItemProperty | `
            foreach {
                $RegPath = $_.PSPath.Substring( $_.PSPath.LastIndexOf(":")+1 )
                $RegPath = "HKLM:" + $RegPath.Substring($RegPath.IndexOf("\") )

                $FilePath = $_.15
                if($FilePath -match $Filename)
                {
                    Write-Host "[+]Data to be removed:"
                    Write-Host $FilePath
                    Write-Host $RegPath
                    Remove-Item $RegPath -Recurse -Force
                }            
            }
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        Write-Output $ErrorMessage
	    break
    }
    finally {
        [gc]::collect()
        [gc]::WaitForPendingFinalizers()
        #Generate the new AMCache hive
        Write-Host "[+]The new AMCache hive will be saved as new.hve"
        reg.exe save $DestRegKey "new.hve" /y| Out-Null
        #Unload it
        reg.exe unload $DestRegKey | Out-Null
    }
}
