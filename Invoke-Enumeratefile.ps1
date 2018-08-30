function Invoke-Enumeratefile
{
<#
.SYNOPSIS
Enumerate all the files under c:\Windows that the permission of NT AUTHORITY\SYSTEM is full control.
We can use the task scheduler to write an arbitrary DACL to the file and then we can modify the files with normal user permissions.
This script will enumerate all the files you can take control over.

.LINK
https://github.com/SandboxEscaper/randomrepo/blob/master/PoC-LPE.rar

.PARAMETER SearchType
Specifies the file byte to search.

.EXAMPLE
PS C:\> Invoke-Enumeratefile -SearchType exe
PS C:\> Invoke-Enumeratefile -SearchType dll
#>

 	param (
        [Parameter(Mandatory = $True)]
		[string]$SearchType
	)
    
    #eg. search *.exe
    $Type = "*." + $SearchType
    $aapsid = 'NT AUTHORITY\SYSTEM'
    ForEach($file in (Get-ChildItem -recurse -Filter $Type -Path 'C:\windows'  -ErrorAction SilentlyContinue )) 
    {
        $acl = Get-Acl -path $file.PSPath
        ForEach($ace in $acl.Access) 
        {
            If(($ace.FileSystemRights -eq [Security.AccessControl.FileSystemRights]::FullControl) -and $ace.IdentityReference.Value -eq $aapsid) 
            {
                Write-Output $file.PSPath.Substring(38)
            }
        }
    }
}
Invoke-Enumeratefile -SearchType exe
