function DirectExportMailfromExchange
{
#Requires -Version 2.0
<#
.SYNOPSIS
This script will export the mail(.pst) from the Exchange server.
The script needs to be executed on the Exchange server.

Author: 3gstudent

.PARAMETER MailBox
The mail you want to export.

.PARAMETER ExportPath
The export path of the mail.
 
.PARAMETER $Filter
The search filter of the mail.

.PARAMETER $Version
The version of the Exhange.
It can be 2007,2010,2013 and 2016.

.EXAMPLE
PS C:\> DirectExportMailfromExchange -MailBox "test1" -ExportPath "\\localhost\c$\test\" -Filter "{`"(body -like `"*pass*`")`"}" -Version 2013
#>
 	param (
        [Parameter(Mandatory = $True)]
		[string]$MailBox,
        [Parameter(Mandatory = $True)]
		[string]$ExportPath,
        [Parameter(Mandatory = $True)]
		[string]$Filter,
        [Parameter(Mandatory = $True)]
		[string]$Version
	)

    Write-Host "[>] Start to add PSSnapin" 
    if ($Version -eq 2007)
    {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.Admin;
    }

    elseif ($Version -eq 2010)
    {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.E2010;
    }

    else
    {
        
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn;
    }
  
    Write-Host "[+] Start to export mail" 
    #Export mail and do not save the export request
    New-MailboxexportRequest -mailbox $MailBox -ContentFilter {(body -like "*pass*")} -FilePath ($ExportPath+$MailBox+".pst") -CompletedRequestAgeLimit 0
    Write-Host "[+] All done."
}
