function DirectSearchMailfromExchange
{
#Requires -Version 2.0
<#
.SYNOPSIS
This script will search the mail from the Exchange server and export the results to the selected mailbox.
The script needs to be executed on the Exchange server.

Author: 3gstudent

.PARAMETER MailBox
The mail you want to search.
If you set it as 'All',it will search all the mailbox.
    
.PARAMETER Filter
The search filter of the mail.

.PARAMETER TargetMailbox
The mailbox of the results will be export.

.PARAMETER TargetFolder
The folder of the targetmailbox. 

.PARAMETER $Version
The version of the Exhange.
It can be 2007,2010,2013 and 2016.

.EXAMPLE
PS C:\> DirectSearchMailfromExchange -MailBox "test1" -Filter "*pass*" -TargetMailbox "test2" -TargetFolder "out2" -Version 2013
or
PS C:\> DirectSearchMailfromExchange -MailBox "All" -Filter "*pass*" -TargetMailbox "test2" -TargetFolder "outAll" -Version 2013

#>
 	param (
        [Parameter(Mandatory = $True)]
		[string]$MailBox,
        [Parameter(Mandatory = $True)]
		[string]$Filter,
        [Parameter(Mandatory = $True)]
        [string]$TargetMailbox,
        [Parameter(Mandatory = $True)]
        [string]$TargetFolder,
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

    Write-Host "[+] Start to search mail and export the results to the selectd mailbox" 
    #Searche mail and export the results to the selectd mailbox
    if($MailBox -eq "all")
    {
        Write-Host "[!] It will search from all the mailbox,it may be a long time." 
        Get-Mailbox|Search-Mailbox -SearchQuery $Filter -TargetMailbox $TargetMailbox -TargetFolder $TargetFolder -LogLevel Suppress| Out-Null
    }
    else
    {
        Search-Mailbox -Identity $MailBox -SearchQuery $Filter -TargetMailbox $TargetMailbox -TargetFolder $TargetFolder -LogLevel Suppress| Out-Null
    }
    Write-Host "[+] All done."
}
