function UsePSSessionToSearchMailfromExchange
{
#Requires -Version 2.0
<#
.SYNOPSIS
This script will search the mail from the Exchange server and export the results to the selected mailbox.
First it will use PSSession to connect the Exchange server.
Then it'll check the user's privilege.
If the user is not in the "Mailbox Search",the script will add the user to it and reconnect the Exchange server.
Next it will search the mail from the Exchange server and export the results to the selected mailbox.
At last it will remove the user from the group and remove the PSSession.

Author: 3gstudent

.PARAMETER User
The user to use.
In general, you can choose the account in the domain admins.

.PARAMETER Password
The password of the user.

.PARAMETER MailBox
The mail you want to search.
If you set it as 'All',it will search all the mailbox.

.PARAMETER ConnectionUri
The uri of the Exchange server.
Eg.
    http://Exchange01.test.com/PowerShell/
    
.PARAMETER Filter
The search filter of the mail.

.PARAMETER TargetMailbox
The mailbox of the results will be export.

.PARAMETER TargetFolder
The folder of the targetmailbox. 

.EXAMPLE
PS C:\> UsePSSessionToSearchMailfromExchange -User "administrator" -Password "DomainAdmin123!" -MailBox "test1" -ConnectionUri "http://Exchange01.test.com/PowerShell/" -Filter "*pass*" -TargetMailbox "test2" -TargetFolder "out2"
or
PS C:\> UsePSSessionToSearchMailfromExchange -User "administrator" -Password "DomainAdmin123!" -MailBox "All" -ConnectionUri "http://Exchange01.test.com/PowerShell/" -Filter "*pass*" -TargetMailbox "test2" -TargetFolder "outAll"

#>
 	param (
        [Parameter(Mandatory = $True)]
		[string]$User,
        [Parameter(Mandatory = $True)]
		[string]$Password,
        [Parameter(Mandatory = $True)]
		[string]$MailBox,
        [Parameter(Mandatory = $True)]
		[string]$ConnectionUri,
        [Parameter(Mandatory = $True)]
		[string]$Filter,
        [Parameter(Mandatory = $True)]
        [string]$TargetMailbox,
        [Parameter(Mandatory = $True)]
        [string]$TargetFolder
	)
    $Flag = 0
    Write-Host "[>] Start to Import-PSSession" 
    #Import-PSSession
    $Pass = ConvertTo-SecureString -AsPlainText $Password -Force
    $Credential = New-Object System.Management.Automation.PSCredential -ArgumentList $User,$Pass
    $Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $ConnectionUri -Authentication Kerberos -Credential $Credential
    Import-PSSession $Session -AllowClobber| Out-Null

    Write-Host "[>] Start to check user"
    #check user
    if(Get-ManagementRoleAssignment ("Mailbox Search-"+$User) -ErrorAction SilentlyContinue) 
    {
    	Write-Host "[!] The specified user already exists.No need to add it to the group"
	$Flag = 1
    }
    else
    {
    	Write-Host "[+] Start to add user" 
    	#Add user
    	New-ManagementRoleAssignment –Role "Mailbox Search" –User $User| Out-Null
    	Write-Host "[>] Start to reconnect"
    	#Reconnect
    	Remove-PSSession $Session
    	$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $ConnectionUri -Authentication Kerberos -Credential $Credential
    	Import-PSSession $Session -AllowClobber| Out-Null
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
    
    if ($Flag = 0)
    {
        Write-Host "[>] Start to remove user"
        #Remove user
        Get-ManagementRoleAssignment ("Mailbox Search-"+$User) |Remove-ManagementRoleAssignment -Confirm:$false
    }
    
    Write-Host "[>] Start to Remove-PSSession"
    #Remove PSSession
    Remove-PSSession $Session
    Write-Host "[+] All done."
}
