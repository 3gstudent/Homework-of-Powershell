# Homework-of-Powershell
powershell codes of my blog.

### Invoke-Enumeratefile.ps1

Enumerate all the files under `c:\Windows` that the permission of NT AUTHORITY\SYSTEM is full control.

We can use the task scheduler to write an arbitrary DACL to the file and then we can modify the files with normal user permissions.

This script will enumerate all the files you can take control over.

### Invoke-LibraryFilesPersistence.ps1

First modify the registry and then create a file named Documents.library-ms in %appdata%\Microsoft\Windows\Start Menu\Programs\Accessories.

It'll load c:\test\calc.dll on start-up.

### Delete-Amcache.ps1

This script loads the AMCache hive from the default Windows location and delete the seleted data.
You can use Get-Amcache.ps1 to list the data of AMCache hive,then use this to delete the seleted data.
The new AMCache hive will be saved as new.hve

Get-Amcache.ps1:https://github.com/yoda66/GetAmCache/blob/master/Get-Amcache.ps1

### New-GPOImmediateTask.ps1

Builds an 'Immediate' schtask to push out through a specified GPO.

Because I haven't found out how to register the 'Immediate' schtask yet.

So I have to backup the gpo,then modify the Backup.xml and gpreport.xml,and finally import the gpo.
                
        (1)Create a gpo
            new-gpo -name TestGPO | new-gplink -Target "dc=test,dc=com"
        (2)Use New-GPOImmediateTask.ps1 to backup the gpo into the current path,modify the Backup.xml and gpreport.xml and finally import the gpo       
            New-GPOImmediateTask -TaskName Debugging -GPODisplayName TestGPO -SysPath '\\dc.test.com\sysvol\test.com' -CommandArguments '-c "123 | Out-File C:\test\debug.txt"'
        (3)You can force the client to refresh the gpo:
            Invoke-GPUpdate -Computer "TEST\COMPUTER-01"
           Or you can wait 90 minutes,the client's gpo will refresh automatically. 

### dns-dump.ps1

Dump all the DNS records via AD LDAP and DNS query when you can access the Active Directory.

### Invoke-OutlookPersistence.ps1

This script allows you to use COM Object hijacking to maintain persistence.

When the Outlook starts,it will load the backdoor DLL.

This method is first used by Turla in public.

Learn from:https://www.welivesecurity.com/wp-content/uploads/2018/08/Eset-Turla-Outlook-Backdoor.pdf

### Get-AllExports.ps1

Reference:

https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Get-Exports.ps1

This script is mainly used to automatically scan whether the export function of DLL in the specified directory contains "minidump" or not.

### UsePSSessionToExportMailfromExchange.ps1

This script will export the mail(.pst) from the Exchange server.

First it will use PSSession to connect the Exchange server.

Then it'll check the user's privilege.

If the user is not in the "Mailbox Import Export",the script will add the user to it and reconnect the Exchange server..

Next it will export the mail and save it.

At last it will remove the user from the group and remove the PSSession.

### DirectExportMailfromExchange.ps1

This script will export the mail(.pst) from the Exchange server.

The script needs to be executed on the Exchange server.

### UsePSSessionToSearchMailfromExchange.ps1

This script will search the mail from the Exchange server and export the results to the selected mailbox.

First it will use PSSession to connect the Exchange server.

Then it'll check the user's privilege.

If the user is not in the "Mailbox Search",the script will add the user to it and reconnect the Exchange server.

Next it will search the mail from the Exchange server and export the results to the selected mailbox.

At last it will remove the user from the group and remove the PSSession.

### DirectSearchMailfromExchange.ps1

This script will search the mail from the Exchange server and export the results to the selected mailbox.

The script needs to be executed on the Exchange server.

