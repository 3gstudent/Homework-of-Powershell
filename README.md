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


