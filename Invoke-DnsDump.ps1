##
## dns-dump.ps1
##
## Michael B. Smith
## michael at smithcons dot com
## http://TheEssentialExchange.com/blogs/michael
## May/June, 2009
## Updated December, 2009 adding many add'l record types.
##
## Use as you wish, no warranties expressed, implied or explicit.
## Works for me, may not for you.
## If you use it, I would appreciate an attribution.
##
## Thanks to Chris Dent, chris at highorbit dot co dot uk
## for some clarification on the precise format of the
## dnsRecord attribute. See his blog post on the topic at
## http://www.highorbit.co.uk/?p=1097
## ---------------------------------------------------------------------
## Update：2019.4.28
## 3gstudent
## I modified the search parameters to use in the new environment.(Eg.Server2012R2)
## Reference:https://github.com/mmessano/PowerShell/blob/master/dns-dump.ps1
## .EXAMPLE
## PS C:\> Powershell -ep bypass -f dns-dump.ps1 -zone test.com
## PS C:\> Powershell -ep bypass -f dns-dump.ps1 -zone test.com -csv
##

Param(
	[string]$zone,
	[string]$domain,
	[string]$dc,
	[switch]$csv,
	[switch]$help
)

function dumpByteArray([System.Byte[]]$array, [int]$width = 9)
{
	## this is only used if we run into a record type
	## we don't understand.

	$hex = ""
	$chr = ""
	$int = ""

	$i = $array.Count
	"Array contains {0} elements" -f $i
	$index = 0
	$count = 0
	while ($i-- -gt 0)
	{
		$val = $array[$index++]

		$hex += ("{0} " -f $val.ToString("x2"))

		if ([char]::IsLetterOrDigit($val) -or 
		    [char]::IsPunctuation($val)   -or 
		   ([char]$val -eq " "))
		{
			$chr += [char]$val
		}
		else
		{
			$chr += "."
		}

		$int += "{0,4:N0}" -f $val

		$count++
		if ($count -ge $width)
		{
			"$hex $chr $int"
			$hex = ""
			$chr = ""
			$int = ""
			$count = 0
		}		
	}

	if ($count -gt 0)
	{
		if ($count -lt $width)
		{
			$hex += (" " * (3 * ($width - $count)))
			$chr += (" " * (1 * ($width - $count)))
			$int += (" " * (4 * ($width - $count)))
		}

		"$hex $chr $int"
	}
}

function dwordLE([System.Byte[]]$arr, [int]$startIndex)
{
	## convert four consecutive bytes in $arr into a
	## 32-bit integer value... if I had bit-manipulation
	## primitives in PowerShell, I'd use them instead
	## of the multiply operator.
	##
	## this routine is for little-endian values.

	$res = $arr[$startIndex + 3]
	$res = ($res * 256) + $arr[$startIndex + 2]
	$res = ($res * 256) + $arr[$startIndex + 1]
	$res = ($res * 256) + $arr[$startIndex + 0]

	return $res
}

function dwordBE([System.Byte[]]$arr, [int]$startIndex)
{
	## convert four consecutive bytes in $arr into a
	## 32-bit integer value... if I had bit-manipulation
	## primitives in PowerShell, I'd use them instead
	## of the multiply operator.
	##
	## this routine is for big-endian values.

	$res = $arr[$startIndex]
	$res = ($res * 256) + $arr[$startIndex + 1]
	$res = ($res * 256) + $arr[$startIndex + 2]
	$res = ($res * 256) + $arr[$startIndex + 3]

	return $res
}

function wordLE([System.Byte[]]$arr, [int]$startIndex)
{
	## convert two consecutive bytes in $arr into a
	## 16-bit integer value... if I had bit-manipulation
	## primitives in PowerShell, I'd use them instead
	## of the multiply operator.
	##
	## this routine is for little-endian values.

	$res = $arr[$startIndex + 1]
	$res = ($res * 256) + $arr[$startIndex]

	return $res
}

function wordBE([System.Byte[]]$arr, [int]$startIndex)
{
	## convert two consecutive bytes in $arr into a
	## 16-bit integer value... if I had bit-manipulation
	## primitives in PowerShell, I'd use them instead
	## of the multiply operator.
	##
	## this routine is for big-endian values.

	$res = $arr[$startIndex]
	$res = ($res * 256) + $arr[$startIndex + 1]

	return $res
}

function decodeName([System.Byte[]]$arr, [int]$startIndex)
{
	## names in DNS are stored in two formats. one
	## format contains a single name and is what we
	## called "simple string" in the old days. the
	## first byte of a byte array contains the length
	## of the string, and the rest of the bytes in 
	## the array are the data in the string.
	##
	## a "complex string" is built from simple strings.
	## the complex string is prefixed by the total
	## length of the complex string in byte 0, and the
	## total number of segments in the complex string
	## in byte 1, and the first simple string starts 
	## (with its length byte) in byte 2 of the complex
	## string.

	[int]$totlen   = $arr[$startIndex]
	[int]$segments = $arr[$startIndex + 1]
	[int]$index    = $startIndex + 2

	[string]$name  = ""

	while ($segments-- -gt 0)
	{
		[int]$segmentLength = $arr[$index++]
		while ($segmentLength-- -gt 0)
		{
			$name += [char]$arr[$index++]
		}
		$name += "."
	}

	return $name
}

function analyzeArray([System.Byte[]]$arr, [System.Object]$var)
{
	$nameArray = $var.distinguishedname.ToString().Split(",")
	$name = $nameArray[0].SubString(3)

	## RData Length is the length of the payload in bytes (that is, the variable part of the record)
	## Truth be told, we don't use it. The payload starts at $arr[24]. If you are ever concerned
	## about corrupt data and running off the end of $arr, then you need to verify against the RData
	## Length value.
	$rdataLen = wordLE $arr 0

	## RData Type is the type of the record
	$rdatatype = wordLE $arr 2

	## the serial in the SOA where this item was last updated
	$updatedAtSerial = dwordLE $arr 8

	## TimeToLive
	$ttl = dwordBE $arr 12

	## $unknown = dword $arr 16

	## timestamp of when the record expires, or 0 means "static"
	$age = dwordLE $arr 20
	if ($age -ne 0)
	{
		## hours since January 1, 1601 (start of Windows epoch)
		## there is a long-and-dreary way to do this manually,
		## but get-date makes it trivial to do the conversion.
		$timestamp = ((get-date -year 1601 -month 1 -day 1 -hour 0 -minute 0 -second 0).AddHours($age)).ToString()
	}
	else
	{
		$timestamp = "[static]"
	}

	if ($rdatatype -eq 1)
	{
		# "A" record
		$ip = "{0}.{1}.{2}.{3}" -f $arr[24], $arr[25], $arr[26], $arr[27]

		if ($csv)
		{
			$formatstring = "{0},{1},{2},{3},{4}"
		}
		else
		{
			$formatstring = "{0,-30}`t{1,-24}`t{2}`t{3}`t{4}"
		}

		$formatstring -f $name, $timestamp, $ttl, "A", $ip
	}
	elseif ($rdatatype -eq 2)
	{
		# "NS" record
		$nsname = decodeName $arr 24

		if ($csv)
		{
			$formatstring = "{0},{1},{2},{3},{4}"
		}
		else
		{
			$formatstring = "{0,-30}`t{1,-24}`t{2}`t{3}`t{4}"
		}

		$formatstring -f $name, $timestamp, $ttl, "NS", $nsname
	}
	elseif ($rdatatype -eq 5)
	{
		# CNAME record
		# canonical name or alias

		$alias = decodeName $arr 24

		if ($csv)
		{
			$formatstring = "{0},{1},{2},{3},{4}"
		}
		else
		{
			$formatstring = "{0,-30}`t{1,-24}`t{2}`t{3}`t{4}"
		}

		$formatstring -f $name, $timestamp, $ttl, "CNAME", $alias
	}
	elseif ($rdatatype -eq 6)
	{
		# "SOA" record
		# "Start-Of-Authority"

		$nslen = $arr[44]
		$priserver = decodeName $arr 44
		$index = 46 + $nslen

		# "Primary server: $priserver"

		##$index += 1
		$resparty = decodeName $arr $index

		# "Responsible party: $resparty"

		# "TTL: $ttl"
		# "Age: $age"

		$serial = dwordBE $arr 24
		# "Serial: $serial"

		$refresh = dwordBE $arr 28
		# "Refresh: $refresh"

		$retry = dwordBE $arr 32
		# "Retry: $retry"

		$expires = dwordBE $arr 36
		# "Expires: $expires"

		$minttl = dwordBE $arr 40
		# "Minimum TTL: $minttl"

		if ($csv)
		{
			$formatstring = "{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10}"

			$formatstring -f $name, $timestamp, $ttl, `
				"SOA", $priserver, $resparty, `
				$serial, $refresh, $retry, `
				$expires, $minttl
		}
		else
		{
			$formatstring = "{0,-30}`t{1,-24}`t{2}`t{3}"

			$formatstring -f $name, $timestamp, $ttl, "SOA"
			(" " * 32) + "Primary server: $priserver"
			(" " * 32) + "Responsible party: $resparty"
			(" " * 32) + "Serial: $serial"
			(" " * 32) + "TTL: $ttl"
			(" " * 32) + "Refresh: $refresh"
			(" " * 32) + "Retry: $retry"
			(" " * 32) + "Expires: $expires"
			(" " * 32) + "Minimum TTL (default): $minttl"
		}
	}
	elseif ($rdatatype -eq 12)
	{
		# "PTR" record

		$ptr = decodeName $arr 24

		if ($csv)
		{
			$formatstring = "{0},{1},{2},{3},{4}"
		}
		else
		{
			$formatstring = "{0,-30}`t{1,-24}`t{2}`t{3}`t{4}"
		}

		$formatstring -f $name, $timestamp, $ttl, "PTR", $ptr
	}
	elseif ($rdatatype -eq 13)
	{
		# "HINFO" record

		[string]$cputype = ""
		[string]$ostype  = ""

		[int]$segmentLength = $arr[24]
		$index = 25

		while ($segmentLength-- -gt 0)
		{
			$cputype += [char]$arr[$index++]
		}

		$index = 24 + $arr[24] + 1
		[int]$segmentLength = $index++

		while ($segmentLength-- -gt 0)
		{
			$ostype += [char]$arr[$index++]
		}

		if ($csv)
		{
			$formatstring = "{0},{1},{2},{3},{4},{5}"
		}
		else
		{
			$formatstring = "{0,-30}`t{1,-24}`t{2}`t{3}`t{4},{5}"
		}

		$formatstring -f $name, $timestamp, $ttl, "HINFO", $cputype, $ostype
	}
	elseif ($rdatatype -eq 15)
	{
		# "MX" record

		$priority = wordBE $arr 24
		$mxhost   = decodeName $arr 26

		if ($csv)
		{
			$formatstring = "{0},{1},{2},{3},{4},{5}"
		}
		else
		{
			$formatstring = "{0,-30}`t{1,-24}`t{2}`t{3}`t{4}  {5}"
		}

		$formatstring -f $name, $timestamp, $ttl, "MX", $priority, $mxhost
	}
	elseif ($rdatatype -eq 16)
	{
		# "TXT" record

		[string]$txt  = ""

		[int]$segmentLength = $arr[24]
		$index = 25

		while ($segmentLength-- -gt 0)
		{
			$txt += [char]$arr[$index++]
		}

		if ($csv)
		{
			$formatstring = "{0},{1},{2},{3},{4}"
		}
		else
		{
			$formatstring = "{0,-30}`t{1,-24}`t{2}`t{3}`t{4}"
		}

		$formatstring -f $name, $timestamp, $ttl, "TXT", $txt

	}
	elseif ($rdatatype -eq 28)
	{
		# "AAAA" record

		### yeah, this doesn't do all the fancy formatting that can be done for IPv6

		$str = ""
		for ($i = 24; $i -lt 40; $i+=2)
		{
			$seg = wordBE $arr $i
			$str += ($seg).ToString('x4')
			if ($i -ne 38) { $str += ':' }
		}

		if ($csv)
		{
			$formatstring = "{0},{1},{2},{3},{4}"
		}
		else
		{
			$formatstring = "{0,-30}`t{1,-24}`t{2}`t{3}`t{4}"
		}

		$formatstring -f $name, $timestamp, $ttl, "AAAA", $str
	}
	elseif ($rdatatype -eq 33)
	{
		# "SRV" record

		$port   = wordBE $arr 28
		$weight = wordBE $arr 26
		$pri    = wordBE $arr 24

		$nsname = decodeName $arr 30

		if ($csv)
		{
			$formatstring = "{0},{1},{2},{3},{4},{5}"
		}
		else
		{
			$formatstring = "{0,-30}`t{1,-24}`t{2}`t{3} {4} {5}"
		}

		$formatstring -f `
			$name, $timestamp, `
			$ttl, "SRV", `
			("[" + $pri.ToString() + "][" + $weight.ToString() + "][" + $port.ToString() + "]"), `
			$nsname
	}
	else
	{
		$name
		"RDataType $rdatatype"
		$var.distinguishedname.ToString()
		dumpByteArray $arr
	}

}

function processAttribute([string]$attrName, [System.Object]$var)
{
	$array = $var.$attrName.Value
####	"{0} contains {1} rows of type {2} from {3}" -f $attrName, $array.Count, $array.GetType(), $var.distinguishedName.ToString()

	if ($array -is [System.Byte[]])
	{
####		dumpByteArray $array
		" "
		analyzeArray $array $var
		" "
	}
	else
	{
		for ($i = 0; $i -lt $array.Count; $i++)
		{
####			dumpByteArray $array[$i]
			" "
			analyzeArray $array[$i] $var
			" "
		}
	}
}

function usage
{
"
.\dns-dump -zone  [-dc ] [-domain] [-csv] |
	   -help

dns-dump will dump, from Active Directory, a particular named zone. 
The zone named must be Active Directory integrated.

Zone contents can vary depending on domain controller (in regards
to replication and the serial number of the SOA record). By using
the -dc parameter, you can specify the desired DC to use. Otherwise,
dns-dump uses the default DC.

The -domain option can be specified if the script is to be used
against a domain that the current host isn't a part of but has read
access to.

Usually, output is formatted for display on a workstation. If you
want CSV (comma-separated-value) output, specify the -csv parameter.
Use out-file in the pipeline to save the output to a file.

Finally, to produce this helpful output, you can specify the -help
parameter.

This command is basically equivalent to (but better than) the:

	dnscmd /zoneprint 
or
	dnscmd /enumrecords  '@'

commands.

Example 1:

	.\dns-dump -zone essential.local -dc win2008-dc-3

Example 2:

	.\dns-dump -help

Example 3:

	.\dns-dump -zone essential.local -csv |
            out-file essential.txt -encoding ascii

	Note: the '-encoding ascii' is important if you want to
	work with the file within the old cmd.exe shell. Otherwise,
	you can usually leave that off.
"
}

	##
	## Main
	##

	if ($help)
	{
		usage
		return
	}

	if ($args.Length -gt 0)
	{
		write-error "Invalid parameter specified"
		usage
		return
	}

	if (!$zone)
	{
		throw "must specify zone name"
		return
	}
	
	if ($domain)
	{
		$defaultNC = "DC=" + $domain.replace(".",",DC=")
	}
	else
	{
		$root = [ADSI]"LDAP://RootDSE"
		$defaultNC = $root.defaultNamingContext	
	}

	$dn = "LDAP://"
	if ($dc) { $dn += $dc + "/" }
#	$dn += "DC=" + $zone + ",CN=MicrosoftDNS,CN=System," + $defaultNC
  $dn += "DC=" + $zone + ",CN=MicrosoftDNS,DC=DomainDnsZones," + $defaultNC
	$obj = [ADSI]$dn
	if ($obj.name)
	{
		if ($csv)
		{
			"Name,Timestamp,TTL,RecordType,Param1,Param2"
		}

		#### dNSProperty has a different format than dNSRecord
		#### processAttribute "dNSProperty" $obj

		foreach ($record in $obj.psbase.Children)
		{
			####	if ($record.dNSProperty) { processAttribute "dNSProperty" $record }
			if ($record.dnsRecord)   { processAttribute "dNSRecord"   $record }
		}
	}
	else
	{
		write-error "Can't open $dn"
	}

	$obj = $null
