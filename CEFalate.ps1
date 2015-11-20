Param(
    [Parameter(Mandatory=$True,Position=1)]
    [string]$SysLogServer,
    
    [Parameter(Mandatory=$True,Position=2)]
    [string]$DevVend,

    [Parameter(Mandatory=$True,Position=3)]
    [string]$DevProd,
    
    [Parameter(Mandatory=$True,Position=4)]
    [int]$DevVers,
    
    [Parameter(Mandatory=$True,Position=5)]
    [int]$sigID,
    
    [Parameter(Mandatory=$True,Position=6)]
    [string]$Name,
    
    [Parameter(Mandatory=$True,Position=7)]
    [string]$Sev,

    [Parameter(Mandatory=$True,Position=7)]
    [string]$msg
)

Function SyslogSender ()
{
	<#
		.SYNOPSIS
			UDP client creation to send message to a syslog server
		.DESCRIPTION
			Basic usage:
				$Obj = ./SyslogSender 192.168.2.4
				$Obj.Send("string message1")
				$Obj.Send("string message2")
	 
				This uses the following defaults:
					- Facility : user
					- Severity : info
					- Timestamp : now
					- Computername : name of the computer on which the script is executed.
					- Syslog Port: 514
	 
			Advanced usage:
				$Obj = ./SyslogSender 192.168.231.3 432
					This defines a custom port when setting up the object
	 
				$Obj.Send("String Message", "String Facility", "String Severity", "String Timestamp", "String Hostname")
					This sends a message with a custom facility, severity, timestamp and hostname.
					i.e. $obj.Send("Script Error", "local7", "alert", $(Get-Date), $env:COMPUTERNAME)
	#>

	# Create the object.
	# Requires a destination host. A destination port is optional.
    Param
    (
        [String]$Destination = $(throw "Error SyslogSender: A destination host must be given."),
        [Int32]$Port = 514
    )
    $ObjSyslogSender = New-Object PsObject
    $ObjSyslogSender.PsObject.TypeNames.Insert(0, "SyslogSender")
 
    # Initialize the udp 'connection'
    $ObjSyslogSender | Add-Member -MemberType NoteProperty -Name UDPClient -Value $(New-Object System.Net.Sockets.UdpClient)
    $ObjSyslogSender.UDPClient.Connect($Destination, $Port)
 
    
    # Add the Send method:
    $ObjSyslogSender | Add-Member -MemberType ScriptMethod -Name Send -Value {
        Param
        (
			[String]$Data = $(throw "Error SyslogSender: test_Can_you_see_me?!"),
			[String]$Facility = "user",
			[String]$Severity = "info",
			[String]$Timestamp = $(Get-Date),
			[String]$Hostname = $env:COMPUTERNAME
        )
 
        # Maps used to translate string to corresponding decimal value
        $FacilityMap = @{  
			"kern" = 0;"user" = 1;"mail" = 2;"daemon" = 3;"security" = 4;"auth" = 4;"syslog" = 5;
			"lpr" = 6;"news" = 7;"uucp" = 8;"cron" = 9;"authpriv" = 10;"ftp" = 11;"ntp" = 12;
			"logaudit" = 13;"logalert" = 14;"clock" = 15;"local0" = 16;"local1" = 17;"local2" = 18;
			"local3" = 19;"local4" = 20;"local5" = 21;"local6" = 21;"local7" = 23;
		}
 
        $SeverityMap = @{  
			"emerg" = 0;"panic" = 0;"alert" = 1;"crit" = 2;"error" = 3;"err" = 3;"warning" = 4;
			"warn" = 4;"notice" = 5;"info" = 6;"debug" = 7;
		}
 
        # Map facility, default to user
		$FacilityDec = 1
        if ($FacilityMap.ContainsKey($Facility))
        {
            $FacilityDec = $FacilityMap[$Facility]
        }

        # Map severity, default to info
		$SeverityDec = 6
        if ($SeverityMap.ContainsKey($Severity))
        {
            $SeverityDec = $SeverityMap[$Severity]
        }        
 
        # Calculate PRI code
        $PRI = ($FacilityDec * 8) + $SeverityDec
 
        # Format the data, recommended is a maximum length of 1kb
        $Message = $([System.Text.Encoding]::ASCII).GetBytes("<$PRI> $Timestamp $Hostname $Data")
        if ($Message.Length -gt 1024)
        {
            $Message = $Message.Substring(0, 1024)
        }
 
        # Send the message
        $this.UDPClient.Send($Message, $Message.Length) | Out-Null
    }
	
    $ObjSyslogSender
}


$Obj = syslogsender -destination $SysLogServer

$Obj.Send("CEF:0|$DevVend|$DevProd|$DevVers|$SigID|$Name|$Sev|msg=$msg, $(get-date)")
