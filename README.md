# CEFalate
Powershell Script to send data to ArcSight via syslog over UDP 514. 

Required params.
1. Specify syslog server with -SyslogServer <<Server>>
2. Also need to specify Device Vendor with -DevVend
3. Aaaand -DevProd for Device Product
4. need some sid ID with -SigID
5. Drop the name in -Name
6. Severity is -Sev
7. Message is in -msg

Will add more stuff's later, but these are the required for CEF to function. 
