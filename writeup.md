# HTB Season 10 — Logging (Windows / Medium) — Complete Writeup

**Starting foothold:** credentials for `wallace.everette / Welcome2026@` (simulating a realistic pentest starting point).
**personal point of view this box is medieum to hard**

---

## 1. Reconnaissance

### Nmap scan
![[Pasted image 20260727173858.png]]
Key observations:

- Full Active Directory Domain Controller (Kerberos, LDAP, LDAPS, Global Catalog, kpasswd)
- Ports **8530/8531** = WSUS (HTTP/HTTPS) — this becomes central to the final privilege escalation
- WinRM open (5985) — will be the main shell access vector throughout
### Building the hosts file
![[Pasted image 20260727173503.png]]
### Anonymous access check
![[Pasted image 20260727173646.png]]
No anonymous foothold — moving on with the provided credentials.

---

## 2. Initial Credential Validation & Roasting Attempts

### Kerberoasting / AS-REP Roasting (unsuccessful)
![[Pasted image 20260727174617.png]]
No AS-REP roastable or Kerberoastable accounts — the environment is reasonably hardened against these classic attacks.

---
## Users and shares enumeration

![[Pasted image 20260727175017.png]]
Full user list obtained — useful for later targeted attacks (Kerberoasting/spraying attempts, BloodHound cross-referencing).
Two shares stand out: `Logs` (readable) and `WSUSTemp` (no access with current creds — foreshadowing the WSUS attack later).
### Downloading and analysing the Logs share

![[Pasted image 20260727175512.png]]
Inside `IdentitySync_Trace_20260219.log`, a leaked domain credential is found:

```
svc_recovery : Em3rg3ncyPa$$2025
```
![[Pasted image 20260727175639.png]]
**Lesson:** application/sync logs often leak plaintext credentials during debugging or error logging — a classic real-world misconfiguration replicated here.

---

##  Logon Restriction → Kerberos-Only Bypass

Testing the leaked credential over SMB fails:
![[Pasted image 20260727181919.png]]
`STATUS_ACCOUNT_RESTRICTION` indicates the account is **restricted to Kerberos-only authentication** (NTLM logon is blocked, e.g. via `msDS-SupportedEncryptionTypes`/logon restrictions or `Protected Users` group behavior). Switching to Kerberos pre-auth:

The password fails pre-auth. Reasoning: the log was dated `20260219` and the password ends in `2025` — likely an annually-rotated password. Trying the `2026` variant, with clock sync to avoid Kerberos time-skew rejection:

![[Pasted image 20260727183107.png]]

saving and exporting the ticket
![[Pasted image 20260727183143.png]]

**Foothold #1 achieved: valid TGT for `svc_recovery`.**

---

##  BloodHound Enumeration

![[Pasted image 20260727184113.png]]
Key finding: `svc_recovery` has **GenericWrite** over `MSA_HEALTH$`. `MSA_HEALTH$` is a member of **Remote Management Users** (WinRM access) and **Domain Computers**.
This opens a **Shadow Credentials** attack path.
![[Pasted image 20260727205043.png]]

---
![[Pasted image 20260727205224.png]]
## 6. Shadow Credentials Attack (GenericWrite Abuse)

### Concept

Shadow Credentials abuses the `msDS-KeyCredentialLink` attribute to inject an attacker-controlled public key into a target object. This enables authentication via **PKINIT**, requesting a TGT _as the target object_ — without ever touching or knowing the object's actual password.

![[Pasted image 20260727210648.png]]

**Foothold #2 achieved: shell as `MSA_HEALTH$`.**

---

## Local Enumeration → Scheduled Task & DLL Hijacking

### WinPEAS finding: a privileged scheduled task

WinPEAS reveals a scheduled task running as `logging\Administrator`:

```
UpdateChecker Agent: "C:\Program Files\UpdateMonitor\UpdateMonitor.exe" /scan=3 /autofix=true
Trigger: repeats every 00:03:00 indefinitely
```
![[Pasted image 20260727213315.png]]
### Checking folder ACLs

![[Pasted image 20260727213457.png]]

The `IT` group has **Full Control** over this directory (explicitly granted, not inherited). Checking membership:
![[Pasted image 20260727213613.png]]
```
The only member of the IT group is JAYLEE.CLIFTON
```

### Confirming DLL Hijacking
![[Pasted image 20260727220016.png]]
![[Pasted image 20260727215629.png]]

`BUILTIN\Users` (which `MSA_HEALTH$` is a member of) has write access to this directory — a classic **DLL Hijacking** vulnerability: the privileged process searches for a DLL it can't find, and any authenticated user can plant it.

### Building and delivering the malicious DLL

The program reads from `C:\ProgramData\UpdateMonitor\Settings_Update.zip` and loads the DLL contained inside.
![[Pasted image 20260727220254.png]]
![[Pasted image 20260727220232.png]]
The scheduled task fires (max 3-minute wait), loads the malicious DLL, and a reverse shell is caught:
![[Pasted image 20260727232631.png]]
![[Pasted image 20260727222622.png]]
**Foothold #3 achieved: shell as `jaylee.clifton`.**
![[Pasted image 20260727232834.png]]

---

## 8. Root — flag

### reexploiting the same plan with different dll

```
cat > domain_admin.c << 'EOF'  
#include <windows.h>  
#include <stdlib.h>  
  
BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID reserved) {  
    if (reason == DLL_PROCESS_ATTACH) {  
        system("powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command \""  
               "Add-ADGroupMember -Identity 'Domain Admins' -Members 'MSA_HEALTH$'"  
               "\"");  
    }  
    return TRUE;  
}  
EOF  
  
x86_64-w64-mingw32-gcc -shared -o settings_update.dll domain_admin.c -s  
zip Settings_Update.zip settings_update.dll
```
**Root flag captured.**
![[Pasted image 20260728021313.png]]
![[Pasted image 20260728021246.png]]
