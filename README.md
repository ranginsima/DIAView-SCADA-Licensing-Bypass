# Technical Report: Critical Licensing Mechanism Bypass in Delta DIAView SCADA

**Prepared for:** TWCERT/CC & Delta Electronics PSIRT

---

## 1. Executive Summary

This report details a critical vulnerability in the licensing and protection mechanism of Delta's DIAView SCADA software.
The vulnerability stems from an improperly implemented client-side security check that can be easily bypassed by a local attacker with standard reverse engineering tools.

**Impact:** Unlimited, unauthorized use of the software → direct and significant revenue loss risk.
The report includes reproduction steps and recommendations for mitigation and long-term hardening.

---

## 2. Vulnerability Details

* **Product:** Delta DIAView SCADA
* **Affected Versions:** All current and previous versions
* **Vulnerability Type:** CWE-1299: Missing Protection against Software Reverse Engineering
* **Impact:** Complete bypass of software licensing mechanism
* **Attack Vector:** Local
* **CVSS 3.1 Score:** 3.3
* **CVSS Vector String:** `AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N`

---

## 3. Technical Description

* Main protection in **SCADA.SafeLock.dll**.
* DLL protected with **ConfuserEx** (open-source obfuscator).
* ConfuserEx is weak → many public deobfuscation tools exist.
* **Architectural weakness:** License validation is fully client-side.
* No anti-tampering or anti-debugging.
* Other components rely entirely on this DLL.

---

## 4. Proof of Concept & Steps to Reproduce

### 4.1. Prerequisites

* Working installation of DIAView SCADA
* **ConfuserEx Unpacker v2.0** (ElektroKill)
* .NET decompiler/editor (**dnSpy**)

### 4.2. Step 1: Deobfuscating DLL

1. Locate `SCADA.SafeLock.dll`.
2. Process with **ConfuserEx Unpacker v2.0**.
3. Tool performs multiple cleaning passes:

   * Anti De4dot Remover
   * Mutation Cleaner
   * Control Flow Unpacking
   * Constant Decrypter
   * Instruction Emulator
   * Integrity Check Cleaner
4. Save result as `SCADA.SafeLock.unpacked.dll`.

### 4.3. Step 2: Code Analysis and Patching

1. Open in **dnSpy**.
2. Locate `CheckSafeLock` function.
3. Modify to always succeed:

```csharp
public VerifyResult CheckSafeLock(int ioCount = -1, int variableCount = -1, int userCount = -1)
{
    // Original complex logic is bypassed
    return VerifyResult.VerifySuccess;
}
```

4. Compile & save modified DLL.

### 4.4. Step 3: Verification

* Replace original `SCADA.SafeLock.dll` with patched version.
* Run DIAView → starts fully licensed.

### 4.5. Additional Weaknesses

* **Hardcoded Limits:** `IoCount`, `ClientCount`, `dongleInfo.Features` easily modifiable.
* **Main Executable:** `DIAViewServer.exe` unprotected.

  * Single conditional jump patch bypasses licensing logic.

---

## 5. Impact Analysis

* **Direct Financial Loss:** Bypass = no payment → revenue loss.
* **Intellectual Property Violation:** Core protection nullified.
* **Reputational Damage:** Ease of bypass harms trust in DIAView.
