# HookBypassSuite (HBS)

**A research-driven suite showcasing various proof-of-concept (PoC) techniques to bypass userland hooking mechanisms, including IAT, Kernel32, and NT-level inline hooks, along with both direct and indirect syscall evasions.**

---

## 🚀 Overview
HookBypassSuite (HBS) is a collection of proof-of-concept (PoC) implementations designed to evade various hooking mechanisms commonly employed by security products. It provides low-level techniques to restore original execution flow and bypass monitoring at different levels of the Windows operating system.

### 🔍 Features
✅ **IAT Hooking Bypass** – Evades Import Address Table (IAT) hooks to restore original API calls.  
✅ **Kernel32 Hooking Bypass** – Eliminates userland hooks placed on Kernel32 functions.  
✅ **NT-Level Inline Hooking Bypass** – Neutralizes inline hooks at the NT function level.  
✅ **Direct Syscall Bypass** – Executes syscalls indirectly to direct syscall detection strategies. 

✅ **Indirect Syscall Bypass** – Uses Vectored Exception Handling with the approach of dynamic retrieval of SSNs with creation of legitimate stack to bypass already present strategies for detection present.  

---

## ⚙️ Technical Details
HBS employs advanced techniques to ensure stealthy and reliable unhooking:
- **Restoring IAT Entries** – Dynamically resolves API calls to their original addresses.
- **Syscall Stubs & Direct Execution** – Bypasses userland monitoring by invoking syscalls directly.
- **Hook Detection & Removal** – Identifies and eliminates inline patches in NT functions.
---

