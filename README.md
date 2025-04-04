![AslanRoarGIF](https://github.com/user-attachments/assets/a5758fee-4645-48a2-88dd-09229ec24e4d)# EDRBypassZoo 

**A research-driven suite showcasing various proof-of-concept (PoC) techniques to bypass userland hooking mechanisms, including IAT, Kernel32, and NT-level inline hooks, along with both direct and indirect syscall evasions.**

---

## 🚀 Overview
EDRBypassZoo is a collection of proof-of-concept (PoC) implementations designed to evade various hooking mechanisms commonly employed by security products. It provides low-level techniques to restore original execution flow and bypass monitoring at different levels of the Windows operating system.

### 🔍 Features  
✅ **IAT Hooking Bypass** – Restores original API calls by evading Import Address Table (IAT) hooks.  
✅ **Kernel32 Hooking Bypass** – Bypasses userland hooks placed on Kernel32 functions to ensure unmonitored execution.  
✅ **NT-Level Inline Hooking Bypass** – Identifies and neutralizes inline hooks at the NT function level to restore original code execution.  
✅ **Direct Syscall Bypass** – Executes syscalls without relying on standard API calls, effectively circumventing direct syscall monitoring mechanisms.  
✅ **Indirect Syscall Bypass** – Leverages Vectored Exception Handling (VEH) to dynamically retrieve System Service Numbers (SSNs) and construct a legitimate execution stack, bypassing existing syscall detection strategies.  

---

## ⚙️ Technical Details
HBS employs advanced techniques to ensure stealthy and reliable unhooking:
- **Restoring IAT Entries** – Dynamically resolves API calls to their original addresses.
- **Syscall Stubs & Direct Execution** – Bypasses userland monitoring by invoking syscalls directly.
- **Hook Detection & Removal** – Identifies and eliminates inline patches in NT functions.
- **Memory Manipulation Techniques** – Restores original function prologues to counter inline hooks.

---

