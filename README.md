# EDRBypassZoo
![AslanRoarGIF](https://github.com/user-attachments/assets/a5758fee-4645-48a2-88dd-09229ec24e4d) 

**EDRBypassZoo** is a focused collection of proof-of-concept implementations aimed at bypassing userland EDR hooking mechanisms. This includes evasion of Import Address Table (IAT) hooks, Kernel32 API interceptions, NT-layer inline hooks, and syscall monitoring via both direct and indirect approaches.

---

## 🧩 Project Scope

This repository demonstrates low-level techniques to subvert runtime monitoring by security products and restore original execution flow at different OS layers. The project serves as a research base for exploring and validating modern bypass strategies used in red teaming and malware development.

---

## 📌 Implemented Techniques

- **IAT Hooking Evasion**  
  Resolves and restores original function pointers from the Import Address Table to bypass userland API redirection.

- **Kernel32 Hook Bypass**  
  Identifies and avoids hooks placed on high-level WinAPI functions (e.g., `OpenProcess`, `VirtualAllocEx`) by resolving lower-level equivalents or using direct memory access.

- **NTDLL Inline Hook Removal**  
  Scans and restores overwritten function prologues in NTDLL to neutralize inline hooks placed by EDRs.

- **Direct Syscalls (Halo’s Gate)**  
  Implements syscall stubs by resolving SSNs dynamically to execute native APIs without touching hooked functions.

- **Indirect Syscalls (Tartarus Gate, VEH)**  
  Bypasses syscall detection using Vectored Exception Handlers and hardware breakpoints to emulate execution flow and construct valid call stacks.

---

## ⚙️ Core Techniques and Internals

- **Dynamic API Resolution**  
  Custom `GetProcAddress`/`GetModuleHandle` logic using PEB traversal to avoid touching hooked APIs.

- **Fiber-Based Execution**  
  Uses Windows Fibers for stealthy execution flow and context switching during injection.

- **Hook Detection**  
  Compares Syscall stubs by performing byte comparison to find out inline hooks in Various APIs.

- **Syscall Spoofing**  
  Implements call stack spoofing to evade indirect syscall heuristics and detection patterns.

- **Hardware Breakpoints + VEH**  
  Coordinates hardware breakpoints with VEH handlers to emulate syscalls and preserve realistic call traces.

---

## 📚 References & Credits

The following resources were studied and adapted to develop various PoCs included in this repository:

- [Layered Syscall - @AmunRha](https://whiteknightlabs.com/2024/07/31/layeredsyscall-abusing-veh-to-bypass-edrs/)
- [Halo’s Gate – @_EthicalChaos_](https://www.ired.team/offensive-security/defense-evasion/hiding-your-shellcode-with-halosgate)  
- [Tartarus Gate – @am0nsec](https://github.com/am0nsec/HellsGate)   
- [PEB Traversal for API Resolution](https://www.ired.team/offensive-security/defense-evasion/windows-api-hash-resolving-and-manual-mapping)  
- [Maldev Academy](https://maldevacademy.com/)  

---


