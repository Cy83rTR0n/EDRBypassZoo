#pragma once
#include<Windows.h>
#include<stdio.h>
// Functions required are as follows
// 1. VirtualAllocEx
// 2. VirtualProtectEx
// 3. WriteProcessMemory

typedef LPVOID(WINAPI* fnVirtualAllocEx)(
	HANDLE hProcess,
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect
	);

typedef BOOL(WINAPI* fnVirtualProtectEx)(
	HANDLE hProcess,
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flNewProtect,
	PDWORD lpflOldProtect
	);

typedef BOOL(WINAPI* fnWriteProcessMemory)(
	HANDLE  hProcess,
	LPVOID  lpBaseAddress,
	LPCVOID lpBuffer,
	SIZE_T  nSize,
	SIZE_T* lpNumberOfBytesWritten
	);

