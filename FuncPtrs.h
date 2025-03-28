#pragma once
#include<Windows.h>

typedef NTSTATUS(NTAPI* fnNtQueryDirectoryFile) (
	ULONG_PTR uParam1,
	ULONG_PTR uParam2,
	ULONG_PTR uParam3,
	ULONG_PTR uParam4,
	ULONG_PTR uParam5,
	ULONG_PTR uParam6,
	ULONG_PTR uParam7,
	ULONG_PTR uParam8,
	ULONG_PTR uParam9,
	ULONG_PTR uParamA,
	ULONG_PTR uParamB
	);

