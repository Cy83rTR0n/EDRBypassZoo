#include<Windows.h>
#include<stdio.h>
#include<Tlhelp32.h>

#include "Structs.h"
#include "Macros.h"

extern PVOID NTAPI Spoof(PVOID a, ...);

PVOID FindGadget(LPBYTE Module, ULONG Size) {
	for (int x = 0; x < (INT)Size; x++) {
		if (memcmp(Module + x, "\xff\x23", 2) == 0)
		{
			printf("JOP GADGET FOUND !!!\n");
			return (PVOID)(Module + x);
		}
	}

	return NULL;
}


ULONG CalculateFunctionStackSize(PRUNTIME_FUNCTION pRunTimeFunction, const DWORD64 ImageBase, StackFrame &stackFrame)
{
	NTSTATUS status = STATUS_SUCCESS;
	PUNWIND_INFO pUnwindInfo = NULL;
	ULONG unwindOperation = 0;
	ULONG operationInfo = 0;
	ULONG index = 0;
	ULONG frameOffset = 0;
	stackFrame = { 0 };


	if (!pRunTimeFunction)
	{
		status = STATUS_INVALID_PARAMETER;
		goto Cleanup;
	}

	pUnwindInfo = (PUNWIND_INFO)(pRunTimeFunction->UnwindData + ImageBase);
	while (index < pUnwindInfo->CountOfCodes) {

		unwindOperation = pUnwindInfo->UnwindCode[index].UnwindOp;
		operationInfo = pUnwindInfo->UnwindCode[index].OpInfo;

		switch (unwindOperation) {
		case UWOP_PUSH_NONVOL:
			stackFrame.totalStackSize += 8;

			if (RBP_OP_INFO == operationInfo) {
				stackFrame.pushRbp = true;
				stackFrame.countOfCodes = pUnwindInfo->CountOfCodes;
				stackFrame.pushRbpIndex = index + 1;
			}
			break;
		case UWOP_SAVE_NONVOL:
			index += 1;
			break;
		case UWOP_ALLOC_SMALL:
			stackFrame.totalStackSize += ((operationInfo * 8) + 8);
			break;
		case UWOP_ALLOC_LARGE:
			index += 1;
			frameOffset = pUnwindInfo->UnwindCode[index].FrameOffset; 
			if (operationInfo == 0)
			{
				frameOffset *= 8;
			}
			else {
				index += 1;
				frameOffset += (pUnwindInfo->UnwindCode[index].FrameOffset << 16);
			}
			stackFrame.totalStackSize += frameOffset;
		case UWOP_SET_FPREG:
			stackFrame.setsFramePointer = true;
			break;
		default:
			printf("[-] Error: Unsupported Unwind Op Code \n");
			status = STATUS_ASSERTION_FAILURE;
			break;
		}

		index += 1;
	}


	if ((pUnwindInfo->Flags & UNW_FLAG_CHAININFO))
	{
		index = pUnwindInfo->CountOfCodes;
		if ((index & 1) != 0)
		{
			index += 1;
		}
		pRunTimeFunction = (PRUNTIME_FUNCTION)(&pUnwindInfo->UnwindCode[index]);
		return CalculateFunctionStackSize(pRunTimeFunction, ImageBase, stackFrame);
	}

	stackFrame.totalStackSize += 8;

	return stackFrame.totalStackSize;

Cleanup:
	return status;
}

ULONG CalculateFunctionStackSizeWrapper(StackFrame& stackFrame)
{
	NTSTATUS status = STATUS_SUCCESS;
	PRUNTIME_FUNCTION pRuntimeFunction = NULL;
	DWORD64 ImageBase = 0;
	PUNWIND_HISTORY_TABLE pHistoryTable = NULL;

	// [0] Sanity check return address.
	if (!stackFrame.returnAddress)
	{
		status = STATUS_INVALID_PARAMETER;
		goto Cleanup;
	}

	// [1] Locate RUNTIME_FUNCTION for given function.
	pRuntimeFunction = RtlLookupFunctionEntry(
		(DWORD64)stackFrame.returnAddress,
		&ImageBase,
		pHistoryTable);
	if (NULL == pRuntimeFunction)
	{
		status = STATUS_ASSERTION_FAILURE;
		goto Cleanup;
	}

	// [2] Recursively calculate the total stack size for
	// the function we are "returning" to.
	status = CalculateFunctionStackSize(pRuntimeFunction, ImageBase, stackFrame);

Cleanup:
	return status;
}

int bruh(int a, int b, int c, int d, int* e, int* f, int* g) {
	*e = 7;
	*f = 8;
	*g = 9;

	return 0;
}

int main() {

	PVOID ReturnAddress = NULL;
	PRM p = { 0 };
	PRM ogp = { 0 };
	NTSTATUS status = STATUS_SUCCESS;

	PVOID pPrintf = GetProcAddress(LoadLibraryA("mscvrt.dll"), "printf");

	p.trampoline = FindGadget((LPBYTE)GetModuleHandleA("KERNEL32.DLL"), 0x200000);
	printf("[+] Gadget is located at 0x%llx \n", p.trampoline);


	ReturnAddress = (PBYTE)(GetProcAddress(LoadLibraryA("kernel32.dll"), "BaseThreadInitThunk")) + 0x14; // Would walk export table but am lazy
	p.BTIT_ss = (PVOID)CalculateFunctionStackSizeWrapper(ReturnAddress);
	p.BTIT_retaddr = ReturnAddress;

	ReturnAddress = (PBYTE)(GetProcAddress(LoadLibraryA("ntdll.dll"), "RtlUserThreadStart")) + 0x21;
	p.RUTS_ss = (PVOID)CalculateFunctionStackSizeWrapper(ReturnAddress);
	p.RUTS_retaddr = ReturnAddress;

	p.Gadget_ss = (PVOID)CalculateFunctionStackSizeWrapper(p.trampoline);

}


