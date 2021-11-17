// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

#include <easyhook.h>
#include <string>
#include <iostream>
#include <Windows.h>
#include <list>
#include <functional>
#include <Wincrypt.h>
#include <winsock2.h>
#include <psapi.h>
#include <shlwapi.h>
#include <format>
#include <fstream>

using namespace std;

// EasyHook will be looking for this export to support DLL injection. If not found then 
// DLL injection will fail.
extern "C" void __declspec(dllexport) __stdcall NativeInjectionEntryPoint(REMOTE_ENTRY_INFO * inRemoteInfo);
void InitializeTracing();

// Global tracing stream
ofstream tracingStream;

// Path to the wendokernel trace directory
CHAR wendokernel_trace_path[256];


// Hook Defs
void WINAPI myDiskFreespaceHook(LPCSTR lpRootPathName, LPDWORD lpSectors, LPDWORD lpBytesPerSector, LPDWORD freeCluster, LPDWORD lpTotalClusters);
std::function<void(LPCSTR, LPDWORD, LPDWORD, LPDWORD, LPDWORD)> Disk_hook =
[](LPCSTR lpRootPathName, LPDWORD lpSectors, LPDWORD lpBytesPerSector, LPDWORD freeCluster, LPDWORD lpTotalClusters)->void {
	std::cout << "\n Hooked the disk freespace function!\n";
};
void WINAPI myDiskFreespaceHook(LPCSTR lpRootPathName, LPDWORD lpSectors, LPDWORD lpBytesPerSector, LPDWORD freeCluster, LPDWORD lpTotalClusters)
{
	Disk_hook(lpRootPathName, lpSectors, lpBytesPerSector, freeCluster, lpTotalClusters);
}

std::function<void(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)>
create_file = []
(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
->void {
	std::cout << "\n Create_File Lambda: Hooked the createfile function for function\n";
	// cout << "Current thread id is: " << GetCurrentThreadId() << endl;
	// tracingStream << "CreateFileW, " << "lpFileName: " << lpFileName <<
	//	", dwDesiredAccess: " << dwDesiredAccess <<
	//	", lpSecurityAttributes: " << lpSecurityAttributes << endl;
	tracingStream << "CreateFileW" << endl;
};

void
WINAPI
myCreateFileW(
	_In_ LPCWSTR lpFileName,
	_In_ DWORD dwDesiredAccess,
	_In_ DWORD dwShareMode,
	_In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	_In_ DWORD dwCreationDisposition,
	_In_ DWORD dwFlagsAndAttributes,
	_In_opt_ HANDLE hTemplateFile
) {
	create_file(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

// Create File Mapping Hook

std::function<void(HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCWSTR lpName)>
create_file_mapping_w = [](HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCWSTR lpName) -> void {
	tracingStream << "CreateFileMappingW" << endl;
};

void
WINAPI
myCreateFileMapping(
	_In_ HANDLE hFile,
	_In_opt_ LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
	_In_ DWORD flProtect,
	_In_ DWORD dwMaximumSizeHigh,
	_In_ DWORD dwMaximumSizeLow,
	_In_opt_ LPCWSTR lpName

) {
	create_file_mapping_w(hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName);
}

std::function<void(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)>
create_process_w = [](LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation) {
	tracingStream << "CreateProcessW" << endl;
};

void
WINAPI
myCreateProcessW(_In_opt_ LPCWSTR lpApplicationName, _Inout_opt_ LPWSTR lpCommandLine, _In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes, _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes, _In_ BOOL bInheritHandles, _In_ DWORD dwCreationFlags, _In_opt_ LPVOID lpEnvironment, _In_opt_ LPCWSTR lpCurrentDirectory, _In_ LPSTARTUPINFOW lpStartupInfo, _Out_ LPPROCESS_INFORMATION lpProcessInformation) {
	create_process_w(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
}

std::function<void(PCWSTR NewDirectory)>
add_dll_directory = [](PCWSTR NewDirectory) {
	tracingStream << "AddDllDirectory" << endl;
};

void
WINAPI
hookAddDllDirectory(_In_ PCWSTR NewDirectory) {
	add_dll_directory(NewDirectory);
}


std::function<void(HMODULE hLibModule)>
disable_thread_library_calls = [](HMODULE hLibModule) {
	tracingStream << "DisableThreadLibraryCalls" << endl;
};

void
WINAPI
hookDisableThreadLibraryCalls(_In_ HMODULE hLibModule) {
	disable_thread_library_calls(hLibModule);
}


std::function<void(HMODULE hLibModule)>
free_library = [](HMODULE hLibModule) {
	tracingStream << "FreeLibrary" << endl;
};

void
WINAPI
hookFreeLibrary(_In_ HMODULE hLibModule) {
	free_library(hLibModule);
}



// ======================================================  Hooking Helper Classes ============================================== //
class ProcPtr
{
public:
	explicit ProcPtr(FARPROC ptr) : m_ptr(ptr) {}

	template <typename T>
	operator T* () const { return reinterpret_cast<T*>(m_ptr); }

private:
	FARPROC m_ptr;
};

//Helper to get API adress
class DllHelper
{
public:
	~DllHelper() { FreeLibrary(m_module); }

	ProcPtr operator[](LPCSTR proc_name) const
	{
		return ProcPtr(::GetProcAddress(m_module, proc_name));
	}

private:
	HMODULE m_module = GetModuleHandle(TEXT("kernel32"));
};

// Class to compose hooks with their original calls
template<typename U, typename... T>
class FuncComp {
public:
	FuncComp(std::function<U(T...)> composedF) {
		composedFunction = composedF;
	}

	std::function<U(T...)> composedFunction;
};

template<typename U, typename...T>
FuncComp<U, T...> createGenFunc(U(*origFunc)(T... args), std::function<void(T...)> hookFunc) {
	return FuncComp<U, T...>([=](T...xs) {
		hookFunc(xs...);
		return origFunc(xs...);
		});
}


class HookInstaller
{
public:

	HookInstaller(void* origFunc, void* hookedFunction) {
		hHook = { NULL }; // keep track of our hook

		// Install the hook
		NTSTATUS result
			= LhInstallHook(
				origFunc,
				hookedFunction,
				NULL,
				&hHook);

		if (FAILED(result))
		{
			wstring s(RtlGetLastErrorString());
			wcout << "HookInstaller: Failed to install hook: ";
			wcout << s << endl;
		}
		else {
			wcout << "HookInstaller: Installed the hook successfully" << endl;
		}
	}

	void enableHookForCurrentProcess() {
		wcout << "HookInstaller.enableHookForCurrentProcess: Installed the hook successfully" << endl;
		wcout << "HookInstaller.enableHookForCurrentProcess: Current thread is: " << GetCurrentThreadId() << endl;
		ULONG ACLEntries[1] = { 0 };
		LhSetExclusiveACL(ACLEntries, 1, &hHook);

	}

	void uninstallHook() {
		LhUninstallHook(&hHook);
	}
private:
	HOOK_TRACE_INFO hHook;
};

/**
 * @param origFunc original API function
 * @param coreHookLamda core logic to be insert before original API call
 * @param composedFunctionAdd address of function that uses delegates to coreHookLambda
 * @return HookInstaller
 */
template<typename U, typename...T>
HookInstaller
CreateHookingEnvironment(U(*origFunc)(T... args), void(*composedFunctionAdd)(T... args), std::function<void(T...)>* coreHookLamda) {
	cout << "CreateHookingEnvironment: entered." << endl;
	FuncComp<U, T...> composedHook = createGenFunc(origFunc, *coreHookLamda);
	*coreHookLamda = composedHook.composedFunction; // compose hook to contain original function call
	HookInstaller hInstall = HookInstaller(origFunc, composedFunctionAdd);// install hook
	return hInstall;
}

// Helper Class to group and easy access API calls
class WindowsAPIHelper
{
public:
	WindowsAPIHelper() : m_dll()
	{
		_Beep = m_dll["Beep"];
		_DiskFreeSpace = m_dll["GetDiskFreeSpaceA"];
		_CreateFile = m_dll["CreateFileW"];
		_CreateFileMapping = m_dll["CreateFileMapping"];
		_CreateProcess = m_dll["CreateProcess"];
		_CreateRemoteThread = m_dll["CreateRemoteThread"];
		_CryptAcquireContext = m_dll["CryptAcquireContext"];
		_gethostbyname = m_dll["gethostbyname"];
		_GetModuleFilename = m_dll["GetModuleFilename"];
		_GetProcAddress = m_dll["GetProcAddress"];
		_GetThreadContext = m_dll["GetThreadContext"];
		_GetTickCount = m_dll["GetTickCount"];
		_GetWindowsDirectory = m_dll["GetWindowsDirectory"];

		_AddDllDirectory = m_dll["AddDllDirectory"];
		_DisableThreadLibraryCalls = m_dll["DisableThreadLibraryCalls"];
		_FreeLibrary = m_dll["FreeLibrary"];
	}

	decltype(Beep)* _Beep;
	decltype(GetDiskFreeSpaceA)* _DiskFreeSpace;

	// Functions to consider hooking
	decltype(CreateFile)* _CreateFile;
	decltype(CreateFileMapping)* _CreateFileMapping;
	decltype(CreateProcess)* _CreateProcess;
	decltype(CreateRemoteThread)* _CreateRemoteThread;
	decltype(CryptAcquireContext)* _CryptAcquireContext;
	decltype(gethostbyname)* _gethostbyname;
	decltype(GetModuleFileName)* _GetModuleFilename;
	decltype(GetProcAddress)* _GetProcAddress;
	decltype(GetThreadContext)* _GetThreadContext;
	decltype(GetTickCount)* _GetTickCount;
	decltype(GetWindowsDirectory)* _GetWindowsDirectory;

	decltype(AddDllDirectory)* _AddDllDirectory;
	decltype(DisableThreadLibraryCalls)* _DisableThreadLibraryCalls;
	decltype(FreeLibrary)* _FreeLibrary;


private:
	DllHelper m_dll;
};


list<HookInstaller> CreateHooks() {
	list<HookInstaller> hookList;
	WindowsAPIHelper windowsHelper;

	//add specific hooks
	hookList.push_back(CreateHookingEnvironment(windowsHelper._CreateFile, myCreateFileW, &create_file));
	hookList.push_back(CreateHookingEnvironment(windowsHelper._CreateFileMapping, myCreateFileMapping, &create_file_mapping_w));
	hookList.push_back(CreateHookingEnvironment(windowsHelper._CreateProcess, myCreateProcessW, &create_process_w));

	hookList.push_back(CreateHookingEnvironment(windowsHelper._AddDllDirectory, AddDllDirectory, add_dll_directory));
	hookList.push_back(CreateHookingEnvironment(windowsHelper._DisableThreadLibraryCalls, DisableThreadLibraryCalls, disable_thread_library_calls));
	hookList.push_back(CreateHookingEnvironment(windowsHelper._FreeLibrary, FreeLibrary, free_library));
	return hookList;
}

// ======================================================  Hooking Helper Classes ============================================== //

void HookProcess() {
	cout << "hooking into current process:  " << GetCurrentProcessId() << "\n";
	list<HookInstaller> hookEnv = CreateHooks();
	for (HookInstaller hook : hookEnv) {
		// hook.enableHookForProccess(processToHook);
		hook.enableHookForCurrentProcess();
	}

	// cout << "Press enter to unhook and exit\n";
	// cin.ignore();
	// cin.get();
	// for (HookInstaller hook : hookEnv) {
	//    hook.uninstallHook();
	// }
	// cout << "\n\nRestore ALL entry points of pending removals issued by LhUninstallHook()\n";
	// LhWaitForPendingRemovals();
}

/* Checks for the presence of an established tracing directory on the host. If none exists, create it.
	Returns 0 on success, 1 on failure.
*/
int EstablishTracingDirectory() {
	// Construct the proper directory path to place traces in: C:\Users\{username}\Wendokernel_Traces
	// %UserProfile%
	CHAR user_profile_path[128];
	size_t getEnvReturnValue;
	getenv_s(&getEnvReturnValue, user_profile_path, 128, "UserProfile");

	if (getEnvReturnValue == 0) {
		// Environment Variable Not Found.
		return 1;
	}

	sprintf_s(wendokernel_trace_path, "%s\\Wendokernel_Traces", user_profile_path);
	cout << "Full wendokernel trace directory: " << wendokernel_trace_path << endl;

	// Check if it exists. If not, create it.
	DWORD fileAttr = GetFileAttributesA(wendokernel_trace_path);
	if (fileAttr == INVALID_FILE_ATTRIBUTES) {

		DWORD errorCause = GetLastError();
		if (errorCause == ERROR_PATH_NOT_FOUND || errorCause == ERROR_FILE_NOT_FOUND || errorCause == ERROR_INVALID_NAME || errorCause == ERROR_BAD_NETPATH) {
			// Directory needs to be created.
			if (CreateDirectoryA(wendokernel_trace_path, NULL) == 0) {
				// Directory creation failed.
				cerr << "Directory creation failed." << endl;
				return 1;
			}
			else {
				cout << "Directory creation success." << endl;
				return 0;
			}
		}
		else {
			// Some other error occured
			cerr << "Invalid file attributes. Path is malformed." << endl;
			return 1;
		}
	}

	if (fileAttr & FILE_ATTRIBUTE_DIRECTORY) {
		// Directory already exists
		cout << "Tracing directory already exists." << endl;
		return 0;
	}
	else {
		// File exists, but it isn't a directory.
		cerr << "File found at path, but it isn't a directory." << endl;
		return 1;
	}

}

/* Sets up tracing to FS for the process.*/
void InitializeTracing() {
	CHAR fullProcessFileName[128];
	CHAR *processFileName;

	GetModuleFileNameA(NULL, fullProcessFileName, 128);
	processFileName = PathFindFileNameA(fullProcessFileName);

	SYSTEMTIME currentTime;
	GetSystemTime(&currentTime);

	CHAR fullTraceName[512];
	sprintf_s(fullTraceName, "%s\\%s_%d_%d_%d_%d%d.hook", wendokernel_trace_path, processFileName, currentTime.wMonth, currentTime.wDay, currentTime.wYear, currentTime.wHour, currentTime.wMinute);

	cout << "Full file trace path: " << fullTraceName << endl;
	tracingStream.open(fullTraceName);
}


void __stdcall NativeInjectionEntryPoint(REMOTE_ENTRY_INFO* inRemoteInfo)
{
	std::cout << "\n\nNativeInjectionEntryPointt(REMOTE_ENTRY_INFO* inRemoteInfo)\n\n" <<
		"IIIII           jjj               tt                dd !!! \n"
		" III  nn nnn          eee    cccc tt      eee       dd !!! \n"
		" III  nnn  nn   jjj ee   e cc     tttt  ee   e  dddddd !!! \n"
		" III  nn   nn   jjj eeeee  cc     tt    eeeee  dd   dd     \n"
		"IIIII nn   nn   jjj  eeeee  ccccc  tttt  eeeee  dddddd !!! \n"
		"              jjjj                                         \n\n";

	std::cout << "Injected by process Id: " << inRemoteInfo->HostPID << "\n";
	if (EstablishTracingDirectory()) {
		std::cout << "Failed to establish location of tracing directory.";
	}
	InitializeTracing();
	HookProcess();
	return;
}