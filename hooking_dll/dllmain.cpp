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

std::function<void(HMODULE hLibModule, DWORD dwExitCode)>
free_library_and_exit_thread = [](HMODULE hLibModule, DWORD dwExitCode) {
	tracingStream << "FreeLibraryAndExitThread" << endl;
};

void
WINAPI
hookFreeLibraryAndExitThread(_In_ HMODULE hLibModule, _In_ DWORD dwExitCode) {
	free_library_and_exit_thread(hLibModule, dwExitCode);
}


std::function<void(DWORD nBufferLength, LPWSTR lpBuffer)>
get_dll_directory_w = [](DWORD nBufferLength, LPWSTR lpBuffer) {
	tracingStream << "GetDllDirectoryW" << endl;
};

void
WINAPI
hookGetDllDirectoryW(_In_ DWORD nBufferLength, _Out_ LPWSTR lpBuffer) {
	get_dll_directory_w(nBufferLength, lpBuffer);
}

std::function<void(HMODULE hModule, LPWSTR lpFilename, DWORD nSize)>
get_module_file_name_w = [](HMODULE hModule, LPWSTR lpFilename, DWORD nSize) {
	tracingStream << "GetModuleFileNameW" << endl;
};

void
WINAPI
hookGetModuleFileNameW(_In_opt_ HMODULE hModule, _Out_ LPWSTR lpFilename, _In_ DWORD nSize) {
	get_module_file_name_w(hModule, lpFilename, nSize);
}


std::function<void(LPCWSTR lpModuleName)>
get_module_handle_w = [](LPCWSTR lpModuleName) {
	tracingStream << "GetModuleHandleW" << endl;
};

void
WINAPI
hookGetModuleHandleW(_In_opt_ LPCWSTR lpModuleName) {
	get_module_handle_w(lpModuleName);
}


std::function<void(DWORD dwFlags, LPCWSTR lpModuleName, HMODULE* phModule)>
get_module_handle_ex_w = [](DWORD dwFlags, LPCWSTR lpModuleName, HMODULE* phModule) {
	tracingStream << "GetModuleHandleExW" << endl;
};

void
WINAPI
hookGetModuleHandleExW(_In_ DWORD dwFlags, _In_opt_ LPCWSTR lpModuleName, _Out_ HMODULE* phModule) {
	get_module_handle_ex_w(dwFlags, lpModuleName, phModule);
}


std::function<void(HMODULE hModule, LPCSTR lpProcName)>
get_proc_address = [](HMODULE hModule, LPCSTR lpProcName) {
	tracingStream << "GetProcAddress" << endl;
};

void
WINAPI
hookGetProcAddress(_In_ HMODULE hModule, _In_ LPCSTR lpProcName) {
	get_proc_address(hModule, lpProcName);
}


std::function<void(LPCWSTR lpLibFileName)>
load_library_w = [](LPCWSTR lpLibFileName) {
	tracingStream << "LoadLibraryW" << endl;
};

void
WINAPI
hookLoadLibraryW(_In_ LPCWSTR lpLibFileName) {
	load_library_w(lpLibFileName);
}

std::function<void(DLL_DIRECTORY_COOKIE Cookie)>
remove_dll_directory = [](DLL_DIRECTORY_COOKIE Cookie) {
	tracingStream << "RemoveDllDirectory" << endl;
};

void
WINAPI
hookRemoveDllDirectory(_In_ DLL_DIRECTORY_COOKIE Cookie) {
	remove_dll_directory(Cookie);
}


std::function<void(DWORD DirectoryFlags)>
set_default_dll_directories = [](DWORD DirectoryFlags) {
	tracingStream << "SetDefaultDllDirectories" << endl;
};

void
WINAPI
hookSetDefaultDllDirectories(_In_ DWORD DirectoryFlags) {
	set_default_dll_directories(DirectoryFlags);
}


std::function<void(LPCWSTR lpPathName)>
set_dll_directory_w = [](LPCWSTR lpPathName) {
	tracingStream << "SetDllDirectoryW" << endl;
};

void
WINAPI
hookSetDllDirectoryW(_In_opt_ LPCWSTR lpPathName) {
	set_dll_directory_w(lpPathName);
}

std::function<void(HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength)>
adjust_token_privileges = [](HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength) {
	tracingStream << "AdjustTokenPrivileges" << endl;
};

void
WINAPI
hookAdjustTokenPrivileges(_In_ HANDLE TokenHandle, _In_ BOOL DisableAllPrivileges, _In_opt_ PTOKEN_PRIVILEGES NewState, _In_ DWORD BufferLength, _Out_opt_ PTOKEN_PRIVILEGES PreviousState, _Out_opt_ PDWORD ReturnLength) {
	adjust_token_privileges(TokenHandle, DisableAllPrivileges, NewState, BufferLength, PreviousState, ReturnLength);
}


std::function<void(DWORD idAttach, DWORD idAttachTo, BOOL fAttach)>
attach_thread_input = [](DWORD idAttach, DWORD idAttachTo, BOOL fAttach) {
	tracingStream << "AttachThreadInput" << endl;
};

void
WINAPI
hookAttachThreadInput(_In_ DWORD idAttach, _In_ DWORD idAttachTo, _In_ BOOL fAttach) {
	attach_thread_input(idAttach, idAttachTo, fAttach);
}


std::function<void(HHOOK hhk, int nCode, WPARAM wParam, LPARAM lParam)>
call_next_hook_ex = [](HHOOK hhk, int nCode, WPARAM wParam, LPARAM lParam) {
	tracingStream << "CallNextHookEx" << endl;
};

void
WINAPI
hookCallNextHookEx(_In_opt_ HHOOK hhk, _In_ int nCode, _In_ WPARAM wParam, _In_ LPARAM lParam) {
	call_next_hook_ex(hhk, nCode, wParam, lParam);
}


std::function<void(HCRYPTPROV_LEGACY hProv, LPCSTR szSubsystemProtocol)>
cert_open_system_store_a = [](HCRYPTPROV_LEGACY hProv, LPCSTR szSubsystemProtocol) {
	tracingStream << "CertOpenSystemStoreA" << endl;
};

void
WINAPI
hookCertOpenSystemStoreA(_In_ HCRYPTPROV_LEGACY hProv, _In_ LPCSTR szSubsystemProtocol) {
	cert_open_system_store_a(hProv, szSubsystemProtocol);
}


std::function<void(HANDLE hProcess, PBOOL pbDebuggerPresent)>
check_remote_debugger_present = [](HANDLE hProcess, PBOOL pbDebuggerPresent) {
	tracingStream << "CheckRemoteDebuggerPresent" << endl;
};

void
WINAPI
hookCheckRemoteDebuggerPresent(_In_ HANDLE hProcess, _Inout_ PBOOL pbDebuggerPresent) {
	check_remote_debugger_present(hProcess, pbDebuggerPresent);
}


std::function<void(REFCLSID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, REFIID riid, LPVOID* ppv)>
co_create_instance = [](REFCLSID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, REFIID riid, LPVOID* ppv) {
	tracingStream << "CoCreateInstance" << endl;
};

void
WINAPI
hookCoCreateInstance(_In_ REFCLSID rclsid, _In_ LPUNKNOWN pUnkOuter, _In_ DWORD dwClsContext, _In_ REFIID riid, _Out_ LPVOID* ppv) {
	co_create_instance(rclsid, pUnkOuter, dwClsContext, riid, ppv);
}

std::function<void(HANDLE hNamedPipe, LPOVERLAPPED lpOverlapped)>
connect_named_pipe = [](HANDLE hNamedPipe, LPOVERLAPPED lpOverlapped) {
	tracingStream << "ConnectNamedPipe" << endl;
};

void
WINAPI
hookConnectNamedPipe(_In_ HANDLE hNamedPipe, _Inout_opt_ LPOVERLAPPED lpOverlapped) {
	connect_named_pipe(hNamedPipe, lpOverlapped);
}


std::function<void(SC_HANDLE hService, DWORD dwControl, LPSERVICE_STATUS lpServiceStatus)>
control_service = [](SC_HANDLE hService, DWORD dwControl, LPSERVICE_STATUS lpServiceStatus) {
	tracingStream << "ControlService" << endl;
};

void
WINAPI
hookControlService(_In_ SC_HANDLE hService, _In_ DWORD dwControl, _Out_ LPSERVICE_STATUS lpServiceStatus) {
	control_service(hService, dwControl, lpServiceStatus);
}


std::function<void(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)>
create_file_w = [](LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
	tracingStream << "CreateFileW" << endl;
};

void
WINAPI
hookCreateFileW(_In_ LPCWSTR lpFileName, _In_ DWORD dwDesiredAccess, _In_ DWORD dwShareMode, _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes, _In_ DWORD dwCreationDisposition, _In_ DWORD dwFlagsAndAttributes, _In_opt_ HANDLE hTemplateFile) {
	create_file_w(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}



std::function<void(LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCWSTR lpName)>
create_mutex_w = [](LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCWSTR lpName) {
	tracingStream << "CreateMutexW" << endl;
};

void
WINAPI
hookCreateMutexW(_In_opt_ LPSECURITY_ATTRIBUTES lpMutexAttributes, _In_ BOOL bInitialOwner, _In_opt_ LPCWSTR lpName) {
	create_mutex_w(lpMutexAttributes, bInitialOwner, lpName);
}


std::function<void(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId)>
create_remote_thread = [](HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId) {
	tracingStream << "CreateRemoteThread" << endl;
};

void
WINAPI
hookCreateRemoteThread(_In_ HANDLE hProcess, _In_ LPSECURITY_ATTRIBUTES lpThreadAttributes, _In_ SIZE_T dwStackSize, _In_ LPTHREAD_START_ROUTINE lpStartAddress, _In_ LPVOID lpParameter, _In_ DWORD dwCreationFlags, _Out_ LPDWORD lpThreadId) {
	create_remote_thread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
}


std::function<void(HCRYPTPROV* phProv, LPCWSTR szContainer, LPCWSTR szProvider, DWORD dwProvType, DWORD dwFlags)>
crypt_acquire_context_w = [](HCRYPTPROV* phProv, LPCWSTR szContainer, LPCWSTR szProvider, DWORD dwProvType, DWORD dwFlags) {
	tracingStream << "CryptAcquireContextW" << endl;
};

void
WINAPI
hookCryptAcquireContextW(_Out_ HCRYPTPROV* phProv, _In_ LPCWSTR szContainer, _In_ LPCWSTR szProvider, _In_ DWORD dwProvType, _In_ DWORD dwFlags) {
	crypt_acquire_context_w(phProv, szContainer, szProvider, dwProvType, dwFlags);
}


std::function<void(HANDLE hDevice, DWORD dwIoControlCode, LPVOID lpInBuffer, DWORD nInBufferSize, LPVOID lpOutBuffer, DWORD nOutBufferSize, LPDWORD lpBytesReturned, LPOVERLAPPED lpOverlapped)>
device_io_control = [](HANDLE hDevice, DWORD dwIoControlCode, LPVOID lpInBuffer, DWORD nInBufferSize, LPVOID lpOutBuffer, DWORD nOutBufferSize, LPDWORD lpBytesReturned, LPOVERLAPPED lpOverlapped) {
	tracingStream << "DeviceIoControl" << endl;
};

void
WINAPI
hookDeviceIoControl(_In_ HANDLE hDevice, _In_ DWORD dwIoControlCode, _In_opt_ LPVOID lpInBuffer, _In_ DWORD nInBufferSize, _Out_opt_ LPVOID lpOutBuffer, _In_ DWORD nOutBufferSize, _Out_opt_ LPDWORD lpBytesReturned, _Inout_opt_ LPOVERLAPPED lpOverlapped) {
	device_io_control(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize, lpBytesReturned, lpOverlapped);
}

std::function<void(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)>
create_process_w = [](LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation) {
	tracingStream << "CreateProcessW" << endl;
};

void
WINAPI
hookCreateProcessW(_In_opt_ LPCWSTR lpApplicationName, _Inout_opt_ LPWSTR lpCommandLine, _In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes, _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes, _In_ BOOL bInheritHandles, _In_ DWORD dwCreationFlags, _In_opt_ LPVOID lpEnvironment, _In_opt_ LPCWSTR lpCurrentDirectory, _In_ LPSTARTUPINFOW lpStartupInfo, _Out_ LPPROCESS_INFORMATION lpProcessInformation) {
	create_process_w(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
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
 * @param composedFunctionAdd address of function that delegates to coreHookLambda
 * @param coreHookLamda lambda that contains core logic to be insert before original API call
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
		_FreeLibraryAndExitThread = m_dll["FreeLibraryAndExitThread"];
		_GetDllDirectoryW = m_dll["GetDllDirectoryW"];
		_GetModuleFileNameW = m_dll["GetModuleFileNameW"];
		_GetModuleHandleW = m_dll["GetModuleHandleW"];
		_GetModuleHandleExW = m_dll["GetModuleHandleExW"];
		_GetProcAddress = m_dll["GetProcAddress"];
		_LoadLibraryW = m_dll["LoadLibraryW"];
		_RemoveDllDirectory = m_dll["RemoveDllDirectory"];
		_SetDefaultDllDirectories = m_dll["SetDefaultDllDirectories"];
		_SetDllDirectoryW = m_dll["SetDllDirectoryW"];
		_AdjustTokenPrivileges = m_dll["AdjustTokenPrivileges"];
		_AttachThreadInput = m_dll["AttachThreadInput"];
		_CallNextHookEx = m_dll["CallNextHookEx"];
		_CertOpenSystemStoreA = m_dll["CertOpenSystemStoreA"];
		_CheckRemoteDebuggerPresent = m_dll["CheckRemoteDebuggerPresent"];
		_CoCreateInstance = m_dll["CoCreateInstance"];
		_ConnectNamedPipe = m_dll["ConnectNamedPipe"];
		_ControlService = m_dll["ControlService"];
		_CreateFileW = m_dll["CreateFileW"];
		_ConnectNamedPipe = m_dll["ConnectNamedPipe"];
		_ControlService = m_dll["ControlService"];
		_CreateFileW = m_dll["CreateFileW"];
		_CreateMutexW = m_dll["CreateMutexW"];
		_CreateProcessW = m_dll["CreateProcessW"];
		_CreateRemoteThread = m_dll["CreateRemoteThread"];
		_ControlService = m_dll["ControlService"];
		_CryptAcquireContextW = m_dll["CryptAcquireContextW"];
		_DeviceIoControl = m_dll["DeviceIoControl"];
	}

	decltype(Beep)* _Beep;
	decltype(GetDiskFreeSpaceA)* _DiskFreeSpace;

	// Functions to consider hooking
	decltype(CreateFile)* _CreateFile;
	decltype(CreateFileMapping)* _CreateFileMapping;
	decltype(CreateProcess)* _CreateProcess;
	decltype(CryptAcquireContext)* _CryptAcquireContext;
	decltype(gethostbyname)* _gethostbyname;
	decltype(GetModuleFileName)* _GetModuleFilename;
	decltype(GetThreadContext)* _GetThreadContext;
	decltype(GetTickCount)* _GetTickCount;
	decltype(GetWindowsDirectory)* _GetWindowsDirectory;

	decltype(AddDllDirectory)* _AddDllDirectory;
	decltype(DisableThreadLibraryCalls)* _DisableThreadLibraryCalls;
	decltype(FreeLibrary)* _FreeLibrary;
	decltype(FreeLibraryAndExitThread)* _FreeLibraryAndExitThread;
	decltype(GetDllDirectoryW)* _GetDllDirectoryW;
	decltype(GetModuleFileNameW)* _GetModuleFileNameW;
	decltype(GetModuleHandleW)* _GetModuleHandleW;
	decltype(GetModuleHandleExW)* _GetModuleHandleExW;
	decltype(GetProcAddress)* _GetProcAddress;
	decltype(LoadLibraryW)* _LoadLibraryW;
	decltype(RemoveDllDirectory)* _RemoveDllDirectory;
	decltype(SetDefaultDllDirectories)* _SetDefaultDllDirectories;
	decltype(SetDllDirectoryW)* _SetDllDirectoryW;
	decltype(AdjustTokenPrivileges)* _AdjustTokenPrivileges;
	decltype(AttachThreadInput)* _AttachThreadInput;
	decltype(CallNextHookEx)* _CallNextHookEx;
	decltype(CertOpenSystemStoreA)* _CertOpenSystemStoreA;
	decltype(CheckRemoteDebuggerPresent)* _CheckRemoteDebuggerPresent;
	decltype(CoCreateInstance)* _CoCreateInstance;
	decltype(ConnectNamedPipe)* _ConnectNamedPipe;
	decltype(CreateFileW)* _CreateFileW;
	decltype(CreateMutexW)* _CreateMutexW;
	decltype(CreateProcessW)* _CreateProcessW;
	decltype(CreateRemoteThread)* _CreateRemoteThread;
	decltype(ControlService)* _ControlService;
	decltype(CryptAcquireContextW)* _CryptAcquireContextW;
	decltype(DeviceIoControl)* _DeviceIoControl;


private:
	DllHelper m_dll;
};


list<HookInstaller> CreateHooks() {
	list<HookInstaller> hookList;
	WindowsAPIHelper windowsHelper;

	//add specific hooks
	hookList.push_back(CreateHookingEnvironment(windowsHelper._CreateFile, myCreateFileW, &create_file));
	hookList.push_back(CreateHookingEnvironment(windowsHelper._CreateFileMapping, myCreateFileMapping, &create_file_mapping_w));

	hookList.push_back(CreateHookingEnvironment(windowsHelper._AddDllDirectory, hookAddDllDirectory, &add_dll_directory));
	hookList.push_back(CreateHookingEnvironment(windowsHelper._DisableThreadLibraryCalls, hookDisableThreadLibraryCalls, &disable_thread_library_calls));
	hookList.push_back(CreateHookingEnvironment(windowsHelper._FreeLibrary, hookFreeLibrary, &free_library));
	hookList.push_back(CreateHookingEnvironment(windowsHelper._FreeLibraryAndExitThread, hookFreeLibraryAndExitThread, &free_library_and_exit_thread));
	hookList.push_back(CreateHookingEnvironment(windowsHelper._GetDllDirectoryW, hookGetDllDirectoryW, &get_dll_directory_w));
	hookList.push_back(CreateHookingEnvironment(windowsHelper._GetModuleFileNameW, hookGetModuleFileNameW, &get_module_file_name_w));
	hookList.push_back(CreateHookingEnvironment(windowsHelper._GetModuleHandleW, hookGetModuleHandleW, &get_module_handle_w));
	hookList.push_back(CreateHookingEnvironment(windowsHelper._GetModuleHandleExW, hookGetModuleHandleExW, &get_module_handle_ex_w));
	hookList.push_back(CreateHookingEnvironment(windowsHelper._GetProcAddress, hookGetProcAddress, &get_proc_address));
	hookList.push_back(CreateHookingEnvironment(windowsHelper._LoadLibraryW, hookLoadLibraryW, &load_library_w));
	hookList.push_back(CreateHookingEnvironment(windowsHelper._RemoveDllDirectory, hookRemoveDllDirectory, &remove_dll_directory));
	hookList.push_back(CreateHookingEnvironment(windowsHelper._SetDefaultDllDirectories, hookSetDefaultDllDirectories, &set_default_dll_directories));
	hookList.push_back(CreateHookingEnvironment(windowsHelper._SetDllDirectoryW, hookSetDllDirectoryW, &set_dll_directory_w));
	hookList.push_back(CreateHookingEnvironment(windowsHelper._AdjustTokenPrivileges, hookAdjustTokenPrivileges, &adjust_token_privileges));
	hookList.push_back(CreateHookingEnvironment(windowsHelper._AttachThreadInput, hookAttachThreadInput, &attach_thread_input));
	hookList.push_back(CreateHookingEnvironment(windowsHelper._CallNextHookEx, hookCallNextHookEx, &call_next_hook_ex));
	hookList.push_back(CreateHookingEnvironment(windowsHelper._CertOpenSystemStoreA, hookCertOpenSystemStoreA, &cert_open_system_store_a));
	hookList.push_back(CreateHookingEnvironment(windowsHelper._CheckRemoteDebuggerPresent, hookCheckRemoteDebuggerPresent, &check_remote_debugger_present));
	hookList.push_back(CreateHookingEnvironment(windowsHelper._CoCreateInstance, hookCoCreateInstance, &co_create_instance));
	hookList.push_back(CreateHookingEnvironment(windowsHelper._ConnectNamedPipe, hookConnectNamedPipe, &connect_named_pipe));
	hookList.push_back(CreateHookingEnvironment(windowsHelper._CreateFileW, hookCreateFileW, &create_file_w));
	hookList.push_back(CreateHookingEnvironment(windowsHelper._CreateMutexW, hookCreateMutexW, &create_mutex_w));
	hookList.push_back(CreateHookingEnvironment(windowsHelper._CreateProcessW, hookCreateProcessW, &create_process_w));
	hookList.push_back(CreateHookingEnvironment(windowsHelper._CreateRemoteThread, hookCreateRemoteThread, &create_remote_thread));
	hookList.push_back(CreateHookingEnvironment(windowsHelper._ControlService, hookControlService, &control_service));
	hookList.push_back(CreateHookingEnvironment(windowsHelper._CryptAcquireContextW, hookCryptAcquireContextW, &crypt_acquire_context_w));
	hookList.push_back(CreateHookingEnvironment(windowsHelper._DeviceIoControl, hookDeviceIoControl, &device_io_control));
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