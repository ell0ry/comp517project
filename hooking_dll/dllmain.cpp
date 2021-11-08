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

using namespace std;

// EasyHook will be looking for this export to support DLL injection. If not found then 
// DLL injection will fail.
extern "C" void __declspec(dllexport) __stdcall NativeInjectionEntryPoint(REMOTE_ENTRY_INFO * inRemoteInfo);


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

//template<typename U, typename...T>
//FuncComp<U, T...> createGenFunc(U(*origFunc)(T... args), void(*hookFunc)(T... args)) {
//    return FuncComp<U, T...>([=](T...xs) {
//        hookFunc(xs...);
//        return origFunc(xs...);
//        });
//}

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
            wcout << s;
        }
        else {
            wcout << "HookInstaller: Installed the hook successfully";
        }
    }
    void enableHookForProccess(ULONG id) {
        ULONG ACLEntries[1] = { id };
        LhSetInclusiveACL(ACLEntries, 1, &hHook);
    }

    void enableHookForCurrentProcess() {
        ULONG ACLEntries[1] = { 0 };
        LhSetInclusiveACL(ACLEntries, 1, &hHook);
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

private:
    DllHelper m_dll;
};


list<HookInstaller> CreateHooks() {
    list<HookInstaller> hookList;
    WindowsAPIHelper windowsHelper;

    //add specific hooks
    hookList.push_back(CreateHookingEnvironment(windowsHelper._CreateFile, myCreateFileW, &create_file));
    return hookList;
}

// ======================================================  Hooking Helper Classes ============================================== //

void HookProcess(DWORD processToHook) {
    cout << "hooking into " << processToHook << "\n";
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
	/*
	std::cout << "Passed in data size: " << inRemoteInfo->UserDataSize << "\n";
	if (inRemoteInfo->UserDataSize == sizeof(DWORD))
	{
		gFreqOffset = *reinterpret_cast<DWORD*>(inRemoteInfo->UserData);
		std::cout << "Adjusting Beep frequency by: " << gFreqOffset << "\n";
	}

	// Perform hooking
	HOOK_TRACE_INFO hHook = { NULL }; // keep track of our hook

	std::cout << "\n";
	std::cout << "Win32 Beep found at address: " << GetProcAddress(GetModuleHandle(TEXT("kernel32")), "Beep") << "\n";

	// Install the hook
	NTSTATUS result = LhInstallHook(
		GetProcAddress(GetModuleHandle(TEXT("kernel32")), "Beep"),
		myBeepHook,
		NULL,
		&hHook);
	if (FAILED(result))
	{
		std::wstring s(RtlGetLastErrorString());
		std::wcout << "Failed to install hook: ";
		std::wcout << s;
	}
	else
	{
		std::cout << "Hook 'myBeepHook installed successfully.";
	}

	// If the threadId in the ACL is set to 0,
	// then internally EasyHook uses GetCurrentThreadId()
	ULONG ACLEntries[1] = { 0 };

	// Disable the hook for the provided threadIds, enable for all others
	LhSetExclusiveACL(ACLEntries, 1, &hHook);
	*/


	HookProcess(0); // Unclear what the parameter here corresponds to.

	return;
}