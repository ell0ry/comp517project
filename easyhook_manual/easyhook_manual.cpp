#include <string>
#include <iostream>
#include <Windows.h>
#include <easyhook.h>
#include <functional>

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
FuncComp<U, T...> createGenFunc(U(*origFunc)(T... args), std::function<U(T...)> hookFunc) {
    return FuncComp<U, T...>([=](T...xs) {
        hookFunc(xs...);
        return origFunc(xs...);
        });
}

template<typename U, typename...T>
FuncComp<U, T...> createGenFunc(U(*origFunc)(T... args), U(*hookFunc)(T... args)) {
    return FuncComp<U, T...>([=](T...xs) {
        hookFunc(xs...);
        return origFunc(xs...);
    });
}

template<typename U, typename... T>
class HookInstaller
{
    HookInstaller(void* origFunc, void* hookedFunction) {
        
    }

};

// Helper Class to group and easy access API calls
class WindowsAPIHelper
{
public:
    WindowsAPIHelper() : m_dll()
    {
        _Beep = m_dll["Beep"];
        _DiskFreeSpace = m_dll["GetDiskFreeSpaceA"];
    }


    decltype(Beep)* _Beep;
    decltype(GetDiskFreeSpaceA)* _DiskFreeSpace;

private:
    DllHelper m_dll;
};


using namespace std;

BOOL WINAPI myBeepHook(DWORD dwFreq, DWORD dwDuration);
BOOL WINAPI myDiskFreespaceHook(LPCSTR lpRootPathName, LPDWORD lpSectors, LPDWORD lpBytesPerSector, LPDWORD freeCluster, LPDWORD lpTotalClusters);

BOOL WINAPI myBeepHook(DWORD dwFreq, DWORD dwDuration)
{
    cout << "\n****All your beeps belong to us!\n\n";
    return Beep(dwFreq + 800, dwDuration);
}

BOOL WINAPI coreDiskHook(LPCSTR lpRootPathName, LPDWORD lpSectors, LPDWORD lpBytesPerSector, LPDWORD freeCluster, LPDWORD lpTotalClusters)
{
    cout << "\n Hooked the disk freespace function! Going to bypass it.";
    *lpSectors = 10;
    *lpBytesPerSector = 10;
    *freeCluster = 10;
    *lpTotalClusters = 10;
    return true;
}
auto Disk_hook = createGenFunc(GetDiskFreeSpaceA, coreDiskHook).composedFunction;
BOOL WINAPI myDiskFreespaceHook(LPCSTR lpRootPathName, LPDWORD lpSectors, LPDWORD lpBytesPerSector, LPDWORD freeCluster, LPDWORD lpTotalClusters)
{
    return Disk_hook(lpRootPathName, lpSectors, lpBytesPerSector, freeCluster, lpTotalClusters);
}

void print_disk_space(DWORD sectors = 0, DWORD bps = 0, DWORD free_cluster = 0, DWORD total_cluster = 0) {
    cout << "sectors: " << sectors << endl;
    cout << "bytes per sector: " << bps << endl;
    cout << "free clusters: " << free_cluster << endl;
    cout << "total clusters: " << total_cluster << endl;
}

void hook_disk_space() {
    WindowsAPIHelper windowsHelper;
    HOOK_TRACE_INFO hHook = { NULL };
    HMODULE mod = GetModuleHandle(TEXT("kernel32"));
    FARPROC c = GetProcAddress(GetModuleHandle(TEXT("kernel32")), "GetDiskFreeSpaceA");

    // Install the hook
    NTSTATUS result = LhInstallHook(
        GetProcAddress(GetModuleHandle(TEXT("kernel32")), "GetDiskFreeSpaceA"),
        myDiskFreespaceHook,
        NULL,
        &hHook);
    
    if (FAILED(result))
    {
        wstring s(RtlGetLastErrorString());
        wcout << "Failed to install hook: ";
        wcout << s;
        cout << "\n\nPress any key to exit.";
        cin.get();
        return;
    }


    DWORD sectors = 0;
    DWORD bps = 0;
    DWORD free_cluster = 0;
    DWORD total_cluster = 0;
    cout << "Free Disk Space Before\n";
    windowsHelper._DiskFreeSpace("C:/", &sectors, &bps, &free_cluster, &total_cluster);
    print_disk_space(sectors, bps, free_cluster, total_cluster);
    
    // If the threadId in the ACL is set to 0, 
    // then internally EasyHook uses GetCurrentThreadId()
    ULONG ACLEntries[1] = { 0 };
    LhSetInclusiveACL(ACLEntries, 1, &hHook);

    cout << "Free Disk Space After Enabling.\n";
    windowsHelper._DiskFreeSpace("C:/", &sectors, &bps, &free_cluster, &total_cluster);
    print_disk_space(sectors, bps, free_cluster, total_cluster);

    cout << "Uninstall hook\n";
    LhUninstallHook(&hHook);

    cout << "Free Disk Space After Uninstall\n";
    windowsHelper._DiskFreeSpace("C:/", &sectors, &bps, &free_cluster, &total_cluster);
    print_disk_space(sectors, bps, free_cluster, total_cluster);

    cout << "\n\nRestore ALL entry points of pending removals issued by LhUninstallHook()\n";
    LhWaitForPendingRemovals();
}

void hook_beep() {
    WindowsAPIHelper w32;

    HOOK_TRACE_INFO hHook = { NULL }; // keep track of our hook
    cout << "\n";
    cout << GetProcAddress(GetModuleHandle(TEXT("kernel32")), "Beep");

    // Install the hook
    NTSTATUS result = LhInstallHook(
        GetProcAddress(GetModuleHandle(TEXT("kernel32")), "Beep"),
        myBeepHook,
        NULL,
        &hHook);
    if (FAILED(result))
    {
        wstring s(RtlGetLastErrorString());
        wcout << "Failed to install hook: ";
        wcout << s;
        cout << "\n\nPress any key to exit.";
        cin.get();
        return;
    }

    cout << "Beep after hook installed but not enabled.\n";
    w32._Beep(500, 500);

    cout << "Activating hook for current thread only.\n";
    // If the threadId in the ACL is set to 0, 
    // then internally EasyHook uses GetCurrentThreadId()
    ULONG ACLEntries[1] = { 0 };
    LhSetInclusiveACL(ACLEntries, 1, &hHook);

    cout << "Beep after hook enabled.\n";
    w32._Beep(500, 500);

    cout << "Uninstall hook\n";
    LhUninstallHook(&hHook);

    cout << "Beep after hook uninstalled\n";
    w32._Beep(500, 500);

    cout << "\n\nRestore ALL entry points of pending removals issued by LhUninstallHook()\n";
    LhWaitForPendingRemovals();

}

int main()
{
    //hook_beep();
    hook_disk_space();
    //genFunc<> twst = genFunc();
    cout << "Press any key to exit.";
    cin.get();

    return 0;
}