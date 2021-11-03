#include <string>
#include <iostream>
#include <Windows.h>
#include <easyhook.h>
#include <functional>
//BOOL GetDiskFreeSpaceA(
//    [in]  LPCSTR  lpRootPathName,
//    [out] LPDWORD lpSectorsPerCluster,
//  [out] LPDWORD lpBytesPerSector,
//  [out] LPDWORD lpNumberOfFreeClusters,
//  [out] LPDWORD lpTotalNumberOfClusters
//);


class ProcPtr
{
public:
    explicit ProcPtr(FARPROC ptr) : m_ptr(ptr) {}

    template <typename T>
    operator T* () const { return reinterpret_cast<T*>(m_ptr); }

private:
    FARPROC m_ptr;
};

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

template <class T>
class genFunc {

    genFunc(T originalFunction, LPCSTR proc) {
        originalFunc = originalFunction;
        newFunc = [] (T) {
            return originalFunction;
        };
        proc_name = proc;
    }

private:
    LPCSTR proc_name;
    T originalFunc;
    T newFunc;
};

class windows32Help
{
public:
    windows32Help() : m_dll()
    {
        newbeep = m_dll["Beep"];
        newDA = m_dll["GetDiskFreeSpaceA"];
    }

    decltype(Beep)* newbeep;
    decltype(GetDiskFreeSpaceA)* newDA;

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

BOOL WINAPI myDiskFreespaceHook(LPCSTR lpRootPathName, LPDWORD lpSectors, LPDWORD lpBytesPerSector, LPDWORD freeCluster, LPDWORD lpTotalClusters)
{
    cout << "\n Hooked the disk freespace function! Going to bypass it.";
    *lpSectors = 10;
    *lpBytesPerSector = 10;
    *freeCluster = 10;
    *lpTotalClusters = 10;

    return true;
    
}

void print_disk_space(DWORD sectors = 0, DWORD bps = 0, DWORD free_cluster = 0, DWORD total_cluster = 0) {
    cout << "sectors: " << sectors << endl;
    cout << "bytes per sector: " << bps << endl;
    cout << "free clusters: " << free_cluster << endl;
    cout << "total clusters: " << total_cluster << endl;
}

void hook_disk_space() {
    windows32Help w32;
    HOOK_TRACE_INFO hHook = { NULL };
    HMODULE mod = GetModuleHandle(TEXT("kernel32"));
    FARPROC c = GetProcAddress(GetModuleHandle(TEXT("kernel32")), "GetDiskFreeSpaceA");
    //std::function<void(DWORD, DWORD, DWORD, DWORD)> fn = c;

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
    w32.newDA("C:/", &sectors, &bps, &free_cluster, &total_cluster);
    print_disk_space(sectors, bps, free_cluster, total_cluster);
    
    // If the threadId in the ACL is set to 0, 
    // then internally EasyHook uses GetCurrentThreadId()
    ULONG ACLEntries[1] = { 0 };
    LhSetInclusiveACL(ACLEntries, 1, &hHook);

    cout << "Free Disk Space After Enabling.\n";
    w32.newDA("C:/", &sectors, &bps, &free_cluster, &total_cluster);
    print_disk_space(sectors, bps, free_cluster, total_cluster);

    cout << "Uninstall hook\n";
    LhUninstallHook(&hHook);

    cout << "Free Disk Space After Uninstall\n";
    w32.newDA("C:/", &sectors, &bps, &free_cluster, &total_cluster);
    print_disk_space(sectors, bps, free_cluster, total_cluster);

    cout << "\n\nRestore ALL entry points of pending removals issued by LhUninstallHook()\n";
    LhWaitForPendingRemovals();
}

void hook_beep() {
    windows32Help w32;

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
    w32.newbeep(500, 500);

    cout << "Activating hook for current thread only.\n";
    // If the threadId in the ACL is set to 0, 
    // then internally EasyHook uses GetCurrentThreadId()
    ULONG ACLEntries[1] = { 0 };
    LhSetInclusiveACL(ACLEntries, 1, &hHook);

    cout << "Beep after hook enabled.\n";
    w32.newbeep(500, 500);

    cout << "Uninstall hook\n";
    LhUninstallHook(&hHook);

    cout << "Beep after hook uninstalled\n";
    w32.newbeep(500, 500);

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