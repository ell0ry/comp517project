#include <string>
#include <iostream>
#include <Windows.h>
#include <easyhook.h>
#include <functional>
#include <list>
using namespace std;




/* Simple console application that hooks our IDS DLL into an arbitrary process. */
int main()
{
    char line[15];
    cout << "Enter pid of application to hook:\n";
    cin >> line;
    DWORD pidOfInterest = atol(line);
    // HookProcess(pidOfInterest);

    WCHAR dllName[] = L"hooking_dll.dll";

    NTSTATUS nt = RhInjectLibrary(
        pidOfInterest,
        0,
        EASYHOOK_INJECT_DEFAULT,
        NULL,
        dllName,
        NULL,
        0
    );

    if (nt != 0)
    {
        printf("RhInjectLibrary failed with error code = %d\n", nt);
        PWCHAR err = RtlGetLastErrorString();
        std::wcout << err << "\n";
    }
    else
    {
        std::wcout << L"Library injected successfully.\n";
    }

    std::wcout << "Press Enter to exit";
    std::wstring input;
    std::getline(std::wcin, input);
    std::getline(std::wcin, input);
    return 0;
}