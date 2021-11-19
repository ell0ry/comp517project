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
    while (1) {
        char line[15];
        cout << "Enter pid of application to hook, or ctrl-c to exit:\n";
        cin >> line;
        if (line[0] == '\0') {
            return 0;
        }
        cout << (int) line[0] << endl;

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
    }
}