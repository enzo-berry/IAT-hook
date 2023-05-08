#include <windows.h>
#include <stdio.h>


#include <Psapi.h>
#pragma comment(lib, "Psapi.lib")





//The original pointer to the MessageBoxA function
uintptr_t orignal_ptr = NULL;

//declare MessageBoxA type 
typedef int(WINAPI* pMessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);

//The wrapper function, which will be called instead of the original MessageBoxA, needs to be same type as the original function
int WINAPI MessageBoxWrapper(HWND h, LPCSTR lpText, LPCSTR lpText2, UINT uType) {

    //Call the original MessageBoxA function but with different parameters
    pMessageBoxA originalMessageBoxA = (pMessageBoxA)orignal_ptr;
    originalMessageBoxA(h, "Hooked", "Hooked", uType);

    return 0;
}

void realmain() {
    // Obtain the process handle
    HANDLE hProcess = GetCurrentProcess();

    // Get the process's module base address
    HMODULE hMainModule = nullptr;
    DWORD cbNeeded;

    //We enumerate all Modules loaded from the process
    if (EnumProcessModules(hProcess, &hMainModule, sizeof(hMainModule), &cbNeeded)) {

        //Fetching headers of imported module
        PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hMainModule;
        PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hMainModule + pDosHeader->e_lfanew);

        //Get the IAT
        PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)hMainModule + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        while (pImportDescriptor->Name) {
            // Get the name of the imported DLL
            char* pszDllName = (char*)((BYTE*)hMainModule + pImportDescriptor->Name);

            // Check if the DLL is USER32.dll because MessageBoxA is in this DLL
            if (_stricmp(pszDllName, "USER32.dll") == 0) {
                // Look for the desired WinAPI function

                //The chunk that contains the function names
                PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((BYTE*)hMainModule + pImportDescriptor->OriginalFirstThunk);
                //The chunk that contains the function addresses
                PIMAGE_THUNK_DATA pFuncThunk = (PIMAGE_THUNK_DATA)((BYTE*)hMainModule + pImportDescriptor->FirstThunk);
                
                while (pThunk->u1.Function) {
                    PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)hMainModule + pThunk->u1.AddressOfData);
                    if (strcmp((char*)pImportByName->Name, "MessageBoxA") == 0) {
                        printf("Resolved MessageBoxA pointer at: 0x%p\n",pFuncThunk->u1.Function);

                        DWORD dwOldProtect;

                        // Change the protection of the page containing the function address
                        VirtualProtect(&pFuncThunk->u1.Function, sizeof(pFuncThunk->u1.Function), PAGE_READWRITE, &dwOldProtect);
                        orignal_ptr = pFuncThunk->u1.Function;

                        // Change the function address to the address of our wrapper function
                        pFuncThunk->u1.Function = (uintptr_t)&MessageBoxWrapper;

                        // Restore the protection of the page containing the function address
                        VirtualProtect(&pFuncThunk->u1.Function, sizeof(pFuncThunk->u1.Function), dwOldProtect, &dwOldProtect);
                        
                        printf("Hooked\n", pFuncThunk->u1.Function);
                        break;
                    }
                    //we increment the pointers to the next thunk
                    pThunk++;
                    pFuncThunk++;
                }
                break;
            }
            //we increment the pointer to the next import descriptor
            pImportDescriptor++;
        }
    }
}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
   if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
       printf("Injected !\n");
       realmain();
	}
    
    return TRUE;
}

