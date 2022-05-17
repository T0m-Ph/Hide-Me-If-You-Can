VIRTUALALLOCEX = {
    "name": "VirtualAllocEx",
    "code": """
typedef LPVOID (WINAPI * VirtualAllocEx_t)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
unsigned char sVirtualAllocEx[] = {{ {encryptedString} }};
unsigned int lenVirtualAllocEx = sizeof(sVirtualAllocEx);
VirtualAllocEx_t VirtualAllocEx_p;
    """,
    "mainCode": """
    {decryptionRoutine}
    VirtualAllocEx_p = (VirtualAllocEx_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sVirtualAllocEx);
    """,
    "dependencies": []
}

VIRTUAL_ALLOC = {
    "name": "VirtualAlloc",
    "code": """
typedef LPVOID (WINAPI * VirtualAlloc_t)(LPVOID, SIZE_T, DWORD, DWORD);
unsigned char sVirtualAlloc[] = {{ {encryptedString} }};
unsigned int lenVirtualAlloc = sizeof(sVirtualAlloc);
VirtualAlloc_t VirtualAlloc_p;
    """,
    "mainCode": """
    {decryptionRoutine}
    VirtualAlloc_p = (VirtualAlloc_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sVirtualAlloc);
    """,
    "dependencies": []
}

WRITEPROCESSMEMORY = {
    "name": "WriteProcessMemory",
    "code": """
typedef LPVOID (WINAPI * WriteProcessMemory_t)(HANDLE, LPVOID, LPVOID, SIZE_T, SIZE_T*);
unsigned char sWriteProcessMemory[] = {{ {encryptedString} }};
unsigned int lenWriteProcessMemory = sizeof(sWriteProcessMemory);
WriteProcessMemory_t WriteProcessMemory_p;
    """,
    "mainCode": """
    {decryptionRoutine}
    WriteProcessMemory_p = (WriteProcessMemory_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sWriteProcessMemory);
    """,
    "dependencies": []
}

CREATEREMOTETHREAD = {
    "name": "CreateRemoteThread",
    "code": """
typedef LPVOID (WINAPI * CreateRemoteThread_t)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
unsigned char sCreateRemoteThread[] = {{ {encryptedString} }};
unsigned int lenCreateRemoteThread = sizeof(sCreateRemoteThread);
CreateRemoteThread_t CreateRemoteThread_p;
    """,
    "mainCode": """
    {decryptionRoutine}
    CreateRemoteThread_p = (CreateRemoteThread_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sCreateRemoteThread);
    """,
    "dependencies": []
}

VIRTUALPROTECT = {
    "name": "VirtualProtect",
    "code": """
typedef BOOL (WINAPI * VirtualProtect_t)(LPVOID, SIZE_T, DWORD, PDWORD);
unsigned char sVirtualProtect[] = {{ {encryptedString} }};
unsigned int lenVirtualProtect = sizeof(sVirtualProtect);
VirtualProtect_t VirtualProtect_p;
    """,
    "mainCode": """
    {decryptionRoutine}
    VirtualProtect_p = (VirtualProtect_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sVirtualProtect);
    """,
    "dependencies": []
}

CREATEFILEMAPPINGA = {
    "name": "CreateFileMappingA",
    "code": """
typedef HANDLE (WINAPI * CreateFileMappingA_t)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR);
unsigned char sCreateFileMappingA[] = {{ {encryptedString} }};
unsigned int lenCreateFileMappingA = sizeof(sCreateFileMappingA);
CreateFileMappingA_t CreateFileMappingA_p;
    """,
    "mainCode": """
    {decryptionRoutine}
    CreateFileMappingA_p = (CreateFileMappingA_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sCreateFileMappingA);
    """,
    "dependencies": []
}

MAPVIEWOFFILE = {
    "name": "MapViewOfFile",
    "code": """
typedef LPVOID (WINAPI * MapViewOfFile_t)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
unsigned char sMapViewOfFile[] = {{ {encryptedString} }};
unsigned int lenMapViewOfFile = sizeof(sMapViewOfFile);
MapViewOfFile_t MapViewOfFile_p;
    """,
    "mainCode": """
    {decryptionRoutine}
    MapViewOfFile_p = (MapViewOfFile_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sMapViewOfFile);
    """,
    "dependencies": []
}

UNMAPVIEWOFFILE = {
    "name": "UnmapViewOfFile",
    "code": """
typedef BOOL (WINAPI * UnmapViewOfFile_t)(LPVOID);
unsigned char sUnmapViewOfFile[] = {{ {encryptedString} }};
unsigned int lenUnmapViewOfFile = sizeof(sUnmapViewOfFile);
UnmapViewOfFile_t UnmapViewOfFile_p;
    """,
    "mainCode": """
    {decryptionRoutine}
    UnmapViewOfFile_p = (UnmapViewOfFile_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sUnmapViewOfFile);
    """,
    "dependencies": []
}

CREATE_PROCESS = {
    "name": "CreateProcessA",
    "code": """
typedef BOOL (WINAPI * CreateProcessA_t)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
unsigned char sCreateProcessA[] = {{ {encryptedString} }};
unsigned int lenCreateProcessA = sizeof(sCreateProcessA);
CreateProcessA_t CreateProcessA_p;
    """,
    "mainCode": """
    {decryptionRoutine}
    CreateProcessA_p = (CreateProcessA_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sCreateProcessA);
    """,
    "dependencies": []
}

INITIALIZE_PROC_THREAD_ATTRIBUTE_LIST = {
    "name": "InitializeProcThreadAttributeList",
    "code": """
typedef BOOL (WINAPI * InitializeProcThreadAttributeList_t)(LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD, PSIZE_T);
unsigned char sInitializeProcThreadAttributeList[] = {{ {encryptedString} }};
unsigned int lenInitializeProcThreadAttributeList = sizeof(sInitializeProcThreadAttributeList);
InitializeProcThreadAttributeList_t InitializeProcThreadAttributeList_p;
    """,
    "mainCode": """
    {decryptionRoutine}
    InitializeProcThreadAttributeList_p = (InitializeProcThreadAttributeList_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sInitializeProcThreadAttributeList);
    """,
    "dependencies": []
}

CREATE_TOOL_HELP_32_SNAPSHOT = {
    "name": "CreateToolhelp32Snapshot",
    "code": """
typedef HANDLE (WINAPI * CreateToolhelp32Snapshot_t)(DWORD, DWORD);
unsigned char sCreateToolhelp32Snapshot[] = {{ {encryptedString} }};
unsigned int lenCreateToolhelp32Snapshot = sizeof(sCreateToolhelp32Snapshot);
CreateToolhelp32Snapshot_t CreateToolhelp32Snapshot_p;
    """,
    "mainCode": """
    {decryptionRoutine}
    CreateToolhelp32Snapshot_p = (CreateToolhelp32Snapshot_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sCreateToolhelp32Snapshot);
    """,
    "dependencies": []
}

PROCESS_32_FIRST = {
    "name": "Process32First",
    "code": """
typedef BOOL (WINAPI * Process32First_t)(HANDLE, LPPROCESSENTRY32);
unsigned char sProcess32First[] = {{ {encryptedString} }};
unsigned int lenProcess32First = sizeof(sProcess32First);
Process32First_t Process32First_p;
    """,
    "mainCode": """
    {decryptionRoutine}
    Process32First_p = (Process32First_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sProcess32First);
    """,
    "dependencies": []
}

PROCESS_32_NEXT = {
    "name": "Process32Next",
    "code": """
typedef BOOL (WINAPI * Process32Next_t)(HANDLE, LPPROCESSENTRY32);
unsigned char sProcess32Next[] = {{ {encryptedString} }};
unsigned int lenProcess32Next = sizeof(sProcess32Next);
Process32Next_t Process32Next_p;
    """,
    "mainCode": """
    {decryptionRoutine}
    Process32Next_p = (Process32Next_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sProcess32Next);
    """,
    "dependencies": []
}

CLOSE_HANDLE = {
    "name": "CloseHandle",
    "code": """
typedef BOOL (WINAPI * CloseHandle_t)(HANDLE);
unsigned char sCloseHandle[] = {{ {encryptedString} }};
unsigned int lenCloseHandle = sizeof(sCloseHandle);
CloseHandle_t CloseHandle_p;
    """,
    "mainCode": """
    {decryptionRoutine}
    CloseHandle_p = (CloseHandle_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sCloseHandle);
    """,
    "dependencies": []
}


HEAP_ALLOC = {
    "name": "HeapAlloc",
    "code": """
typedef LPVOID (WINAPI * HeapAlloc_t)(HANDLE, DWORD, SIZE_T);
unsigned char sHeapAlloc[] = {{ {encryptedString} }};
unsigned int lenHeapAlloc = sizeof(sHeapAlloc);
HeapAlloc_t HeapAlloc_p;
    """,
    "mainCode": """
    {decryptionRoutine}
    HeapAlloc_p = (HeapAlloc_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sHeapAlloc);
    """,
    "dependencies": []
}


OPEN_PROCESS = {
    "name": "OpenProcess",
    "code": """
typedef HANDLE (WINAPI * OpenProcess_t)(DWORD, BOOL, DWORD);
unsigned char sOpenProcess[] = {{ {encryptedString} }};
unsigned int lenOpenProcess = sizeof(sOpenProcess);
OpenProcess_t OpenProcess_p;
    """,
    "mainCode": """
    {decryptionRoutine}
    OpenProcess_p = (OpenProcess_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sOpenProcess);
    """,
    "dependencies": []
}

UPDATE_PROC_THREAD_ATTRIBUTE = {
    "name": "UpdateProcThreadAttribute",
    "code": """
typedef BOOL (WINAPI * UpdateProcThreadAttribute_t)(LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD_PTR, PVOID, SIZE_T, PVOID, PSIZE_T);
unsigned char sUpdateProcThreadAttribute[] = {{ {encryptedString} }};
unsigned int lenUpdateProcThreadAttribute = sizeof(sUpdateProcThreadAttribute);
UpdateProcThreadAttribute_t UpdateProcThreadAttribute_p;
    """,
    "mainCode": """
    {decryptionRoutine}
    UpdateProcThreadAttribute_p = (UpdateProcThreadAttribute_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sUpdateProcThreadAttribute);
    """,
    "dependencies": []
}

DELETE_PROC_THREAD_ATTRIBUTE_LIST = {
    "name": "DeleteProcThreadAttributeList",
    "code": """
typedef void (WINAPI * DeleteProcThreadAttributeList_t)(LPPROC_THREAD_ATTRIBUTE_LIST);
unsigned char sDeleteProcThreadAttributeList[] = {{ {encryptedString} }};
unsigned int lenDeleteProcThreadAttributeList = sizeof(sDeleteProcThreadAttributeList);
DeleteProcThreadAttributeList_t DeleteProcThreadAttributeList_p;
    """,
    "mainCode": """
    {decryptionRoutine}
    DeleteProcThreadAttributeList_p = (DeleteProcThreadAttributeList_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sDeleteProcThreadAttributeList);
    """,
    "dependencies": []
}

WAIT_FOR_SINGLE_OBJECT = {
    "name": "WaitForSingleObject",
    "code": """
typedef DWORD (WINAPI * WaitForSingleObject_t)(HANDLE, DWORD);
unsigned char sWaitForSingleObject[] = {{ {encryptedString} }};
unsigned int lenWaitForSingleObject = sizeof(sWaitForSingleObject);
WaitForSingleObject_t WaitForSingleObject_p;
    """,
    "mainCode": """
    {decryptionRoutine}
    WaitForSingleObject_p = (WaitForSingleObject_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sWaitForSingleObject);
    """,
    "dependencies": []
}

READ_PROCESS_MEMORY = {
    "name": "ReadProcessMemory",
    "code": """
typedef BOOL (WINAPI * ReadProcessMemory_t)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T *);
unsigned char sReadProcessMemory[] = {{ {encryptedString} }};
unsigned int lenReadProcessMemory = sizeof(sReadProcessMemory);
ReadProcessMemory_t ReadProcessMemory_p;
    """,
    "mainCode": """
    {decryptionRoutine}
    ReadProcessMemory_p = (ReadProcessMemory_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sReadProcessMemory);
    """,
    "dependencies": []
}

TERMINATE_PROCESS = {
    "name": "TerminateProcess",
    "code": """
typedef BOOL (WINAPI * TerminateProcess_t)(HANDLE, UINT);
unsigned char sTerminateProcess[] = {{ {encryptedString} }};
unsigned int lenTerminateProcess = sizeof(sTerminateProcess);
TerminateProcess_t TerminateProcess_p;
    """,
    "mainCode": """
    {decryptionRoutine}
    TerminateProcess_p = (TerminateProcess_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sTerminateProcess);
    """,
    "dependencies": []
}

VIRTUAL_FREE = {
    "name": "VirtualFree",
    "code": """
typedef BOOL (WINAPI * VirtualFree_t)(LPVOID, SIZE_T, DWORD);
unsigned char sVirtualFree[] = {{ {encryptedString} }};
unsigned int lenVirtualFree = sizeof(sVirtualFree);
VirtualFree_t VirtualFree_p;
    """,
    "mainCode": """
    {decryptionRoutine}
    VirtualFree_p = (VirtualFree_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sVirtualFree);
    """,
    "dependencies": []
}

CREATE_FILE = {
    "name": "CreateFileA",
    "code": """
typedef HANDLE (WINAPI * CreateFileA_t)(LPCTSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
unsigned char sCreateFileA[] = {{ {encryptedString} }};
unsigned int lenCreateFileA = sizeof(sCreateFileA);
CreateFileA_t CreateFileA_p;
    """,
    "mainCode": """
    {decryptionRoutine}
    CreateFileA_p = (CreateFileA_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sCreateFileA);
    """,
    "dependencies": []
}

VIRTUAL_ALLOC_EX_NUMA = {
    "name": "VirtualAllocExNuma",
    "code": """
typedef LPVOID (WINAPI * VirtualAllocExNuma_t)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD, DWORD);
unsigned char sVirtualAllocExNuma[] = {{ {encryptedString} }};
unsigned int lenVirtualAllocExNuma = sizeof(sVirtualAllocExNuma);
VirtualAllocExNuma_t VirtualAllocExNuma_p;
    """,
    "mainCode": """
    {decryptionRoutine}
    VirtualAllocExNuma_p = (VirtualAllocExNuma_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sVirtualAllocExNuma);
    """,
    "dependencies": []
}