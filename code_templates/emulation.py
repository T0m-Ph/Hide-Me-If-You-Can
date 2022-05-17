from code_templates import headers
from code_templates import winapi

def unimplementedAPIs():
    requiredHeaders = []
    requiredWinApis = [winapi.VIRTUAL_ALLOC_EX_NUMA]

    codeBase =  ""

    main = """
    LPVOID mem = VirtualAllocExNuma_p(
        GetCurrentProcess(),
        NULL,
        0x1000,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE,
        0
    );
    if (mem == NULL){
        return 0;
    }
    """

    return requiredHeaders, requiredWinApis, codeBase, main