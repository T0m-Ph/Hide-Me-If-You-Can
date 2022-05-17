WINDOWS_H = {
    "name": "WINDOWS_H",
    "code": "#include <Windows.h>",
    "dependencies": []
}

CRYPT_32_LIB = {
    "name": "CRYPT_32_LIB",
    "code": "#pragma comment (lib, \"crypt32.lib\")",
    "dependencies": [WINDOWS_H]
}

ADVAPI_LIB = {
    "name": "ADVAPI_LIB",
    "code": "#pragma comment (lib, \"advapi32\")",
    "dependencies": [WINDOWS_H]
}

WINCRYPT_H = {
    "name": "WINCRYPT_H",
    "code": "#include <wincrypt.h>",
    "dependencies": [WINDOWS_H, CRYPT_32_LIB, ADVAPI_LIB]
}

TLHELP32_H = {
    "name": "TLHELP32_H",
    "code": "#include <tlhelp32.h>",
    "dependencies": [WINDOWS_H]
}

SKERNEL32 = {
    "name": "SKERNEL32",
    "code": "unsigned char sKernel32[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0x0 };",
    "dependencies": []
}

# def getHeaderCode(header, alreadyIncludedHeaders):
#     code = ""
#     includedDependencies = set()
#     for dep in header['dependencies']:
#         if dep["name"] not in alreadyIncludedHeaders:
#             depCode, depDependencies = getHeaderCode(dep, alreadyIncludedHeaders)
#             code += depCode
#             code += "\n"
#             includedDependencies.update(depDependencies)
#     code += header['code']
#     for dependency in header['dependencies']:
#         includedDependencies.add(dependency["name"])
#     return code, includedDependencies
