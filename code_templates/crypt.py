from code_templates import headers

def xor():
	requiredHeaders = [headers.WINDOWS_H]
	codeBase = """
void XORcrypt(char str2xor[], size_t len, char key[], size_t keylen) {
	int i;

	for (i = 0; i < len; i++) {
		str2xor[i] = (BYTE)str2xor[i] ^ key[i % keylen];
	}
}
	"""
	return requiredHeaders, codeBase


def xorDecryptionRoutine(toDecryptName, toDecryptLengthName, keyName, keyLengthName):
	return """
	XORcrypt((char *) {toDecryptName}, {toDecryptLengthName}, (char *) {keyName}, {keyLengthName});
	""".format(toDecryptName=toDecryptName, toDecryptLengthName=toDecryptLengthName, keyName=keyName, keyLengthName=keyLengthName)


def aesDecrypt():
	requiredHeaders = [headers.WINCRYPT_H]
	codeBase = """
int AESDecrypt(char * payload, unsigned int payload_len, char * key, size_t keylen) {
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;
	HCRYPTKEY hKey;

	if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
			return -1;
	}
	if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)){
			return -1;
	}
	if (!CryptHashData(hHash, (BYTE*) key, (DWORD) keylen, 0)){
			return -1;              
	}
	if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0,&hKey)){
			return -1;
	}
	
	if (!CryptDecrypt(hKey, (HCRYPTHASH) NULL, 0, 0, (BYTE *) payload, (DWORD *) &payload_len)){
			return -1;
	}
	
	CryptReleaseContext(hProv, 0);
	CryptDestroyHash(hHash);
	CryptDestroyKey(hKey);
	
	return 0;
}
	"""

	return requiredHeaders, codeBase

# TODO: Add key with decryption routine
def aesDecryptionRoutine(toDecryptName, toDecryptLengthName, keyName, keyLengthName):
	return """
	AESDecrypt((char *) {toDecryptName}, {toDecryptLengthName}, (char *) {keyName}, {keyLengthName});
	""".format(toDecryptName=toDecryptName, toDecryptLengthName=toDecryptLengthName, keyName=keyName, keyLengthName=keyLengthName)