from enum import Enum

# Argument parsing
COMMAND_GENERATE = "generate"
COMMAND_SPOOF = "spoof"



KEY_LENGTH_MIN = 10
KEY_LENGTH_MAX = 50

VARIABLE_NAME_LENGHT_MIN = 3
VARIABLE_NAME_LENGHT_MAX = 15

NTDLL_PATH = "c:\\windows\\system32\\ntdll.dll" + "\x00"

RESULTING_EXECUTABLE_NAME = "hmiyc"

class Encryption(Enum):
    XOR = "ENCRYPTION_XOR"
    AES = "ENCRYPTION_AES"

class Injection(Enum):
    CLASSIC = "INJECTION_CLASSIC"

class Unhooking(Enum):
    freshCopy = "UNHOOKING_FRESH_COPY"
    perunsFart = "UNHOOKING_PERUNS_FART"