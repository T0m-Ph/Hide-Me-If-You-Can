# Hide-Me-If-You-Can

This github repository is a small project to try and implement some AV bypassing techniques.

## Features

As of now this project allows to:
- Obfuscate win32 API calls
- Encrypt payloads
- Unhook ntdll
- PPID spoofing

## Usage

This project uses python to compile C++ code. it requires uses the MSVC compiler, which is installed with the C++ tools from Visual Studio (see [Microsoft Documentation](https://docs.microsoft.com/en-us/cpp/build/reference/compiler-options?view=msvc-170))

```
usage: hmiyc.py generate [-h] --payload PAYLOAD --injectionTarget INJECTIONTARGET [--encryption {XOR,AES}] [--unhook {freshCopy,perunsFart}] [--detectEmulation]
options:
-h, --help                          Show this help message and exit
--payload PAYLOAD                   The file containing the binary payload to embed.
--injectionTarget INJECTIONTARGET   The name of the process to inject into.
--encryption {XOR,AES}              The algorithm to use to encrypt the paylod. The payload will not be encrypted if this argument is not specified.
--unhook {freshCopy,perunsFart}     The technique to use to remove hooks from ntdll.
--detectEmulation                   Attempts to detect emulation by studying the behavior of commonly unimplemented win32 APIs. 


usage: hmiyc.py spoof [-h] --parentProcess PARENTPROCESS --childProcess CHILDPROCESS
options:
-h, --help          show this help message and exit
--parentProcess     PARENTPROCESS
--childProcess      CHILDPROCESS
```

## Next features

- Port to Linux
- Add unit testing
- Additional injection techniques, see [here](https://www.ired.team/offensive-security/code-injection-process-injection)
- Direct syscalls
- Allow to embed paylod in different sections
- Allow generation in different formats (DLL, service executable etc.)
- Executable signature
- Executable properties
- Allow to continue execution in the same thread (no migration)
- Improve emulation detection. Potential starting point [here](https://reverseengineering.stackexchange.com/questions/2805/detecting-an-emulator-using-the-windows-api)
- So much more