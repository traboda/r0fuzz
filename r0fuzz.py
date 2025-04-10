from core.logger import get_logger

from core.extract import Extractor
from core.mut_fuzzing import PackGen
from core.dumb_fuzzing import DFuzz
from core.gen_fuzzing import GFuzz
from core.replayer import Replayer

# Default imports
import argparse
import os
import sys
from colorama import init
from termcolor import cprint
from pyfiglet import figlet_format


class r0fuzz(object):

    supported_protocol = ["modbus"]

    def __init__(self, args):
        self.protocol = args.target
        self.command = args.command
        self.log_level = args.verbosity
        self.ip = args.ip
        self.port = args.port

        if self.command == "dumb":
            self.dfuzz = DFuzz(self)

        elif self.command == "mutate":
            self.seed = os.path.join(os.getcwd(), args.seed)
            self.extractor = Extractor(self)
            self.packgen = PackGen(self)

        elif self.command == "generate":
            self.gfuzz = GFuzz(self)
            
        elif self.command == "replay":
            self.crash_log = os.path.join(os.getcwd(), args.logfile)
            self.replayer = Replayer(self)

        if not self._sanity_check():
            logging.critical("[+] r0fuzz failed to init")
            sys.exit(-1)

    def _sanity_check(self) -> bool:
        """Verify the arguments passed"""

        if self.protocol.lower() not in self.supported_protocol:
            logging.error("[-] %s protocol is not supported", self.protocol)
            return False
        logging.debug("[+] Fuzzing %s protocol", self.protocol)

        if self.command == "mutate":
            if not os.path.isfile(self.seed):
                logging.error("[-] The seed file is not found at %s", self.seed)
                return False
            logging.debug("[+] The input file is at %s", self.seed)

        return True


def main():
    global logging

    init(strip=not sys.stdout.isatty())  # strip colors if stdout is redirected
    cprint(
        figlet_format("R0FUZZ", font="doom", width=110), "yellow", attrs=["bold"]
    )

    parser = argparse.ArgumentParser(
        description="A fuzzer for OT-network protocols"
    )
    subparser = parser.add_subparsers(dest="command")
    
    dumb = subparser.add_parser("dumb", help="Dumb fuzzing")
    mutate = subparser.add_parser("mutate", help="Mutation-based fuzzing")
    generate = subparser.add_parser("generate", help="Generation-based fuzzing")
    replay = subparser.add_parser("replay", help="Replay the packets")
    
    parser.add_argument(
        "-t", "--target", help="Target Protocol [modbus/opcua]", type=str, required=True
    )
    parser.add_argument("-v", "--verbosity", help="Log level", action="count")
    parser.add_argument("-i", "--ip", help="Target IP Address [= 127.0.0.1]", default="127.0.0.1")
    parser.add_argument("-p", "--port", help="Target Port [= 1234]", type=int, default=1234)
    
    mutate.add_argument(
        "-s", "--seed", help="Sample input file", type=str, required=True
    )

    replay.add_argument(
        "-log", "--logfile", help="Crash Log file", type=str, required=True
    )
    
    args = parser.parse_args()

    logging = get_logger("r0fuzz", args.verbosity)

    r0obj = r0fuzz(args)

    if r0obj.command == "mutate":
        if r0obj.protocol == "modbus":
            extracted_fields = r0obj.extractor.extract_fields_from_packets(r0obj.protocol)
            r0obj.packgen.formPacket(extracted_fields)
            logging.info("[+] Generated fields")

    elif r0obj.command == "dumb":
        if not r0obj.dfuzz.dumb_fuzzing():
            logging.error("[X] Failed to dumb fuzz the target")
            sys.exit(-1)

    elif r0obj.command == "generate":
        if r0obj.protocol == "modbus":
            r0obj.gfuzz.modbus_fuzz()
        elif r0obj.protocol == "opcua":
            print("WIP")
            sys.exit()
            
    elif r0obj.command == "replay":
        logging.info("[+] Replaying Log Packets")
        r0obj.replayer.replayPackets()
            
    else:
        print("Invalid command")


if __name__ == "__main__":
    logging = None
    main()
