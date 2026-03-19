#!/usr/bin/python3

import argparse
from scapy.all import *

"""
Found an issue with iwlwifi on the Intel Alder Lake-P PCH CNVi rev1 on Ubuntu 24 and Tiger Lake PCH CNVi rev11 on Ubuntu 22.
This is not seen with mt7921u on the MediaTek Inc. Wireless_Device on either 22 or 24.

Reverting can be done with the printed debug to a scapy object where X is the debug string:
    RadioTap(binascii.unhexlify(X))
"""

class Fox(object):
    """ Traces the source of a given 802.11 transmission based on the specs from
    IEEE in reference to ADDRs 1-4 for the source of a given frame that has been
    transmitted.
    """
    __slots__ = ['i', 't', 'spC', 'spA', 'freqDict']
    def __init__(self, i, t):
        self.i = i
        self.t = t
        self.spC = 4
        self.spA = ['|',
                    '/',
                    '~',
                    '\\',
                    '*']
        self.freqDict = {2412: 1,
                         2417: 2,
                         2422: 3,
                         2427: 4,
                         2432: 5,
                         2437: 6,
                         2442: 7,
                         2447: 8,
                         2452: 9,
                         2457: 10,
                         2462: 11,
                         2467: 12,
                         2472: 13,
                         2484: 14,
                         5180: 36,
                         5200: 40,
                         5210: 42,
                         5220: 44,
                         5240: 48,
                         5250: 50,
                         5260: 52,
                         5290: 58,
                         5300: 60,
                         5320: 64,
                         5745: 149,
                         5760: 152,
                         5765: 153,
                         5785: 157,
                         5800: 160,
                         5805: 161,
                         5825: 165}


    def lFilter(self, tgtMac):
        mac = tgtMac.lower()
        def tailChaser(frame):
            if not hasattr(frame, 'FCfield'):
                ### DEBUG
                # print(hexstr(frame, onlyhex = 1).replace(' ', ''))
                return False
            fc = frame.FCfield
            if fc.from_DS and not fc.to_DS:
                return frame.addr3 == mac
            return frame.addr2 == mac
        return tailChaser


    def pHandler(self, tgtMac):
        """ prn """
        mac = tgtMac.lower()
        def snarf(frame):
            try:
                print(f'{self.spinner()} {mac} --> {self.freqDict.get(frame.ChannelFrequency)} @ {frame.dBm_AntSignal}' )
            except Exception as E:
                print(E)
        return snarf


    def spinner(self):
        """ Track and return the spins """
        ## Grab orig value
        sp = self.spA[self.spC]
        self.spC += 1

        ## Increase or set to 0 new value
        if self.spC >= len(self.spA):
            self.spC = 0
        return sp


def main(args):
    """Grab a fox by the tail"""
    fx = Fox(args.i, args.t)
    lFilter = fx.lFilter(args.t)
    pHandler = fx.pHandler(args.t)
    mNic = args.i
    sniff(iface = mNic, prn = pHandler, lfilter = lFilter, store = 0)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description = 'Fox hunting for 802.11')
    parser.add_argument('-t',
                        metavar = 'MAC to listen for',
                        help = 'MAC to listen for', required = True)
    parser.add_argument('-i',
                        metavar = 'NIC to sniff with',
                        help = 'NIC to sniff with', required = True)
    args = parser.parse_args()
    main(args)
