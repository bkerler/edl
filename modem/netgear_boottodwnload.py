#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# (c) B.Kerler 2020 under MIT license
# If you use my code, make sure you refer to my name
# If you want to use in a commercial product, ask me before integrating it

def sendcmd(tn,cmd):
    tn.write(bytes(cmd,'utf-8')+b"\n")
    time.sleep(0.05)
    return tn.read_eager().strip().decode('utf-8')

def main():
    from telnetlib import Telnet
    tn = Telnet("localhost", 5510)
    print("Sending download mode command to localhost:5510")
    print(sendcmd(tn,"AT!BOOTHOLD\r"))
    print(sendcmd(tn,'AT!QPSTDLOAD\r'))
    print("Done switching to download mode")
    tn.close()    

if __name__=="__main__":
    main()