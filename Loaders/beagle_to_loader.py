#!/usr/bin/env python3
# Beagle to EDL Loader (c) B.Kerler 2021

import os,sys
from struct import unpack

def main():
	if len(sys.argv)<2:
		print("Usage: ./beagle_to_loader.py [beagle_log.bin] [loader.elf]")
		sys.exit(0)
	with open(sys.argv[1],"rb") as rf:
		data=rf.read()
		outdata=bytearray()
		with open(sys.argv[2], "wb") as wf:
			while True:
				idx=data.find(b"\x03\x00\x00\x00\x14\x00\x00\x00\x0D\x00\x00\x00")
				if idx==-1:
					break
				else:
					cmd,tlen,slen,offset,length=unpack("<IIIII",data[idx:idx+0x14])
					data = data[idx + 0x14:]
					print("Offset : %08X Length: %08X" %(offset,length))
					while (len(outdata)<offset+length):
						outdata.append(0xFF)
					outdata[offset:offset+length]=data[:length]
			wf.write(outdata)

		print("Done.")
		
if __name__=="__main__":
	main()