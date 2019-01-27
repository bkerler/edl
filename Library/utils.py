import sys
import struct
from capstone import *
from keystone import *
import codecs

class elf:
    class memorysegment:
        phy_addr=0
        virt_start_addr=0
        virt_end_addr=0
        file_start_addr=0
        file_end_addr=0


    def __init__(self,indata):
        self.data=indata
        self.header, self.pentry = self.parse()
        self.memorylayout = []
        for entry in self.pentry:
            ms=self.memorysegment()
            ms.phy_addr=entry.phy_addr
            ms.virt_start_addr=entry.virt_addr
            ms.virt_end_addr=entry.virt_addr+entry.seg_mem_len
            ms.file_start_addr=entry.from_file
            ms.file_end_addr=entry.from_file+entry.seg_file_len
            self.memorylayout.append(ms)

    def getfileoffset(self,offset):
        for memsegment in self.memorylayout:
            if offset<=memsegment.virt_end_addr and offset>=memsegment.virt_start_addr:
                return offset-memsegment.virt_start_addr+memsegment.file_start_addr
        return None

    def getvirtaddr(self,fileoffset):
        for memsegment in self.memorylayout:
            if fileoffset<=memsegment.file_end_addr and fileoffset>=memsegment.file_start_addr:
                return memsegment.virt_start_addr+fileoffset-memsegment.file_start_addr
        return None

    def getbaseaddr(self,offset):
        for memsegment in self.memorylayout:
            if offset<=memsegment.virt_end_addr and offset>=memsegment.virt_start_addr:
                return memsegment.virt_start_addr
        return None

    class programentry:
        p_type = 0
        from_file = 0
        virt_addr = 0
        phy_addr = 0
        seg_file_len = 0
        seg_mem_len = 0
        p_flags = 0
        p_align = 0

    def parse_programentry(self,dat):
        pe = self.programentry()
        if self.elfclass==1:
            (pe.p_type,pe.from_file,pe.virt_addr,pe.phy_addr,pe.seg_file_len,pe.seg_mem_len,pe.p_flags,pe.p_align) = struct.unpack("<IIIIIIII",dat)
        elif self.elfclass==2:
            (pe.p_type, pe.p_flags, pe.from_file, pe.virt_addr, pe.phy_addr, pe.seg_file_len, pe.seg_mem_len,pe.p_align) = struct.unpack("<IIQQQQQQ", dat)
        return pe

    def parse(self):
        self.elfclass=self.data[4]
        if self.elfclass==1: #32Bit
            start=0x28
        elif self.elfclass==2: #64Bit
            start=0x34
        elfheadersize, programheaderentrysize, programheaderentrycount = struct.unpack("<HHH", self.data[start:start + 3 * 2])
        programheadersize = programheaderentrysize * programheaderentrycount
        header = self.data[0:elfheadersize+programheadersize]
        pentry=[]
        for i in range(0,programheaderentrycount):
            start=elfheadersize+(i*programheaderentrysize)
            end=start+programheaderentrysize
            pentry.append(self.parse_programentry(self.data[start:end]))

        return [header,pentry]



class patchtools:
    cstyle=False
    bDebug=False

    def __init__(self, bDebug=False):
        self.bDebug = bDebug

    def has_bad_uart_chars(self, data):
        badchars = [b'\x00', b'\n', b'\r', b'\x08', b'\x7f', b'\x20', b'\x09']
        bad = False
        for idx, c in enumerate(data):
            c = bytes([c])
            if c in badchars:
                return True
        return False

    def generate_offset(self, offset):
        div = 0
        found = False
        while (found == False and div < 0x606):
            data = struct.pack("<I", offset + div)
            data2 = struct.pack("<H", div)
            badchars = self.has_bad_uart_chars(data)
            if not (badchars):
                badchars = self.has_bad_uart_chars(data2)
                if not (badchars):
                    return div
            div += 4

        # if div is not found within positive offset, try negative offset
        div = 0
        while (found == False and div < 0x606):
            data = struct.pack("<I", offset - div)
            data2 = struct.pack("<H", div)
            badchars = self.has_bad_uart_chars(data)
            if not (badchars):
                badchars = self.has_bad_uart_chars(data2)
                if not (badchars):
                    return -div
                    break
            div += 4
        return 0

    #Usage: offset, "X24"
    def generate_offset_asm(self, offset, reg):
        div = self.generate_offset(offset)
        abase = ((offset + div) & 0xFFFF0000) >> 16
        a = ((offset + div) & 0xFFFF)
        str = ""
        if (div > 0):
            str += "# " + hex(offset) + "\n"
            str += "mov " + reg + ", #" + hex(a) + ";\n"
            str += "movk " + reg + ", #" + hex(abase) + ", LSL#16;\n"
            str += "sub  " + reg + ", " + reg + ", #" + hex(div) + ";\n"
        else:
            str += "# " + hex(offset) + "\n"
            str += "mov " + reg + ", #" + hex(a) + ";\n"
            str += "movk " + reg + ", #" + hex(abase) + ", LSL#16;\n"
            str += "add  " + reg + ", " + reg + ", #" + hex(-div) + ";\n"
        return str

    def UART_validSC(self, sc):
        badchars = [b'\x00', b'\n', b'\r', b'\x08', b'\x7f', b'\x20', b'\x09']
        for idx, c in enumerate(sc):
            c = bytes([c])
            if c in badchars:
                print("bad char 0x%s in SC at offset %d, opcode # %d!\n" % (codecs.encode(c, 'hex'), idx, idx / 4))
                print(codecs.encode(sc, 'hex'))
                return False
        return True

    def disasm(self, code, size):
        cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        instr = []
        for i in cs.disasm(code, size):
            # print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
            instr.append("%s\t%s" % (i.mnemonic, i.op_str))
        return instr

    def assembler(self, code):
        ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
        if self.bDebug:
            try:
                encoding, count = ks.asm(code)
            except KsError as e:
                print(e)
                print(e.stat_count)
                print(code[e.stat_count:e.stat_count + 10])
                exit(0)
                if self.bDebug:
                    # walk every line to find the (first) error
                    for idx, line in enumerate(code.splitlines()):
                        print("%02d: %s" % (idx, line))
                        if len(line) and line[0] != '.':
                            try:
                                encoding, count = ks.asm(line)
                            except:
                                print("bummer")
                else:
                    exit(0)
        else:
            encoding, count = ks.asm(code)

        sc = ""
        count = 0
        out = ""
        for i in encoding:
            if self.cstyle:
                out += ("\\x%02x" % i)
            else:
                out += ("%02x" % i)
            sc += "%02x" % i

            count += 1
            # if bDebug and count % 4 == 0:
            #    out += ("\n")

        return out

    def find_binary(self,data,strf,pos=0):
        t=strf.split(b".")
        pre=0
        offsets=[]
        while (pre!=-1):
            pre = data[pos:].find(t[0],pre)
            if (pre==-1):
                if len(offsets)>0:
                    for offset in offsets:
                        error = 0
                        rt = offset + len(t[0])
                        for i in range(1, len(t)):
                            if (t[i] == b''):
                                rt += 1
                                continue
                            rt += 1
                            prep = data[rt:].find(t[i])
                            if (prep != 0):
                                error = 1
                                break
                            rt += len(t[i])
                        if error == 0:
                            return offset
                else:
                    return None
            else:
                offsets.append(pre)
                pre+=1
        return None

def read_object(data, definition):
    '''
    Unpacks a structure using the given data and definition.
    '''
    obj = {}
    object_size = 0
    pos=0
    for (name, stype) in definition:
        object_size += struct.calcsize(stype)
        obj[name] = struct.unpack(stype, data[pos:pos+struct.calcsize(stype)])[0]
        pos+=struct.calcsize(stype)
    obj['object_size'] = object_size
    obj['raw_data'] = data
    return obj

def print_progress(iteration, total, prefix='', suffix='', decimals=1, bar_length=100):
    """
    Call in a loop to create terminal progress bar
    @params:
        iteration   - Required  : current iteration (Int)
        total       - Required  : total iterations (Int)
        prefix      - Optional  : prefix string (Str)
        suffix      - Optional  : suffix string (Str)
        decimals    - Optional  : positive number of decimals in percent complete (Int)
        bar_length  - Optional  : character length of bar (Int)
    """
    str_format = "{0:." + str(decimals) + "f}"
    percents = str_format.format(100 * (iteration / float(total)))
    filled_length = int(round(bar_length * iteration / float(total)))
    bar = '█' * filled_length + '-' * (bar_length - filled_length)

    sys.stdout.write('\r%s |%s| %s%s %s' % (prefix, bar, percents, '%', suffix)),

    if iteration == total:
        sys.stdout.write('\n')
    sys.stdout.flush()
