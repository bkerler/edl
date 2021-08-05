import struct


def get_n(x):
    return int(x[6:8] + x[4:6] + x[2:4] + x[0:2], 16)


def parse_pt(data):
    va = 0
    entries = []
    while va < len(data):
        entry = struct.unpack("<L", data[va:va + 4])[0]
        f = get_fld(entry)

        if f is None:
            va += 4
            continue

        entries.append((int(va / 4) << 20, f))
        print("%08x %s" % ((int(va / 4) << 20), str(f)))
        va += 4

    return entries


def parse_spt(data, base):
    va = 0
    while va < 0x400:
        entry = struct.unpack("<L", data[va:va + 4])[0]

        f = get_sld(entry)
        if f != 'UNSUPPORTED' and f.apx == 0 and f.ap == 3 and f.nx == 0:
            print("%08x %s - WX !!" % (base + (int(va / 4) << 12), f))
        else:
            print("%08x %s" % (base + (int(va / 4) << 12), f))
        va += 4


def get_fld(mfld):
    s = mfld & 3
    if s == 0:
        return fault_desc(mfld)

    if s == 1:
        return pt_desc(mfld)

    if s == 2:
        return section_desc(mfld)

    if s == 3:
        return reserved_desc(mfld)
    return None


def get_sld(msld):
    s = msld & 3
    if s == 1:
        return sld_lp(msld)

    if s > 1:
        return sld_xsp(msld)

    return "UNSUPPORTED"


class descriptor(object):
    def __init__(self, mfld):
        pass

    def get_name(self):
        pass

    def __repr__(self):
        s = "%8s " % self.get_name()
        for attr, value in self.__dict__.items():
            try:
                s += "%s=%s, " % (attr, hex(value))
            except:
                s += "%s=%s, " % (attr, value)

        return s


class fld(descriptor):
    pass


class fault_desc(fld):

    def get_name(self):
        return "FAULT"


class reserved_desc(fld):

    def get_name(self):
        return "RESERVED"


class pt_desc(fld):

    def __init__(self, desc):
        self.coarse_base = (desc >> 10) << 10
        self.p = (desc >> 9) & 1
        self.domain = (desc >> 5) & 15
        self.sbz1 = (desc >> 4) & 1
        self.ns = (desc >> 3) & 1
        self.sbz2 = (desc >> 2) & 1

    def get_name(self):
        return "PT"


class section_desc(fld):
    def __init__(self, desc):
        self.section_base = (desc >> 20) << 20
        self.ns = (desc >> 19) & 1
        self.zero = ns = (desc >> 18) & 1
        self.ng = (desc >> 17) & 1
        self.s = (desc >> 16) & 1
        self.apx = (desc >> 15) & 1
        self.tex = (desc >> 12) & 7
        self.ap = (desc >> 10) & 3
        self.p = (desc >> 9) & 1
        self.domain = (desc >> 5) & 15
        self.nx = (desc >> 4) & 1
        self.c = (desc >> 3) & 1
        self.b = (desc >> 2) & 1

    def get_name(self):
        return "SECTION"


class sld(descriptor):
    pass


class sld_lp(sld):

    def __init__(self, desc):
        self.page_base = (desc >> 16) << 16
        self.nx = (desc >> 15) & 1
        self.tex = (desc >> 12) & 7
        self.ng = (desc >> 11) & 1
        self.s = (desc >> 10) & 1
        self.apx = (desc >> 9) & 1
        self.sbz = (desc >> 6) & 7
        self.ap = (desc >> 4) & 3
        self.c = (desc >> 3) & 1
        self.b = (desc >> 2) & 1

    def get_name(self):
        return "LARGEPAGE"


class sld_xsp(sld):

    def __init__(self, desc):
        self.desc = desc
        self.page_base = (desc >> 12) << 12
        self.ng = (desc >> 11) & 1
        self.s = (desc >> 10) & 1
        self.apx = (desc >> 9) & 1
        self.tex = (desc >> 6) & 7
        self.ap = (desc >> 4) & 3
        self.c = (desc >> 3) & 1
        self.b = (desc >> 2) & 1
        self.nx = desc & 1

    def get_name(self):
        return "XSMALLPAGE"
