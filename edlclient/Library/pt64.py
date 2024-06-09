import struct

"""
only supports 4KB granule w/ 25<=TnSZ<=33
https://armv8-ref.codingbelief.com/en/chapter_d4/d42_7_the_algorithm_for_finding_the_translation_table_entries.html

"""


def get_level_index(va, level):
    if level == 1:
        return (va >> 30) & 0x3F

    if level == 2:
        return (va >> 21) & 0x1FF

    if level == 3:
        return (va >> 12) & 0x1FF

    raise NotImplementedError()


def get_level_bits(level, tnsz):
    if level == 1:
        return 37 - tnsz + 26 + 1 - 30

    if level == 2:
        return 9

    if level == 3:
        return 9

    raise NotImplementedError()


def get_level_size(tnsz, level):
    return 2 ** get_level_bits(level, tnsz) * 8


def get_va_for_level(va, index, level):
    if level == 1:
        return va + (index << 30)

    if level == 2:
        return va + (index << 21)

    if level == 3:
        return va + (index << 12)

    return va


def parse_pt(data, base, tnsz, level=1):
    i = 0
    entries = []
    while i < min(len(data), get_level_size(tnsz, level)):
        mentry = struct.unpack("<Q", data[i:i + 8])[0]

        f = get_fld(mentry, level)
        if f is None:
            i += 8
            continue
        va = get_va_for_level(base, int(i / 8), level)
        if f != 'UNSUPPORTED' and f.apx == 0 and f.ap == 3 and f.xn == 0:
            print("%016x %s - WX !!" % (va, f))
        else:
            print("%016x %s" % (va, f))

        entries.append((va, f))
        i += 8

    return entries


def get_fld(mfld, level):
    s = mfld & 3
    if s == 0:
        return None

    if s == 1:
        return block_entry4k(mfld, level)

    if s == 2:
        return None

    if s == 3:
        return table_entry4k(mfld, level)
    return None


class descriptor(object):
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


class entry(fld):
    def __init__(self, desc, level):
        self.level = level
        self.nshigh = desc >> 63
        self.apx = (desc >> 61) & 3
        self.xn = (desc >> 60) & 1
        self.pxn = (desc >> 59) & 1
        self.attrindex = (desc >> 2) & 7
        self.ns = (desc >> 5) & 1
        self.ap = (desc >> 6) & 3
        self.sh = (desc >> 8) & 3
        self.af = (desc >> 10) & 1
        self.nG = (desc >> 11) & 1


class entry4k(entry):
    def __init__(self, desc, level):
        entry.__init__(self, desc, level)
        self.output = ((desc & 0xFFFFFFFFFFFF) >> 12) << 12


class fault_entry(fld):

    def get_name(self):
        return "FAULT"


class block_entry4k(entry4k):

    def __init__(self, desc, level):
        entry4k.__init__(self, desc, level)
        # shift = 39-9*level
        # self.output = ((desc & 0xFFFFFFFFFFFFL) >> shift) << shift

    def get_name(self):
        return "BLOCK4"


class table_entry4k(entry4k):

    def __init__(self, desc, level):
        entry4k.__init__(self, desc, level)

    def get_name(self):
        return "TABLE4"
