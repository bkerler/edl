#!/usr/bin/env python3
import os
import sys
from os import walk
import hashlib
import struct
from shutil import copyfile
from Config.qualcomm_config import sochw, msmids
from Library.utils import elf
from Library.sahara import convertmsmid

vendor = {}
vendor["0000"] = "Qualcomm     "
vendor["0001"] = "Sony/Wingtech"
vendor["0004"] = "ZTE          "
vendor["0015"] = "Huawei       "
vendor["0017"] = "Lenovo       "
vendor["0029"] = "Asus         "
vendor["0030"] = "Haier        "
vendor["0031"] = "LG           "
vendor["0042"] = "Alcatel      "
vendor["0045"] = "Nokia        "
vendor["0048"] = "YuLong       "
vendor["0168"] = "Motorola     "
vendor["01B0"] = "Motorola     "
vendor["0208"] = "Motorola     "
vendor["0228"] = "Motorola     "
vendor["0328"] = "Motorola     "
vendor["0368"] = "Motorola     "
vendor["03C8"] = "Motorola     "
vendor["00C8"] = "Motorola     "
vendor["0348"] = "Motorola     "
vendor["1111"] = "Asus         "
vendor["143A"] = "Asus         "
vendor["1978"] = "Blackphone   "
vendor["2A70"] = "Oxygen       "


class Signed:
    filename = ''
    filesize = 0
    oem_id = ''
    model_id = ''
    hw_id = ''
    sw_id = ''
    app_id = ''
    sw_size = ''
    qc_version = ''
    image_variant = ''
    oem_version = ''
    pk_hash = ''
    hash = b''


def grabtext(data):
    i = len(data)
    j = 0
    text = ''
    while i > 0:
        if data[j] == 0:
            break
        text += chr(data[j])
        j += 1
        i -= 1
    return text


def extract_hdr(memsection, sign_info, mem_section, code_size, signature_size):
    try:
        md_size = \
        struct.unpack("<I", mem_section[memsection.file_start_addr + 0x2C:memsection.file_start_addr + 0x2C + 0x4])[0]
        md_offset = memsection.file_start_addr + 0x2C + 0x4
        major, minor, sw_id, hw_id, oem_id, model_id, app_id = struct.unpack("<IIIIIII",
                                                                             mem_section[md_offset:md_offset + (7 * 4)])
        sign_info.hw_id = "%08X" % hw_id
        sign_info.sw_id = "%08X" % sw_id
        sign_info.oem_id = "%04X" % oem_id
        sign_info.model_id = "%04X" % model_id
        sign_info.hw_id += sign_info.oem_id + sign_info.model_id
        sign_info.app_id = "%08X" % app_id
        md_offset += (7 * 4)
        # v=struct.unpack("<I", mem_section[md_offset:md_offset + 4])[0]
        '''
        rot_en=(v >> 0) & 1
        in_use_soc_hw_version=(v >> 1) & 1
        use_serial_number_in_signing=(v >> 2) & 1
        oem_id_independent=(v >> 3) & 1
        root_revoke_activate_enable=(v >> 4) & 0b11
        uie_key_switch_enable=(v >> 6) & 0b11
        debug=(v >> 8) & 0b11
        md_offset+=4
        soc_vers=hexlify(mm[md_offset:md_offset + (12*4)])
        md_offset+=12*4
        multi_serial_numbers=hexlify(mm[md_offset:md_offset + (8*4)])
        md_offset += 8 * 4
        mrc_index=struct.unpack("<I", mm[md_offset:md_offset + 4])[0]
        md_offset+=4
        anti_rollback_version=struct.unpack("<I", mm[md_offset:md_offset + 4])[0]
        '''

        signatureoffset = memsection.file_start_addr + 0x30 + md_size + code_size + signature_size
        try:
            if mem_section[signatureoffset] != 0x30:
                print("Error on " + sign_info.filename + ", unknown signaturelength")
                return None
        except:
            return None
        if len(mem_section) < signatureoffset + 4:
            print("Signature error on " + sign_info.filename)
            return None
        len1 = struct.unpack(">H", mem_section[signatureoffset + 2:signatureoffset + 4])[0] + 4
        casignature2offset = signatureoffset + len1
        len2 = struct.unpack(">H", mem_section[casignature2offset + 2:casignature2offset + 4])[0] + 4
        rootsignature3offset = casignature2offset + len2
        len3 = struct.unpack(">H", mem_section[rootsignature3offset + 2:rootsignature3offset + 4])[0] + 4
        sign_info.pk_hash = hashlib.sha384(mem_section[rootsignature3offset:rootsignature3offset + len3]).hexdigest()
    except:
        return None
    return sign_info


def extract_old_hdr(memsection, sign_info, mem_section, code_size, signature_size):
    signatureoffset = memsection.file_start_addr + 0x28 + code_size + signature_size
    signature = {}
    if mem_section[signatureoffset] != 0x30:
        print("Error on " + sign_info.filename + ", unknown signaturelength")
        return None
    if signatureoffset != -1:
        if len(mem_section) < signatureoffset + 4:
            print("Signature error on " + sign_info.filename)
            return None
        len1 = struct.unpack(">H", mem_section[signatureoffset + 2:signatureoffset + 4])[0] + 4
        casignature2offset = signatureoffset + len1
        len2 = struct.unpack(">H", mem_section[casignature2offset + 2:casignature2offset + 4])[0] + 4
        rootsignature3offset = casignature2offset + len2
        len3 = struct.unpack(">H", mem_section[rootsignature3offset + 2:rootsignature3offset + 4])[0] + 4
        sign_info.pk_hash = hashlib.sha256(mem_section[rootsignature3offset:rootsignature3offset + len3]).hexdigest()
        idx = signatureoffset

        while idx != -1:
            if idx >= len(mem_section):
                break
            idx = mem_section.find('\x04\x0B'.encode(), idx)
            if idx == -1:
                break
            length = mem_section[idx + 3]
            if length > 60:
                idx += 1
                continue
            try:
                text = mem_section[idx + 4:idx + 4 + length].decode().split(' ')
                signature[text[2]] = text[1]
            except:
                text = ""
            idx += 1
        idx = mem_section.find('QC_IMAGE_VERSION_STRING='.encode(), 0)
        if idx != -1:
            sign_info.qc_version = grabtext(mem_section[idx + len("QC_IMAGE_VERSION_STRING="):])
        idx = mem_section.find('OEM_IMAGE_VERSION_STRING='.encode(), 0)
        if idx != -1:
            sign_info.oem_version = grabtext(mem_section[idx + len("OEM_IMAGE_VERSION_STRING="):])
        idx = mem_section.find('IMAGE_VARIANT_STRING='.encode(), 0)
        if idx != -1:
            sign_info.image_variant = grabtext(mem_section[idx + len("IMAGE_VARIANT_STRING="):])
        if "OEM_ID" in signature:
            if signature["OEM_ID"] in vendor:
                sign_info.oem_id = vendor[signature["OEM_ID"]]
            else:
                sign_info.oem_id = signature["OEM_ID"]
        if "MODEL_ID" in signature:
            sign_info.model_id = signature["MODEL_ID"]
        if "HW_ID" in signature:
            sign_info.hw_id = signature["HW_ID"]
        if "SW_ID" in signature:
            sign_info.sw_id = signature["SW_ID"]
        if "SW_SIZE" in signature:
            sign_info.sw_size = signature["SW_SIZE"]
    return sign_info


def init_loader_db():
    loaderdb = {}
    for (dirpath, dirnames, filenames) in os.walk("Loaders"):
        for filename in filenames:
            file_name = os.path.join(dirpath, filename)
            found = False
            for ext in [".bin", ".mbn", ".elf"]:
                if ext in filename[-4:]:
                    found = True
                    break
            if not found:
                continue
            try:
                hwid = filename.split("_")[0].lower()
                msmid = hwid[:8]
                devid = hwid[8:]
                pkhash = filename.split("_")[1].lower()
                msmid = convertmsmid(msmid)
                mhwid = convertmsmid(msmid) + devid
                if mhwid not in loaderdb:
                    loaderdb[mhwid] = {}
                if pkhash not in loaderdb[mhwid]:
                    loaderdb[mhwid][pkhash] = file_name
                else:
                    loaderdb[mhwid][pkhash].append(file_name)
            except:
                continue
    return loaderdb


def is_duplicate(loaderdb, sign_info):
    lhash = sign_info.pk_hash[:16].lower()
    msmid = sign_info.hw_id[:8].lower()
    devid = sign_info.hw_id[8:].lower()
    hwid = sign_info.hw_id.lower()
    rid = (convertmsmid(msmid) + devid).lower()
    if hwid in loaderdb:
        loader = loaderdb[hwid]
        if lhash in loader:
            return True
    if rid in loaderdb:
        loader = loaderdb[rid]
        if lhash in loader:
            return True
    return False


def main(argv):
    file_list = []
    path = ""
    if len(argv) < 3:
        print("Usage: ./fhloaderparse.py [FHLoaderDir] [OutputDir]")
        exit(0)
    else:
        path = argv[1]
        outputdir = argv[2]
        if not os.path.exists(outputdir):
            os.mkdir(outputdir)

    loaderdb = init_loader_db()
    for (dirpath, dirnames, filenames) in walk(path):
        for filename in filenames:
            file_list.append(os.path.join(dirpath, filename))

    hashes = {}
    for (dirpath, dirnames, filenames) in walk(outputdir):
        for filename in filenames:
            fname = os.path.join(dirpath, filename)
            with open(fname, 'rb') as rhandle:
                data = rhandle.read()
                sha256 = hashlib.sha256()
                sha256.update(data)
                hashes[sha256.digest()] = fname

    filelist = []
    rt = open(os.path.join(outputdir, argv[1] + ".log"), "w")
    extensions = ["elf", "mbn", "bin"]
    if not os.path.exists(os.path.join(outputdir, "unknown")):
        os.makedirs(os.path.join(outputdir, "unknown"))
    for filename in file_list:
        found = False
        for ext in extensions:
            if "." + ext in filename:
                found = True
                break
        if found != True:
            continue
        with open(filename, 'rb') as rhandle:
            mem_section = rhandle.read()
            sha256 = hashlib.sha256()
            sha256.update(mem_section)

            signinfo = Signed()
            signinfo.hash = sha256.digest()
            signinfo.filename = filename
            signinfo.filesize = os.stat(filename).st_size
            if len(mem_section) < 4:
                continue
            hdr = struct.unpack("<I", mem_section[0:4])[0]
            '''
            if  hdr == 0x844BDCD1:  # mbn
                signatureoffset = struct.unpack("<I", mem_section[0x14:0x18])[0] + struct.unpack("<I", mem_section[0x20:0x24])[0] + \
                                  struct.unpack("<I", mem_section[0x28:0x2C])[0]
                if struct.unpack("<I", mem_section[0x28:0x2C])[0] == 0:
                    signatureoffset = -1
            '''
            if hdr == 0x464C457F:
                elfheader = elf(mem_section, signinfo.filename)
                if 'memorylayout' in dir(elfheader):
                    memsection = elfheader.memorylayout[1]
                    try:
                        version = struct.unpack("<I", mem_section[
                                                      memsection.file_start_addr + 0x04:memsection.file_start_addr + 0x04 + 0x4])[
                            0]
                        code_size = \
                            struct.unpack("<I", mem_section[
                                                memsection.file_start_addr + 0x14:memsection.file_start_addr + 0x14 + 0x4])[
                                0]
                        signature_size = \
                            struct.unpack("<I", mem_section[
                                                memsection.file_start_addr + 0x1C:memsection.file_start_addr + 0x1C + 0x4])[
                                0]
                        # cert_chain_size=struct.unpack("<I", mem_section[memsection.file_start_addr + 0x24:memsection.file_start_addr + 0x24 + 0x4])[0]
                    except:
                        continue
                    if signature_size == 0:
                        print("%s has no signature." % filename)
                        continue
                    if version < 6:  # MSM,MDM
                        signinfo = extract_old_hdr(memsection, signinfo, mem_section, code_size, signature_size)
                        if signinfo is None:
                            continue
                        filelist.append(signinfo)
                    elif version >= 6:  # SDM
                        signinfo = extract_hdr(memsection, signinfo, mem_section, code_size, signature_size)
                        if signinfo is None:
                            continue
                        filelist.append(signinfo)
                    else:
                        print("Unknown version for " + filename)
                        continue
            else:
                print("Error on " + filename)
                continue

    sorted_x = sorted(filelist, key=lambda x: (x.hw_id, -x.filesize))

    class loaderinfo:
        hw_id = ''
        item = ''

    if not os.path.exists(os.path.join(outputdir, "Duplicate")):
        os.mkdir(os.path.join(outputdir, "Duplicate"))
    loaderlists = {}
    for item in sorted_x:
        if item.oem_id != '':
            info = f"OEM:{item.oem_id}\tMODEL:{item.model_id}\tHWID:{item.hw_id}\tSWID:{item.sw_id}\tSWSIZE:{item.sw_size}\tPK_HASH:{item.pk_hash}\t{item.filename}\t{str(item.filesize)}"
            if item.oem_version != '':
                info += "\tOEMVER:" + item.oem_version + "\tQCVER:" + item.qc_version + "\tVAR:" + item.image_variant
            loader_info = loaderinfo()
            loader_info.hw_id = item.hw_id
            loader_info.pk_hash = item.pk_hash
            if item.hash not in hashes:
                if loader_info not in loaderlists:
                    if not is_duplicate(loaderdb, item):
                        loaderlists[loader_info] = item.filename
                        print(info)
                        msmid = loader_info.hw_id[:8]
                        devid = loader_info.hw_id[8:]
                        hwid = convertmsmid(msmid) + devid
                        copyfile(item.filename,
                                 os.path.join(outputdir, hwid + "_" + loader_info.pk_hash[0:16] + "_FHPRG.bin"))
                    else:
                        print("Duplicate: " + info)
                        copyfile(item.filename, os.path.join(outputdir, "Duplicate",
                                                             loader_info.hw_id + "_" + loader_info.pk_hash[
                                                                                       0:16] + "_FHPRG.bin"))
                else:
                    copyfile(item.filename, os.path.join(outputdir, "unknown", item.filename[item.filename.rfind(
                        "\\") + 1:] + "_" + loader_info.pk_hash[0:16] + "_FHPRG.bin"))
            else:
                print(item.filename + " does already exist. Skipping")
            try:
                rt.write(info + "\n")
            except:
                continue

    for item in filelist:
        if item.oem_id == '' and (".bin" in item.filename or ".mbn" in item.filename or ".hex" in item.filename):
            info = "Unsigned:" + item.filename + "\t" + str(item.filesize)
            if item.oem_version != '':
                info += "\tOEMVER:" + item.oem_version + "\tQCVER:" + item.qc_version + "\tVAR:" + item.image_variant
            print(info)
            rt.write(info + "\n")
            copyfile(item.filename, os.path.join(outputdir, "unknown", item.filename[item.filename.rfind("\\") + 1:]))

    rt.close()


main(sys.argv)
