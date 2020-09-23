#!/usr/bin/env python3
from Library.utils import elf
import os
import sys
from os import walk
import hashlib
import struct
from shutil import copyfile
from binascii import hexlify, unhexlify
from Library.qualcomm_config import *

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
  hash=b''

def grabtext(data):
    i=len(data)
    t=0
    text=''
    while (i>0):
        if (data[t]==0):
            break
        text+=chr(data[t])
        t+=1
        i-=1
    return text


def extract_hdr(memsection,si,mm,code_size,signature_size):
    try:
        md_size = struct.unpack("<I", mm[memsection.file_start_addr + 0x2C:memsection.file_start_addr + 0x2C + 0x4])[0]
        md_offset=memsection.file_start_addr + 0x2C + 0x4
        major,minor,sw_id,hw_id,oem_id,model_id,app_id=struct.unpack("<IIIIIII",mm[md_offset:md_offset+(7*4)])
        si.hw_id="%08X" % hw_id
        si.sw_id = "%08X" % sw_id
        si.oem_id="%04X" % oem_id
        si.model_id="%04X" % model_id
        si.hw_id += si.oem_id + si.model_id
        si.app_id="%08X" % app_id
        md_offset+=(7 * 4)
        v=struct.unpack("<I", mm[md_offset:md_offset + 4])[0]
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

        signatureoffset = memsection.file_start_addr + 0x30 + md_size + code_size + signature_size
        try:
            if mm[signatureoffset] != 0x30:
                print("Error on " + si.filename + ", unknown signaturelength")
                return None
        except:
            return None
        if len(mm) < signatureoffset + 4:
                print("Signature error on " + si.filename)
                return None
        len1 = struct.unpack(">H", mm[signatureoffset + 2:signatureoffset + 4])[0] + 4
        casignature2offset = signatureoffset + len1
        len2 = struct.unpack(">H", mm[casignature2offset + 2:casignature2offset + 4])[0] + 4
        rootsignature3offset = casignature2offset + len2
        len3 = struct.unpack(">H", mm[rootsignature3offset + 2:rootsignature3offset + 4])[0] + 4
        si.pk_hash = hashlib.sha384(mm[rootsignature3offset:rootsignature3offset + len3]).hexdigest()
    except:
        return None
    return si


def extract_old_hdr(memsection,si,mm,code_size,signature_size):
    signatureoffset = memsection.file_start_addr + 0x28 + code_size + signature_size
    signature = {}
    if mm[signatureoffset] != 0x30:
        print("Error on " + si.filename + ", unknown signaturelength")
        return None
    if signatureoffset != -1:
        if len(mm) < signatureoffset + 4:
            print("Signature error on " + si.filename)
            return None
        len1 = struct.unpack(">H", mm[signatureoffset + 2:signatureoffset + 4])[0] + 4
        casignature2offset = signatureoffset + len1
        len2 = struct.unpack(">H", mm[casignature2offset + 2:casignature2offset + 4])[0] + 4
        rootsignature3offset = casignature2offset + len2
        len3 = struct.unpack(">H", mm[rootsignature3offset + 2:rootsignature3offset + 4])[0] + 4
        si.pk_hash = hashlib.sha256(mm[rootsignature3offset:rootsignature3offset + len3]).hexdigest()
        idx = signatureoffset

        while (idx != -1):
            if (idx >= len(mm)):
                break
            idx = mm.find('\x04\x0B'.encode(), idx)
            if (idx == -1):
                break
            length = mm[idx + 3]
            if (length > 60):
                idx += 1
                continue
            try:
                text = mm[idx + 4:idx + 4 + length].decode().split(' ')
                signature[text[2]] = text[1]
            except:
                text = ""
            idx += 1
        idx = mm.find('QC_IMAGE_VERSION_STRING='.encode(), 0)
        if idx != -1:
            si.qc_version = grabtext(mm[idx + len("QC_IMAGE_VERSION_STRING="):])
        idx = mm.find('OEM_IMAGE_VERSION_STRING='.encode(), 0)
        if idx != -1:
            si.oem_version = grabtext(mm[idx + len("OEM_IMAGE_VERSION_STRING="):])
        idx = mm.find('IMAGE_VARIANT_STRING='.encode(), 0)
        if idx != -1:
            si.image_variant = grabtext(mm[idx + len("IMAGE_VARIANT_STRING="):])
        if "OEM_ID" in signature:
            if signature["OEM_ID"] in vendor:
                si.oem_id = vendor[signature["OEM_ID"]]
            else:
                si.oem_id = signature["OEM_ID"]
        if "MODEL_ID" in signature:
            si.model_id = signature["MODEL_ID"]
        if "HW_ID" in signature:
            si.hw_id = signature["HW_ID"]
        if "SW_ID" in signature:
            si.sw_id = signature["SW_ID"]
        if "SW_SIZE" in signature:
            si.sw_size = signature["SW_SIZE"]
    return si

def convertmsmid(msmid):
    if int(msmid, 16) in sochw:
        names = sochw[int(msmid, 16)].split(",")
        for name in names:
            for ids in msmids:
                if msmids[ids] == name:
                    msmid = hex(ids)[2:].lower()
                    while (len(msmid) < 8):
                        msmid = '0' + msmid
    return msmid

def init_loader_db():
    loaderdb = {}
    for (dirpath, dirnames, filenames) in os.walk("Loaders"):
        for filename in filenames:
            fn = os.path.join(dirpath, filename)
            found=False
            for ext in [".bin",".mbn",".elf"]:
                if ext in filename[-4:]:
                    found=True
                    break
            if found==False:
                continue
            try:
                hwid = filename.split("_")[0].lower()
                msmid=hwid[:8]
                devid=hwid[8:]
                pkhash = filename.split("_")[1].lower()
                msmid=convertmsmid(msmid)
                if msmid not in loaderdb:
                    loaderdb[msmid + devid] = {}
                if pkhash not in loaderdb[msmid + devid]:
                    loaderdb[msmid + devid][pkhash] = fn
                else:
                    if msmid not in loaderdb:
                        loaderdb[msmid+devid] = {}
                    if pkhash not in loaderdb[msmid+devid]:
                        loaderdb[msmid+devid][pkhash] = fn
            except:
                continue
    return loaderdb

def is_duplicate(loaderdb, si):
    for loader in loaderdb:
        for hash in loaderdb[loader]:
            lhash = si.pk_hash[:16]
            if lhash == hash:
                msmid = si.hw_id[:8]
                devid = si.hw_id[8:]
                rid = convertmsmid(msmid) + devid
                if si.hw_id == loader or rid == loader:
                    return True
    return False

def main(argv):
    f = []
    path = ""
    if (len(argv)<3):
        print("Usage: ./fhloaderparse.py [FHLoaderDir] [OutputDir]")
        exit(0)
    else:
        path = argv[1]
        outputdir = argv[2]
        if not os.path.exists(outputdir):
            os.mkdir(outputdir)

    loaderdb=init_loader_db()
    for (dirpath, dirnames, filenames) in walk(path):
        for filename in filenames:
            f.append(os.path.join(dirpath, filename))

    hashes={}
    for (dirpath, dirnames, filenames) in walk(outputdir):
        for filename in filenames:
            fname=os.path.join(dirpath, filename)
            with open(fname,'rb') as rf:
                data=rf.read()
                sha256 = hashlib.sha256()
                sha256.update(data)
                hashes[sha256.digest()]=fname

    filelist = []
    rt=open(os.path.join(outputdir,argv[1]+".log"),"w")
    extensions=["elf","mbn","bin"]
    
    if not os.path.exists(os.path.join(outputdir,"unknown")):
        os.makedirs(os.path.join(outputdir,"unknown"))
    
    for filename in f:
        found=False
        for ext in extensions:
            if "."+ext in filename:
                found=True
                break
        if found!=True:
            continue
        with open(filename,'rb') as rf:
            mm = rf.read()
            sha256 = hashlib.sha256()
            sha256.update(mm)

            si=Signed()
            si.hash=sha256.digest()
            si.filename=filename
            si.filesize=os.stat(filename).st_size
            if len(mm)<4:
                continue
            hdr=struct.unpack("<I", mm[0:4])[0]
            if  hdr == 0x844BDCD1:  # mbn
                signatureoffset = struct.unpack("<I", mm[0x14:0x18])[0] + struct.unpack("<I", mm[0x20:0x24])[0] + \
                                  struct.unpack("<I", mm[0x28:0x2C])[0]
                if struct.unpack("<I", mm[0x28:0x2C])[0] == 0:
                    signatureoffset = -1
            elif hdr == 0x464C457F:
                elfheader = elf(mm,si.filename)
                if 'memorylayout' in dir(elfheader):
                    memsection=elfheader.memorylayout[1]
                    try:
                        version=struct.unpack("<I",mm[memsection.file_start_addr + 0x04:memsection.file_start_addr + 0x04+0x4])[0]
                        code_size = \
                        struct.unpack("<I", mm[memsection.file_start_addr + 0x14:memsection.file_start_addr + 0x14 + 0x4])[
                            0]
                        signature_size = \
                        struct.unpack("<I", mm[memsection.file_start_addr + 0x1C:memsection.file_start_addr + 0x1C + 0x4])[
                            0]
                        cert_chain_size=struct.unpack("<I", mm[memsection.file_start_addr + 0x24:memsection.file_start_addr + 0x24 + 0x4])[
                            0]
                    except:
                        continue
                    if signature_size==0:
                        print("%s has no signature." % filename)
                        continue
                    if version<6: #MSM,MDM
                        si=extract_old_hdr(memsection,si,mm,code_size,signature_size)
                        if si==None:
                            continue
                        filelist.append(si)
                    elif version>=6: #SDM
                        si = extract_hdr(memsection, si, mm, code_size, signature_size)
                        if si == None:
                            continue
                        filelist.append(si)
                    else:
                        print("Unknown version for "+filename)
                        continue
            else:
                print("Error on " + filename)
                continue



    sorted_x = sorted(filelist, key=lambda x: (x.hw_id, -x.filesize))
    class loaderinfo:
        hw_id=''
        item=''
    if not os.path.exists(os.path.join(outputdir,"Duplicate")):
        os.mkdir(os.path.join(outputdir,"Duplicate"))
    loaderlists = {}
    for item in sorted_x:
        if item.oem_id!='':
            info=f"OEM:{item.oem_id}\tMODEL:{item.model_id}\tHWID:{item.hw_id}\tSWID:{item.sw_id}\tSWSIZE:{item.sw_size}\tPK_HASH:{item.pk_hash}\t{item.filename}\t{str(item.filesize)}"
            if item.oem_version!='':
                info+="\tOEMVER:"+item.oem_version+"\tQCVER:"+item.qc_version+"\tVAR:"+item.image_variant
            lf=loaderinfo()
            lf.hw_id=item.hw_id
            lf.pk_hash=item.pk_hash
            if item.hash not in hashes:
                if (lf not in loaderlists):
                    if not is_duplicate(loaderdb, item):
                        loaderlists[lf]=item.filename
                        print(info)
                        msmid = lf.hw_id[:8]
                        devid = lf.hw_id[8:]
                        hwid = convertmsmid(msmid) + devid
                        copyfile(item.filename,os.path.join(outputdir,hwid+"_"+lf.pk_hash[0:16]+"_FHPRG.bin"))
                    else:
                        print("Duplicate: "+info)
                        copyfile(item.filename,os.path.join(outputdir, "Duplicate", lf.hw_id + "_" + lf.pk_hash[0:16] + "_FHPRG.bin"))
                else:
                    copyfile(item.filename,os.path.join(outputdir,"unknown",item.filename[item.filename.rfind("\\")+1:]+"_"+lf.pk_hash[0:16]+"_FHPRG.bin"))
            else:
                print(item.filename+" does already exist. Skipping")
            try:
                rt.write(info+"\n")
            except:
                continue

    for item in filelist:
        if item.oem_id=='' and (".bin" in item.filename or ".mbn" in item.filename or ".hex" in item.filename):
            info="Unsigned:"+item.filename+"\t"+str(item.filesize)
            if item.oem_version != '':
                info += "\tOEMVER:" + item.oem_version + "\tQCVER:" + item.qc_version + "\tVAR:" + item.image_variant
            print(info)
            rt.write(info+"\n")
            copyfile(item.filename,os.path.join(outputdir,"unknown",item.filename[item.filename.rfind("\\")+1:]))

    rt.close()


main(sys.argv)