#!/usr/bin/python3
# -*- coding: utf-8 -*-
# (c) B.Kerler 2018-2021
import xml.etree.ElementTree as ET


class xmlparser:
    def getresponse(self, input):
        lines = input.split(b"<?xml")
        content = {}
        for line in lines:
            if line == b'':
                continue
            line = b"<?xml" + line
            if b"\xf0\xe9\x88\x14" in line:
                line=line.replace(b"\xf0\xe9\x88\x14",b"")
            parser = ET.XMLParser(encoding="utf-8")
            try:
                tree = ET.fromstring(line, parser=parser)
            except Exception as err:
                continue
            e = ET.ElementTree(tree).getroot()
            for atype in e.findall('response'):
                for field in atype.attrib:
                    content[field] = atype.attrib[field]
        return content

    def getlog(self, input):
        lines = input.split(b"<?xml")
        data = []
        for line in lines:
            if line == b'':
                continue
            line = b"<?xml" + line
            if b"\xf0\xe9\x88\x14" in line:
                line=line.replace(b"\xf0\xe9\x88\x14",b"")
            parser = ET.XMLParser(encoding="utf-8")
            try:
                tree = ET.fromstring(line, parser=parser)
            except Exception as err:
                continue
            e = ET.ElementTree(tree).getroot()
            for atype in e.findall('log'):
                if 'value' in atype.attrib:
                    data.append(atype.attrib['value'])
        return data
