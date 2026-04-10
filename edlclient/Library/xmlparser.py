#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# (c) B.Kerler 2018-2024 under GPLv3 license
# If you use my code, make sure you refer to my name
#
# !!!!! If you use this code in commercial products, your product is automatically
# GPLv3 and has to be open sourced under GPLv3 as well. !!!!!
import xml.etree.ElementTree as ET
import os

class xmlparser:
    def getresponse(self, input):
        lines = input.split(b"<?xml")
        content = {}
        for line in lines:
            if line == b'':
                continue
            line = b"<?xml" + line
            if b"\xf0\xe9\x88\x14" in line:
                line = line.replace(b"\xf0\xe9\x88\x14", b"")
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
                line = line.replace(b"\xf0\xe9\x88\x14", b"")
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

    # add parsing sahara XML config method
    def parse_sahara_config(self, xml_path):

        mappings = {}
        
        if not os.path.exists(xml_path):
            raise FileNotFoundError(f"Sahara configuration XML not found: {xml_path}")

        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
            base_dir = os.path.dirname(xml_path)

            if root.tag != "sahara_config":
                raise Exception("Invalid Sahara config: Root element must be <sahara_config>.")

            chipset_node = root.find("chipset")
            if chipset_node is not None and chipset_node.text:
                pass

            images_container = root.find("images")
            if images_container is None:
                raise Exception("Invalid Sahara config: Missing <images> container.")

            image_elements = images_container.findall("image")
            if not image_elements:
                raise Exception("Invalid Sahara config: No <image> elements found.")

            for img in image_elements:
                id_str = img.get("image_id")
                rel_path = img.get("image_path")

                if not id_str or not rel_path:
                    continue

                try:
                    img_id = int(id_str)
                except ValueError:
                    raise Exception(f"Invalid Sahara config: <image> has a non-numeric image_id '{id_str}'.")

                if img_id in mappings:
                    raise Exception(f"Invalid Sahara config: Duplicate <image> entry for image_id '{img_id}'.")

                full_path = rel_path if os.path.isabs(rel_path) else os.path.join(base_dir, rel_path)

                if os.path.exists(full_path):
                    mappings[img_id] = full_path
                else:
                    raise FileNotFoundError(f"Sahara image file defined in XML not found: {rel_path} (Full: {full_path})")

            if not mappings:
                raise Exception("Invalid Sahara config: No valid <image> mappings were produced.")
            
            return mappings

        except Exception as e:
            raise e