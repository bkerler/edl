import xml.etree.ElementTree as ET
class xmlparser():
    def getresponse(self,input):
        lines=input.split(b"<?xml")
        content = {}
        for line in lines:
            if line==b'':
                continue
            line=b"<?xml"+line
            parser = ET.XMLParser(encoding="utf-8")
            tree = ET.fromstring(line, parser=parser)
            e = ET.ElementTree(tree).getroot()
            for atype in e.findall('response'):
                for field in atype.attrib:
                    content[field]=atype.attrib[field]
        return content

    def getlog(self,input):
        lines=input.split(b"<?xml")
        data = ''
        for line in lines:
            if line==b'':
                continue
            line=b"<?xml"+line
            parser = ET.XMLParser(encoding="utf-8")
            tree = ET.fromstring(line, parser=parser)
            e = ET.ElementTree(tree).getroot()
            for atype in e.findall('log'):
                if 'value' in atype.attrib:
                    data+=atype.attrib['value']
        return data