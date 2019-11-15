import usb.core                 # pyusb
import usb.util
import time
import errno

USB_DIR_OUT=0		# to device
USB_DIR_IN=0x80		# to host

# USB types, the second of three bRequestType fields
USB_TYPE_MASK=(0x03 << 5)
USB_TYPE_STANDARD=(0x00 << 5)
USB_TYPE_CLASS=(0x01 << 5)
USB_TYPE_VENDOR=(0x02 << 5)
USB_TYPE_RESERVED=(0x03 << 5)

# USB recipients, the third of three bRequestType fields
USB_RECIP_MASK=0x1f
USB_RECIP_DEVICE=0x00
USB_RECIP_INTERFACE=0x01
USB_RECIP_ENDPOINT=0x02
USB_RECIP_OTHER=0x03
#From Wireless USB 1.0
USB_RECIP_PORT=	0x04
USB_RECIP_RPIPE=0x05

class usb_class():

    def log(self,level,msg):
        if level>1:
            if self.debug==True:
                print(msg)
        else:
            print(msg)

    def __init__(self,vid=0x05c6, pid=0x9008, Debug=False):
        self.vid=vid
        self.pid=pid
        self.debug=Debug
        self.connected=False

    def getInterfaceCount(self):
        self.device = usb.core.find(idVendor=self.vid, idProduct=self.pid)
        if self.device is None:
            self.log(2, "Couldn't detect the device. Is it connected ?")
            return False
        try:
            self.device.set_configuration()
        except:
            pass
        self.configuration = self.device.get_active_configuration()
        self.log(2, self.configuration)
        return self.configuration.bNumInterfaces

    def connect(self, interface=0, EP_IN=-1, EP_OUT=-1):
        self.device = usb.core.find(idVendor=self.vid, idProduct=self.pid)
        if self.device is None:
            self.log(2, "Couldn't detect the device. Is it connected ?")
            return False
        try:
            self.device.set_configuration()
        except:
            pass
        self.configuration = self.device.get_active_configuration()
        self.log(2, self.configuration)
        if interface>self.configuration.bNumInterfaces:
            print("Invalid interface, max number is %d" % self.configuration.bNumInterfaces)
            return False
        for itf_num in [interface]:
            itf = usb.util.find_descriptor(self.configuration,
                                           bInterfaceNumber=itf_num)
            try:
                if self.device.is_kernel_driver_active(itf_num):
                    self.log(2, "Detaching kernel driver")
                    self.device.detach_kernel_driver(itf_num)
            except:
                self.log(2, "No kernel driver supported.")

            usb.util.claim_interface(self.device, itf_num)
            if EP_OUT==-1:
                self.EP_OUT = usb.util.find_descriptor(itf,
                                                   # match the first OUT endpoint
                                                   custom_match= \
                                                       lambda e: \
                                                           usb.util.endpoint_direction(e.bEndpointAddress) == \
                                                           usb.util.ENDPOINT_OUT)
            else:
                self.EP_OUT=EP_OUT
            if EP_IN==-1:
                self.EP_IN = usb.util.find_descriptor(itf,
                                                  # match the first OUT endpoint
                                                  custom_match= \
                                                      lambda e: \
                                                          usb.util.endpoint_direction(e.bEndpointAddress) == \
                                                          usb.util.ENDPOINT_IN)
            else:
                self.EP_IN=EP_IN

        self.connected=True
        return True

    def write(self,command,pktsize=64):
        pos=0
        if command==b'':
            self.device.write(self.EP_OUT, b'')
        else:
            while pos<len(command):
                try:
                    self.device.write(self.EP_OUT,command[pos:pos+pktsize])
                    pos += pktsize
                except:
                    #print("Error while writing")
                    time.sleep(0.05)
                    pass
        return True

    def read(self,length=0x80000,timeout=None):
        tmp=b''
        while (bytearray(tmp) == b''):
                try:
                    tmp=self.device.read(self.EP_IN, length,timeout)
                except usb.core.USBError as e:
                    if b"timeout" in e.strerror:
                        time.sleep(0.05)
                        print("Waiting...")
                    elif e.errno != None:
                        print(repr(e), type(e), e.errno)
                        raise(e)
                    else:
                        break
        return bytearray(tmp)

    def ctrl_transfer(self,bmRequestType,bRequest,wValue,wIndex,data_or_wLength):
        ret=self.device.ctrl_transfer(bmRequestType=bmRequestType,bRequest=bRequest,wValue=wValue,wIndex=wIndex,data_or_wLength=data_or_wLength)
        return ret[0] | (ret[1] << 8)