import usb.core                 # pyusb
import usb.util

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

    def connect(self):
        self.device = usb.core.find(idVendor=self.vid, idProduct=self.pid)
        if self.device is None:
            self.log(2, "Couldn't detect the device. Is it connected ?")
            return False
        self.device.set_configuration()
        self.configuration = self.device.get_active_configuration()
        self.log(2, self.configuration)
        for itf_num in [0]:
            itf = usb.util.find_descriptor(self.configuration,
                                           bInterfaceNumber=itf_num)
            try:
                if self.device.is_kernel_driver_active(itf_num):
                    self.log(2, "Detaching kernel driver")
                    self.device.detach_kernel_driver(itf_num)
            except:
                self.log(2, "No kernel driver supported.")

            usb.util.claim_interface(self.device, itf_num)

            self.EP_OUT = usb.util.find_descriptor(itf,
                                                   # match the first OUT endpoint
                                                   custom_match= \
                                                       lambda e: \
                                                           usb.util.endpoint_direction(e.bEndpointAddress) == \
                                                           usb.util.ENDPOINT_OUT)

            self.EP_IN = usb.util.find_descriptor(itf,
                                                  # match the first OUT endpoint
                                                  custom_match= \
                                                      lambda e: \
                                                          usb.util.endpoint_direction(e.bEndpointAddress) == \
                                                          usb.util.ENDPOINT_IN)
        self.connected=True
        return True

    def write(self,command,pktsize=64):
        pos=0
        if command==b'':
            self.device.write(self.EP_OUT, b'')
        else:
            while pos<len(command):
                self.device.write(self.EP_OUT,command[pos:pos+pktsize])
                pos+=pktsize

    def read(self,length=0x80000,timeout=None):
        tmp=b''
        while (bytearray(tmp) == b''):
            tmp=self.device.read(self.EP_IN, length,timeout)
        return bytearray(tmp)
