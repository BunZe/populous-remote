from scapy.all import *
from scapy.layers.dot11 import *
packets = rdpcap('./wifiTest01.pcapng')

activeChannel = 5
devices = []


def updateDevice(addr, signal, newSeq, list):
    for device in list:
        if device.addr == addr:
            device.lastSeq = newSeq
            if signal > device.signalStrength:
                device.signalStrength = signal
            return

def convertSeq(seq):
    seq = hex(seq)
    seq = seq[0:5]
    return int(seq, 16)


class Device:
    def __init__(self, addr, signalStrength, lastSeq, firstVendorSpecificTag):
        self.addr = addr
        self.signalStrength = signalStrength
        self.lastSeq = lastSeq
        self.firstVendorSpecificTag = firstVendorSpecificTag

    def __repr__(self):
        return "===\n"+"Address: "+self.addr+"\n"+"Signal: "+str(self.signalStrength)+"\n"+"lastSeq: "+str(self.lastSeq)+"\n==="


def main():
    for packet in packets:
        if Dot11ProbeReq in packet:
            p = packet[Dot11FCS]
            addr = p.addr2
            seq = convertSeq(p.SC)
            if any(device.addr == addr for device in devices):
                updateDevice(addr, packet[RadioTap].dBm_AntSignal, seq, devices)
            else:
                if not matchToDevice(packet, devices):
                    devices.append(Device(addr, packet[RadioTap].dBm_AntSignal, seq, p[Dot11EltVendorSpecific].oui))



def matchToDevice(packet, devices):
    p = packet[Dot11FCS]
    newSeq = convertSeq(p.SC)
    for device in devices:
        if device.lastSeq < newSeq:
            if newSeq - device.lastSeq < 35:
                if p[Dot11EltVendorSpecific].oui == device.firstVendorSpecificTag:
                    # Probably same device, new MAC Address
                    device.lastSeq = newSeq
                    if device.signalStrength < packet[RadioTap].dBm_AntSignal:
                        device.signalStrength = packet[RadioTap].dBm_AntSignal
                    return True
    return False


main()
for d in devices:
    print(d)

