from datetime import datetime

def pcap_analyse(file):
    magic = bytes(file.read(4)).hex()
    if magic == 'd4c3b2a1':
        majorbyte = file.read(2)
        major = bytearray(majorbyte)
        major.reverse()
        minorbyte = file.read(2)
        minor = bytearray(minorbyte)
        minor.reverse()
        timezonebyte = file.read(4)
        timezone = bytearray(timezonebyte)
        timezone.reverse()
        accuracybyte = file.read(4)
        accuracy = bytearray(accuracybyte)
        accuracy.reverse()
        snaplenbyte = file.read(4)
        snaplen = bytearray(snaplenbyte)
        snaplen.reverse()
        networkbyte = file.read(4)
        network = bytearray(networkbyte)
        network.reverse()
        packet = []
        capture = {}
        for i in range(1, int(bytes(snaplen).hex(), 16)):
            try:
                timeb = file.read(4)
                time = bytearray(timeb)
                time.reverse()
                time2b =file.read(4)
                time2 = bytearray(time2b)
                time2.reverse()
                lenb =file.read(4)
                leng = bytearray(lenb)
                leng.reverse()
                lenub =file.read(4)
                lenu = bytearray(lenub)
                lenu.reverse()
                payload = file.read(int(bytes(leng).hex(), 16))
                timestamp = float(str(int(bytes(time).hex(), 16)) + '.' + str(int(bytes(time2).hex(), 16)))
                date_time = datetime.fromtimestamp(timestamp)
                packet = [date_time.strftime("%d-%m-%Y %H:%M:%S.%f"), bytes(payload).hex()]
                dict = {i: packet}
                capture.update(dict)
            except:
                continue

        analyse = {}    
        for key in capture:            
            dict_1 = {key : [payload_analyse(capture[key][1]), capture[key][0]]}
            analyse.update(dict_1)
                
    else:
        major = file.read(2)
        minor = file.read(2)
        timezone = file.read(4)
        accuracy = file.read(4)
        snaplen = file.read(4)
        network = file.read(4)
        packet = []
        capture = {}
        for i in range(1, int(bytes(snaplen).hex(), 16)):
            try:
                time = file.read(4)                
                time2 =file.read(4)                
                leng =file.read(4)                
                lenu =file.read(4)                
                payload = file.read(int(bytes(leng).hex(), 16))
                timestamp = float(str(int(bytes(time).hex(), 16)) + '.' + str(int(bytes(time2).hex(), 16)))
                date_time = datetime.fromtimestamp(timestamp)
                packet = [date_time.strftime("%d-%m-%Y %H:%M:%S.%f"), bytes(payload).hex()]
                dict = {i: packet}
                capture.update(dict)
            except:
                continue

        analyse = {}    
        for key in capture:            
            dict_1 = {key : [payload_analyse(capture[key][1]), capture[key][0]]}
            analyse.update(dict_1)
    return(magic, bytes(major).hex(), bytes(minor).hex(), bytes(timezone).hex(), bytes(accuracy).hex(), bytes(snaplen).hex(), bytes(network).hex(), analyse)

def payload_analyse(payload):
    destmac = payload[0:2] + ':' + payload[2:4] + ':' + payload[4:6] + ':' + payload[6:8] + ':' + payload[8:10] + ':' + payload[10:12]
    sourcmac = payload[12:14] + ':' + payload[14:16] + ':' + payload[16:18] + ':' + payload[18:20] + ':' + payload[20:22] + ':' + payload[22:24]
    ipvx = payload[24:52]
    srcip = str(int(payload[52:54], 16)) + '.' + str(int(payload[54:56], 16)) + '.' + str(int(payload[56:58], 16)) + '.' + str(int(payload[58:60], 16))
    destip = str(int(payload[60:62], 16)) + '.' + str(int(payload[62:64], 16)) + '.' + str(int(payload[64:66], 16)) + '.' + str(int(payload[66:68], 16))
    srcport = int(payload[68:72], 16)
    destport = int(payload[72:76], 16)
    udplen = int(payload[76:80], 16)
    checksum = payload[92:96]
    payloadsize = len(payload)
    udppayload = payload[96:]
    analyzer = {'Destination MAC': destmac, 'Source MAC': sourcmac, 'Source IP': srcip, 'Source port': srcport, 'Destination IP': destip,
    'Destination port': destport, 'UDP lenght': udplen, 'Payload size': payloadsize, 'Payload': udppayload}
    return(analyzer)

    
f = open('E:\\NTU\\YEAR2\\CYBERSEC\\Assessment\\CyberSecurity2022.pcap' , 'rb')
#out = open('E:\\NTU\\YEAR2\\CYBERSEC\\Assessment\\CyberSecurity2022.txt', 'a+')
#print(f.read(), file=out)
#print(pcap_analyse(f))
#payload = pcap_analyse(f)[11]
#print(payload_analyse(payload))
#f.close()

f = open('E:\\NTU\\YEAR2\\CYBERSEC\\Assessment\\CyberSecurity2022.pcap' , 'rb')
out = open('E:\\NTU\\YEAR2\\CYBERSEC\\Assessment\\CyberSecurity2022analyseready.txt', 'a+')
print(pcap_analyse(f), file=out)
#print(pcap_analyse(f))
f.close()





