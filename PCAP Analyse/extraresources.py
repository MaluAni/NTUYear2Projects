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
        for i in range(1, 100000):
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
                dict = {i: {'Time':date_time.strftime("%d-%m-%Y %H:%M:%S.%f"), 
                'Destination MAC':payload_analyse(bytes(payload))['Destination MAC'],                
                'Source MAC':payload_analyse(bytes(payload))['Source MAC'],
                'Source IP':payload_analyse(bytes(payload))['Source IP'],                 
                'Source port': payload_analyse(bytes(payload))['Source port'], 
                'Destination IP': payload_analyse(bytes(payload))['Destination IP'], 
                'Destination port': payload_analyse(bytes(payload))['Destination port'], 
                'UDP lenght': payload_analyse(bytes(payload))['UDP lenght'],
                'Payload size': payload_analyse(bytes(payload))['Payload size'], 
                'Payload': payload_analyse(bytes(payload))['Payload']}}
                capture.update(dict)                
            except:                
                continue        
                
    else:
        major = file.read(2)
        minor = file.read(2)
        timezone = file.read(4)
        accuracy = file.read(4)
        snaplen = file.read(4)
        network = file.read(4)
        packet = []
        capture = {}
        for i in range(1, 100000):
            try:
                time = file.read(4)                
                time2 =file.read(4)                
                leng =file.read(4)                
                lenu =file.read(4)                
                payload = file.read(int(bytes(leng).hex(), 16))
                timestamp = float(str(int(bytes(time).hex(), 16)) + '.' + str(int(bytes(time2).hex(), 16)))
                date_time = datetime.fromtimestamp(timestamp)                
                dict = {i: {'Time':date_time.strftime("%d-%m-%Y %H:%M:%S.%f"), 
                'Destination MAC':payload_analyse(bytes(payload))['Destination MAC'],
                'Source MAC':payload_analyse(bytes(payload))['Source MAC'], 
                'Source IP':payload_analyse(bytes(payload))['Source IP'], 
                'Source port': payload_analyse(bytes(payload))['Source port'], 
                'Destination IP': payload_analyse(bytes(payload))['Destination IP'], 
                'Destination port': payload_analyse(bytes(payload))['Destination port'], 
                'UDP lenght': payload_analyse(bytes(payload))['UDP lenght'],
                'Payload size': payload_analyse(bytes(payload))['Payload size'], 
                'Payload': payload_analyse(bytes(payload))['Payload']}}
                capture.update(dict)
            except:
                continue
        
    return('Endianness: ', magic, 'Major version: ', int(bytes(major).hex(), 16), 'Minor version: ', int(bytes(minor).hex(), 16), 'Timezone (0 is GMT): ', int(bytes(timezone).hex(), 16), 'Accuracy: ', int(bytes(accuracy).hex(), 16), 'Snap Length: ', int(bytes(snaplen).hex(), 16), 'Network type: ', int(bytes(network).hex(), 16), 'Packets: ', capture)
    
def payload_analyse(payload):
    destmac = str(payload[:1].hex()) + ':' + str(payload[1:2].hex()) + ':' + str(payload[2:3].hex()) + ':' + str(payload[3:4].hex()) + ':' + str(payload[4:5].hex()) + ':' + str(payload[5:6].hex())
    sourcmac = str(payload[6:7].hex()) + ':' + str(payload[7:8].hex()) + ':' + str(payload[8:9].hex()) + ':' + str(payload[9:10].hex()) + ':' + str(payload[10:11].hex()) + ':' + str(payload[11:12].hex())    
    srcip = str(int(payload[26:27].hex(), 16)) + '.' + str(int(payload[27:28].hex(), 16)) + '.' + str(int(payload[28:29].hex(), 16)) + '.' + str(int(payload[29:30].hex(), 16))
    destip = str(int(payload[30:31].hex(), 16)) + '.' + str(int(payload[31:32].hex(), 16)) + '.' + str(int(payload[32:33].hex(), 16)) + '.' + str(int(payload[33:34].hex(), 16))
    srcport = int(payload[34:36].hex(), 16)
    destport = int(payload[36:38].hex(), 16)
    udplen = int(payload[38:40].hex(), 16)    
    payloadsize = len(payload)
    udppayloadbytes = payload[43:]    
    analyzer = {'Destination MAC': destmac, 'Source MAC': sourcmac, 'Source IP': srcip, 
    'Source port': srcport, 'Destination IP': destip,
    'Destination port': destport, 'UDP lenght': udplen, 'Payload size': payloadsize, 
    'Payload': udppayloadbytes}
    return(analyzer)


