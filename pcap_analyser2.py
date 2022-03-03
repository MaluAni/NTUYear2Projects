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
                dict = {i: (date_time.strftime("Timestamp: %d-%m-%Y %H:%M:%S.%f"), payload_analyse(bytes(payload)))}
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
                dict = {i: (date_time.strftime("Timestamp: %d-%m-%Y %H:%M:%S.%f"), payload_analyse(bytes(payload)))}
                capture.update(dict)
            except:
                continue
        
    return('Endianness:', magic, 'Major version: ', int(bytes(major).hex(), 16), 'Minor version: ', int(bytes(minor).hex(), 16), 'Timezone (0 is GMT): ', int(bytes(timezone).hex(), 16), 'Accuracy: ', int(bytes(accuracy).hex(), 16), 'Snap Length: ', int(bytes(snaplen).hex(), 16), 'Network type: ', int(bytes(network).hex(), 16), 'Packets: ', capture)
    
def payload_analyse(payload):
    destmac = str(payload[:1].hex()) + ':' + str(payload[1:2].hex()) + ':' + str(payload[2:3].hex()) + ':' + str(payload[3:4].hex()) + ':' + str(payload[4:5].hex()) + ':' + str(payload[5:6].hex())
    sourcmac = str(payload[6:7].hex()) + ':' + str(payload[7:8].hex()) + ':' + str(payload[8:9].hex()) + ':' + str(payload[9:10].hex()) + ':' + str(payload[10:11].hex()) + ':' + str(payload[11:12].hex())
    #ipvx = payload[24:52]
    srcip = str(int(payload[26:27].hex(), 16)) + '.' + str(int(payload[27:28].hex(), 16)) + '.' + str(int(payload[28:29].hex(), 16)) + '.' + str(int(payload[29:30].hex(), 16))
    destip = str(int(payload[30:31].hex(), 16)) + '.' + str(int(payload[31:32].hex(), 16)) + '.' + str(int(payload[32:33].hex(), 16)) + '.' + str(int(payload[33:34].hex(), 16))
    srcport = int(payload[34:36].hex(), 16)
    destport = int(payload[36:38].hex(), 16)
    udplen = int(payload[38:40].hex(), 16)
    #checksum = payload[80:84]
    payloadsize = len(payload)
    udppayloadbytes = payload[43:]
    #udppayload = "b'{}'".format(''.join('\\x{:02x}'.format(b) for b in udppayloadbytes)) 
    analyzer = {'Destination MAC': destmac, 'Source MAC': sourcmac, 'Source IP': srcip, 'Source port': srcport, 'Destination IP': destip,
    'Destination port': destport, 'UDP lenght': udplen, 'Payload size': payloadsize, 'Payload': udppayloadbytes}
    return(analyzer)


print('Python pcap file analyser\n Enter a pcap file name and select from the options provided\n')
file_name = input('Please enter the pcap file name:')    
#f = open(file_name , 'rb')
#out = open('E:\\NTU\\YEAR2\\CYBERSEC\\Assessment\\CyberSecurity2022.txt', 'a+')
#print(f.read(), file=out)
#print(pcap_analyse(f))
#payload = pcap_analyse(f)[11]
#print(payload_analyse(payload))
#f.close()

f = open(file_name , 'rb')
#print('Select one of the options below:\n')
#print('1. Header options\n 2. Payload options\n')
#user_option_main = input('Select option:\n')
#if user_option_main == '1':
#    print('Endianness: ', pcap_analyse(f)[1], '\nMajor version: ', pcap_analyse(f)[4])

susout = open('E:\\NTU\\YEAR2\\CYBERSEC\\Assessment\\CyberSecurity2022susact.txt', 'a+')
DNSout = open('E:\\NTU\\YEAR2\\CYBERSEC\\Assessment\\CyberSecurity2022DNS.txt', 'a+')
dict2 = pcap_analyse(f)[15]
#dict3 = dict2[1][1]
DHCPMagicCookie = b'\x63\x82\x53\x63'
DNSCode = b'\x00\x35'
DHCPArray = []
suspArray = []
DNSArray = []
DNSAddressArray = []
suspicious = ['gzip','rar','zip','tar','gif','png']
#if 'Stewie' in str(dict3['Payload']):
#    print(dict3['Payload'])
#else:
#    print('False')
for i in range (1, len(dict2)):
    dict3 = dict2[i][1]
    try:
        for element in suspicious:
            if element in str(dict3['Payload']):
                suspArray.append(dict2[i])
        if dict3['Destination port'] == 53:
            DNSQueryAddress = dict3['Payload'][12:(len(bytearray(dict3['Payload']))-4)].decode()
            dots = ['x00', 'x01','x02', 'x03', 'x04', 'x05', 'x06', 'x07', 'x08', 'x09', 'x0a', 'x0b', 'x0c', 'x0d', 'x0e', 'x0f']                  
            DNSQueryAddress = str(DNSQueryAddress).replace('\x00', '').replace('\x03', '.').replace('\x04', '.').replace('\x06', 
            '.').replace('\x08', '.').replace('\x10', '.').replace('\x0a', '.').replace('\x0c', '.').replace('\t', '.').replace('\n', 
            '.').replace('\x02', '.').replace('\x01', '.').replace('\x05', '.').replace('\x07', '.').replace('\x09', '.').replace('\x0b', 
            '.').replace('\x0d', '.').replace('\x0e', '.').replace('\x0f', '.')
            DNSAddressArray.append(DNSQueryAddress)
            DNSArray.append((dict2[i][0], DNSQueryAddress, 'DNSOut'))
        elif dict3['Source port'] == 53:
            DNSArray.append(dict2[i])
    except:
        continue
    
#print(suspArray, file=susout)
#print(DNSArray, file=DNSout)
print(DNSArray)



#for key in dict2:
#    dict3 = dict2[key][1]    
#    print(bytes(dict3['Payload']))
f.close()


#client_name = ''
#i = 0
#for byte in udppayloadbytes:        
#    if int(byte.hex(), 16) == 81:            
#        length = udppayloadbytes[i+1]
#        client_name = udppayloadbytes[i+4:length]
#    else:
#        i += 1
    







