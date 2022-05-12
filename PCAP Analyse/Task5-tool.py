from extraresources import *
from datetime import datetime

def DNSlog(payload):
    DNSAddressArray = []
    for i in range (1, len(payload)):    
        try:        
            if payload[i]['Destination port'] == 53:
                DNSQueryAddress = payload[i]['Payload'][12:(len(bytearray(payload[i]['Payload']))-4)].decode()                           
                DNSQueryAddress = str(DNSQueryAddress).replace('\x00', '').replace('\x03', '.').replace('\x04', '.').replace('\x06', 
                '.').replace('\x08', '.').replace('\x10', '.').replace('\x0a', '.').replace('\x0c', '.').replace('\t', '.').replace('\n', 
                '.').replace('\x02', '.').replace('\x01', '.').replace('\x05', '.').replace('\x07', '.').replace('\x09', '.').replace('\x0b', 
                '.').replace('\x0d', '.').replace('\x0e', '.').replace('\x0f', '.')
                DNSAddressArray.append(DNSQueryAddress)            
            
        except:
            continue
    return(DNSAddressArray)

def printPacketByNo(payload, option):
    printPacket = payload[option]
    return (printPacket)

def printPacketsByMAC(payload, option):
    MACArray = []
    for i in range (1, len(payload)):
        if payload[i]['Destination MAC'] == option or payload[i]['Source MAC'] == option:
            MACArray.append(payload[i])
    if MACArray != []:
        return(MACArray)
    else:
        return('MAC Address not found!')

def printPacketsByIP(payload, option):
    IPArray = []
    for i in range (1, len(payload)):
        if payload[i]['Destination IP'] == option or payload[i]['Source IP'] == option:
            IPArray.append(payload[i])
    if IPArray != []:
        return(IPArray)
    else:
        return('IP Address not found!')

def printPacketsByTime(payload, option1, option2):
    TimeArray = []
    for i in range (1, len(payload)):
        if payload[i]['Time'] > option1 and payload[i]['Time'] < option2:
            TimeArray.append(payload[i])
    if TimeArray != []:
        return(TimeArray)
    else:
        return('Time out of range!')



print('Python pcap file analyser\n')
file_name = input('Please enter the pcap file name:')

f = open(file_name , 'rb')

if f.read(4) != b'\xd4\xc3\xb2\xa1':
    print('Not a valid pcap file')
    f.close()
else:
    f = open(file_name , 'rb')
    data = pcap_analyse(f)[15]
    print('--------------------------------------------------------')
    print('Select from the following options:')
    print('1. DNS log')
    print('2. Print packet by number')
    print('3. Print packets by MAC address')
    print('4. Print packets by IP address')
    print('5. Print packets by time')
    print('0, Exit or Quit to Close')

    option = input('Enter your choice: \n')

    while option not in ['0', 'Exit', 'Quit', 'X', 'x', 'Q', 'q', 'exit', 'quit', 'EXIT', 'QUIT']:
        if option == '1':
            print('Printing the DNS Log...')
            for element in DNSlog(data):
                print(element)
            print('Task complete')
            print('--------------------------------------------------------')
            print('Select from the following options:')
            print('1. DNS log')
            print('2. Print packet by number')
            print('3. Print packets by MAC address')
            print('4. Print packets by IP address')
            print('5. Print packets by time')
            print('0, Exit or Quit to Close')
            option = input('Enter your choice: \n')
        elif option == '2':
            print('Maximum packet number is: ', len(data))
            try:
                option2 = int(input('Please enter the packet number for printing \n'))                           
                if  option2 <= len(data)+1:
                    print('Printing the required packet...')
                    print(printPacketByNo(data, option2))
                    print('Task complete')
                    print('--------------------------------------------------------')
                    print('Select from the following options:')
                    print('1. DNS log')
                    print('2. Print packet by number')
                    print('3. Print packets by MAC address')
                    print('4. Print packets by IP address')
                    print('5. Print packets by time')
                    print('0, Exit or Quit to Close')        
                    option = input('Enter your choice: \n')                        
                else:
                    print('Maximum packet number is: ', len(data))        
                    option2 = int(input('Please enter the packet number for printing \n'))
            except:
                print('Option must be integer between 1 and ', len(data))
                option2 = int(input('Please enter the packet number for printing \n'))
        elif option == '3':
            option3 = input('Please enter the MAC address in format xx:xx:xx:xx:xx:xx\n')
            print('Printing the required packets...')        
            if printPacketsByMAC(data, option3) != 'MAC Address not found!':
                for element in printPacketsByMAC(data, option3):
                    print(element)
                print('Task complete')
                print('--------------------------------------------------------')
                print('Select from the following options:')
                print('1. DNS log')
                print('2. Print packet by number')
                print('3. Print packets by MAC address')
                print('4. Print packets by IP address')
                print('5. Print packets by time')
                print('0, Exit or Quit to Close')
                option = input('Enter your choice: \n')
            else:
                print('MAC Address not found!')
                print('--------------------------------------------------------')
                print('Select from the following options:')
                print('1. DNS log')
                print('2. Print packet by number')
                print('3. Print packets by MAC address')
                print('4. Print packets by IP address')
                print('5. Print packets by time')
                print('0, Exit or Quit to Close')
                option = input('Enter your choice: \n')
        elif option == '4':
            option4 = input('Please enter the IP address in format xxx.xxx.xxx.xxx\n') 
            print('Printing the required packets...')        
            if printPacketsByIP(data, option4) != 'IP Address not found!':
                for element in printPacketsByIP(data, option4):
                    print(element)
                print('Task complete')
                print('--------------------------------------------------------')
                print('Select from the following options:')
                print('1. DNS log')
                print('2. Print packet by number')
                print('3. Print packets by MAC address')
                print('4. Print packets by IP address')
                print('5. Print packets by time')
                print('0, Exit or Quit to Close')
                option = input('Enter your choice: \n')
            else:
                print('IP Address not found!')
                print('--------------------------------------------------------')
                print('Select from the following options:')
                print('1. DNS log')
                print('2. Print packet by number')
                print('3. Print packets by MAC address')
                print('4. Print packets by IP address')
                print('5. Print packets by time')
                print('0, Exit or Quit to Close')
                option = input('Enter your choice: \n')
        elif option == '5':
            option5 = input('Please enter the first time in format DD-MM-YYYY HH:MM:SS\n')
            option6 = input('Please enter the second time in format DD-MM-YYYY HH:MM:SS\n') 
            print('Printing the required packets...')        
            if printPacketsByTime(data, option5, option6) != 'Time out of range!':
                for element in printPacketsByTime(data, option5, option6):
                    print(element)
                print('Task complete')
                print('--------------------------------------------------------')
                print('Select from the following options:')
                print('1. DNS log')
                print('2. Print packet by number')
                print('3. Print packets by MAC address')
                print('4. Print packets by IP address')
                print('5. Print packets by time')
                print('0, Exit or Quit to Close')
                option = input('Enter your choice: \n')
            else:
                print('IP Address not found!')
                print('--------------------------------------------------------')
                print('Select from the following options:')
                print('1. DNS log')
                print('2. Print packet by number')
                print('3. Print packets by MAC address')
                print('4. Print packets by IP address')
                print('5. Print packets by time')
                print('0, Exit or Quit to Close')
                option = input('Enter your choice: \n')
        elif option not in ['1', '2', '3', '4', '5']:
                print('Not a valid choice, please try again...')
                print('--------------------------------------------------------')
                print('Select from the following options:')
                print('1. DNS log')
                print('2. Print packet by number')
                print('3. Print packets by MAC address')
                print('4. Print packets by IP address')
                print('5. Print packets by time')
                print('0, Exit or Quit to Close')
                option = input('Enter your choice: \n')    
    else:
        print('Exiting...')
        input('Press Enter to close...')     
    print('--------------------------------------------------------------------------------------------')