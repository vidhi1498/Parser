#! /usr/local/bin/python3.6
from queue import Queue
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import as_completed
from ObjectDto import ObjectDto
import multiprocessing
import socket
import struct
from threading import Thread
import textwrap
import numpy
from bitarray import bitarray
from bitstring import BitArray
from Queue_RawData import Queue_RawData
import time
import logging
import json
from kafka import KafkaProducer
from time import sleep


class Extract_RawData():
    identification_map = {}
    batch_dict = {}
    batch_size = 0

    def __init__(self,producer):
        self.producer = producer




    def parse(self,raw_data):
        
        
        dest_mac, src_mac, eth_proto, data = self.ethernet_frame(raw_data)
        print("eth_proto",eth_proto)
        if eth_proto == 8:
            (version, header_length, ttl, proto, src, target, data) = self.ipv4_Packet(data)
            print("proto",proto)

            #udp
            if proto == 17:
                print("proto",proto)
                source_port, dest_port, length, data = self.udp_seg(data)
                parsed_info_object = {'src_mac':src_mac,'dest_mac':dest_mac,'source_port':source_port,'dest_port':dest_port}
                
                
                if source_port == 53:
                    objectDto = ObjectDto()
                    objectDto.source_port = source_port
                    objectDto.destination_port = dest_port
                    objectDto.src_mac_address = src_mac
                    objectDto.dest_mac_address = dest_mac#inbound
                    objectDto.source_ip = src.rstrip(".")
                    objectDto.destination_ip = target.rstrip(".")
                    objectDto = self.parse_response(data,objectDto)
                    
                    response_dict = self.write_object_to_file(objectDto)
                    self.batch_dict[self.batch_size+1] = response_dict
                    self.batch_size = self.batch_size + 1
                    print("batch size + 1",self.batch_size)

                    if self.batch_size == 3:
                        self.batch_size = 0
                        self.produce(self.batch_dict)
                        batch_dict = {}
                        




    def serializer(self,value):
        return json.dumps(value).encode()

    
    def produce(self,response_dict):
        self.producer.send('dns_parser',response_dict)
        
        
            


    def parse_request(self,data):
        print("parse request")
        byte_array=bytearray(data)
        print(type(byte_array))
        Bits = numpy.unpackbits(byte_array)
        identification_no = struct.unpack('! H',data[:2])
        qr , opcode ,AA ,TC ,RD ,RA ,RCode = self.dns_seg(Bits)

        QDCount,ANcount,NSCount,ARcount = struct.unpack('! H H H H',data[4:12])
        value = len(data)-16
                    
        #questio section
        qname_value , length_of_qname = self.qname_def(bytearray(data[12:]))
                   

        queryType , queryClass = struct.unpack('! 2s 2s',data[(12+length_of_qname):len(data)]) 
        
        # identification number and value is length of domain-name
        self.identification_map.update({identification_no : value})



    
        print("identification_no",identification_no[0])
        print("qr =",qr)
        print("Opcode =",opcode[0])
        print("AA =",AA)
        print("TC =",TC)
        print("RD =",RD)
        print("RA =",RA)
        print("RCode =",RCode[0])
        print("QDCount=",QDCount)
        print("ANcount=",ANcount)
        print("NSCount=",NSCount)
        print("ARcount=",ARcount)
        print("----------------------------------Question Section-----------------------------")
        print("queryDomainName=",qname_value)
        print("queryType =",queryType.hex())
        print("queryClass =",queryClass.hex())


    
    
    


    # unpack response packet
    def parse_response(self,data,parsed_info_object):
       

        print(type(data))
        byte_array=bytearray(data)
        print(type(byte_array))
        Bits = numpy.unpackbits(byte_array)
        identification_no = struct.unpack('! H',data[:2])
        qr , opcode ,AA ,TC ,RD ,RA ,RCode = self.dns_seg(Bits)
        QDCount,ANcount,NSCount,ARcount = struct.unpack('! H H H H',data[4:12])

        if identification_no in self.identification_map:
            value = self.identification_map[identification_no]
            




        qname_value , length_of_qname = self.qname_def(bytearray(data[12:]))
        queryType , queryClass = struct.unpack('! 2s 2s',data[12+length_of_qname : 16+length_of_qname]) 
        
        #parsed_info_object['question'] = ques_dict
        parsed_info_object.question = qname_value.rstrip(".") 
        responder_section=16+length_of_qname
                   
                    
                    
        data_label=0
        pointer_label=0
        label_decider = bytearray(data[responder_section:responder_section+2])
        bits_array = numpy.unpackbits(label_decider)
        if (bits_array[0]==1):
            if(bits_array[1]==1):
                pointer_label =1
        else:
            data_label=1

        s = bitarray('00')
        for x in numpy.nditer(bits_array[2:]):
            s.append(x)
        
        offset_value = numpy.uint16(s)  

        type_record,class_value,TTl,data_length = struct.unpack('!  2s 2s I H ',data[responder_section+2: (12+responder_section)])
        resouce_domainname_length = offset_value[1]-4+1  #not from 0

        print("resouce_domainname_length",resouce_domainname_length)
        print("12+responder_section+resouce_domainname_length",12+responder_section+resouce_domainname_length)
        SOA ={}
        A_Record={}
        TXT={}
        NS={}
        

        #SOA
        if type_record.hex() == '0006':
            print("--------------------------------------AUTHORITY SECTION----------------------------------------")
            print("length of data",len(data))
                            
            print("type_record",type_record.hex())
            print("class_value",class_value.hex())
            print("ttl =",TTl)
            print("data_length =",data_length)
            SOA=self.parseSOA(data,responder_section,offset_value) #resonder_section is offset for raw length
        
        # A Record
        elif type_record.hex() == '0001':
            resource_names = ""
            data_byteArray = bytearray(data[responder_section+12:])
            for i in range(len(data_byteArray)):
                resource_names = resource_names+str(data_byteArray[i])+"."
            A_Record = {'ttl':TTl,'ip':resource_names.rstrip(".")}
                           
            print("--------------------------------------ANSWER SECTION----------------------------------------")
                            
            print("type_record",type_record.hex())
            print("class_value",class_value.hex())
            print("ttl =",TTl)
            print("ip = ",resource_names)

         
        #TXT 
        elif type_record.hex() == '0010':
            TXT = self.parse_record(data,responder_section,ANcount)
            
            

        #NS
        elif type_record.hex() == '0002':
            print("NS",data)
            print("label_decider",label_decider)
            if data_label ==1:
                NS = self.parse_record(data,responder_section,ANcount)
            else:
                NS = self.parse_ans_with_offset(data,responder_section,ANcount,offset_value[1])
            

        print("SOA",SOA)
        parsed_info_object.SOA = SOA
        parsed_info_object.A_Record = A_Record
        parsed_info_object.TXT = TXT
        parsed_info_object.NS = NS

        return parsed_info_object

                            
  

                    
    
                                
            







    # Unpack Ethernet Frame
    def ethernet_frame(self,data):


        dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
        return self.get_mac_addr(dest_mac), self.get_mac_addr(src_mac), socket.htons(proto), data[14:]

    def parseSOA(self,data,responder_section,offset_value):
        SOA_dict = {}

        length_of_pri_ns = len(data)-12-responder_section -20
        resource_names ,length = self.rData_Compression(data,bytearray(data[12+responder_section:]),offset_value[1],length_of_pri_ns)

        offset_to_admin = len(data)-20
                            
        serial_no = struct.unpack('! I',data[offset_to_admin:offset_to_admin+4])
        refresh_interval = struct.unpack('! I',data[offset_to_admin+4:offset_to_admin+8])
        retry_interval = struct.unpack('! I',data[offset_to_admin+8:offset_to_admin+12])
        expiration_limit = struct.unpack('! I',data[offset_to_admin+12:offset_to_admin+16])
        min_ttl = struct.unpack('! I',data[offset_to_admin+16:offset_to_admin+20])
        SOA_dict = {'primary_ns':resource_names[0],'admin_mb':resource_names[1],'serial_no':serial_no[0],'refresh_interval':refresh_interval[0],'retry_interval':retry_interval[0],'expiration_limit':expiration_limit[0],'min_ttl':min_ttl[0]}
    
        
                            
        print("primary_ns = ",resource_names[0])
        print("admin_mb = ",resource_names[1])
        print("serial_no = ",serial_no[0])
        print("refresh_interval = ",refresh_interval[0])
        print("retry_interval = ",retry_interval[0])
        print("expiration_limit = ",expiration_limit[0])
        print("min-ttl = ",min_ttl[0])
        return SOA_dict

    def parse_record(self,data,responder_section,ANcount):
        List = []
        print("data",data)
        length = responder_section
        new_length = length + 12
        if ANcount != 0:
            while(ANcount>=0):
                if new_length >= len(data):
                    break
                Txt_dict = {}
                print("new_length",new_length)
                print("length+2",length+2)
                type_record,class_value,TTl,data_length = struct.unpack('!  2s 2s I H ',data[length+2:new_length])
                qname , add_to_length= self.getQnameResource(bytearray(data[new_length:]))
                print("type_record = ",type_record)
                print("class_value = ",class_value)
                print("TTL = ",TTl)
                print("qname =",qname)
                length = new_length +add_to_length
                new_length = length + 12
                print("new_length",new_length)
                print("length+2",length+2)
                Txt_dict = {'TTl':TTl,'qname':qname}                  
                List.append(Txt_dict)                    
                ANcount = ANcount - 1;
                print(len(data))
            print("End of while!!")
        return List

    def parse_ans_with_offset(self,data,responder_section,ANcount,offset_value):
        List = []
        length = responder_section
        new_length = length + 12
        if ANcount != 0:
            while(ANcount>=0):
                if new_length >= len(data):
                    break
                Txt_dict = {}
                print("new_length",new_length)
                print("length+2",length+2)
                type_record,class_value,TTl,data_length = struct.unpack('!  2s 2s I H ',data[length+2:new_length])
                qname , add_to_length= self.getQnameResource_with_pointer(data,bytearray(data[new_length:]),offset_value)
                print("type_record = ",type_record)
                print("class_value = ",class_value)
                print("TTL = ",TTl)
                print("qname =",qname)
                length = new_length +add_to_length
                new_length = length + 12
                print("new_length",new_length)
                print("length+2",length+2)
                Txt_dict = {'TTl':TTl,'qname':qname}                   
                List.append(Txt_dict)          
                ANcount = ANcount - 1;
                print(len(data))
            print("End of while!!")
        return List



    # Format MAC Address
    def get_mac_addr(self,bytes_addr):

        bytes_str = map('{:02x}'.format, bytes_addr)
        mac_addr = ':'.join(bytes_str).upper()
        return mac_addr

    # Unpack IPv4 Packets Recieved
    def ipv4_Packet(self,data):

        version_header_len = data[0]
        version = version_header_len >> 4
        header_len = (version_header_len & 15) * 4
        ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
        return version, header_len, ttl, proto, self.ipv4(src), self.ipv4(target), data[header_len:]

    # Returns Formatted IP Address
    def ipv4(self,addr):
        return '.'.join(map(str, addr))


    # Unpacks for any ICMP Packet
    def icmp_packet(data):

        icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
        return icmp_type, code, checksum, data[4:]

    # Unpacks for any TCP Packet
    def tcp_seg(data):
        (src_port, destination_port, sequence, acknowledgenment, offset_reserv_flag) = struct.unpack('! H H L L H', data[:14])
        offset = (offset_reserv_flag >> 12) * 4
        flag_urg = (offset_reserved_flag & 32) >> 5
        flag_ack = (offset_reserved_flag & 32) >>4
        flag_psh = (offset_reserved_flag & 32) >> 3
        flag_rst = (offset_reserved_flag & 32) >> 2
        flag_syn = (offset_reserved_flag & 32) >> 1
        flag_fin = (offset_reserved_flag & 32) >> 1

        return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]


    # Unpacks for any UDP Packet
    def udp_seg(self,data):
        src_port, dest_port, size = struct.unpack('! H H H 2x', data[:8])
        return src_port, dest_port, size, data[8:]

    # Formats the output line
    def format_output_line(prefix, string, size=80):
        size -= len(prefix)
        if isinstance(string, bytes):
            string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
            if size % 2:
                size-= 1
                return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])



    def dns_seg(self,Bits):

        return Bits[16] ,struct.unpack('I',Bits[17:21]) , Bits[21], Bits[22],Bits[23],Bits[24] ,struct.unpack('I',Bits[28:32])

    def ByteToHex( byteStr ):
            

        return ''.join( [ "%02X " % ord( x ) for x in byteStr ] ).strip()
    # Data Label
    def qname_def(self,qname_byte_array):
        i=0
        j=1
        qname_value = ""
        while qname_byte_array[i]!=0:
            size = qname_byte_array[i]
            while size>0 :
                if i+1 < len(qname_byte_array) :
                    qname_value = str(qname_value) + (struct.unpack('! s', qname_byte_array[i+1:i+2])[0]).decode()
                    i=i+1
                size = size -1
            qname_value = str(qname_value)+'.'
            print("!!qname_value",qname_value)
            i = i + 1
            print("i==",i)
        length = i+1 #next data length
        return qname_value , length 

    # Compression Label

    def rData_Compression(self,data,rData_byte_array,offset_value,length_of_pri_ns):
        print("rData_byte_array===>",rData_byte_array)  
        i=0
        j=1
        p=0
        qname_value = ""
        print("length_of_pri_ns",length_of_pri_ns)
        List = [] 
        while p!=(length_of_pri_ns-1):
            size = rData_byte_array[i]
            p=p+1
            while size>0 :
                if i+1 < (length_of_pri_ns) :
                    qname_value = str(qname_value) + (struct.unpack('! s', rData_byte_array[i+1:i+2])[0]).decode()
                    i=i+1
                    p=p+1
                size = size -1
            #qname_value = qname_value+'.'
            print("qname_value",qname_value)
            i = i + 1
            print("i==",i)
            if p == length_of_pri_ns:
                break
            offset = (struct.unpack('! B', rData_byte_array[i:i+1])[0])
            print("offset",offset)
            print("offset_value",offset_value)
            if (struct.unpack('! B', rData_byte_array[i:i+1])[0]) == 192:
                qnames,size = self.qname_def(bytearray(data[offset_value:]))
                qname_value = qname_value+'.'+ qnames
                List.append(qname_value)
                qname_value = ""
                print("main-qname_value",qname_value)
                i=i+2
                p=p+1
            print("After internal while i=",i)
        length = i+1 #next data length
        return List , length 

    def getQnameResource(self,data_bytes):
        i=0
        qname =""
        length = 0
        rest_length =0
        print("length of data_bytes",len(data_bytes))
        print("len",rest_length)
        print("data_byes",data_bytes)
        print("data_bytes[i]",data_bytes[i])
        while data_bytes[i]!=192: 
            if len(data_bytes)==rest_length+1:
                break
            if i+1 < len(data_bytes) :
                qname = qname + struct.unpack('s',data_bytes[i:i+1])[0].decode()
                length = length + 1
                i = i +1
                rest_length = rest_length +1

        return qname , length
    def getQnameResource_with_pointer(self,data,data_bytes,offset_value):
        i=0
        count=0
        qname =""
        length = 0
        rest_length =0
        print("length of data_bytes",len(data_bytes))
        print("len",rest_length)
        print("data_byes",data_bytes)
        while data_bytes[i]!=192: 
            if i+1 < len(data_bytes) :
                qname = qname + struct.unpack('s',data_bytes[i:i+1])[0].decode()
                length = length + 1
                i = i +1
                rest_length = rest_length +1
            if data_bytes[i]==192 : 
                print("data_bytes[offset_value:]",data_bytes[offset_value:])
                qnames,size = self.qname_def(bytearray(data[offset_value:]))
                qname = qname + "."+qnames
                length = length + 2
                i=i+2
                rest_length = rest_length +2
            if len(data_bytes)==rest_length:
                break


        return qname , length

    def write_object_to_file(self,dtoObject):
        #add in json and dump it in file:
        print("in write")
        dtoobject_dict = {'source_ip':dtoObject.source_ip,'destination_ip':dtoObject.destination_ip,'source_port':dtoObject.source_port,'destination_port':dtoObject.destination_port,'src_mac_address':dtoObject.src_mac_address,'dest_mac_address':dtoObject.dest_mac_address,'query-name':dtoObject.question, 'A_Record':dtoObject.A_Record,'TXT':dtoObject.TXT,'SOA':dtoObject.SOA,'NS':dtoObject.NS}
        
        #with open('parse_dns_respons.txt', 'a+') as json_file:
            #json.dump(dtoobject_dict, json_file)

        return dtoobject_dict



    

