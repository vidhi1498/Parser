
from threading import Thread
import time
import random
from queue import Queue
import socket
from Extract_RawData import Extract_RawData 
from Queue_RawData import Queue_RawData
import struct
from kafka import KafkaProducer
import json

queue = Queue_RawData()
producer = KafkaProducer(bootstrap_servers='localhost:9092',
            value_serializer=lambda v: json.dumps(v).encode('utf-8'),
            compression_type="gzip")
extract = Extract_RawData(producer)
class ProducerThread(Thread):
    def run(self):
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        #conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        global queue
        while True:
            raw_packet, addr = conn.recvfrom(65536)
            eth_proto = struct.unpack('! H',raw_packet[12:14])
            eth_proto = socket.htons(eth_proto[0])
            proto = struct.unpack('! B', raw_packet[23:24])
            if eth_proto == 8:
                if proto[0] == 17:
                    queue.enqueue(raw_packet)
            


class ConsumerThread(Thread):
    def run(self):
        global queue
        while True:
            
            
            if queue.size() >= 1:
                print("queue.size()",queue.size())
                extract.parse(queue.dequeue())
            
def serializer(value):
        return json.dumps(value).encode()         


ProducerThread().start()
ProducerThread().setDaemon(True)

ConsumerThread().start()