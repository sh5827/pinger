from socket import *
import os
import sys
import struct
import time
import select
import binascii
# Should use stdev
from statistics import stdev 

ICMP_ECHO_REQUEST = 8
def checksum(string):
    csum = 0
    countTo = (len(string) // 2) * 2
    count = 0

    while count < countTo:
        thisVal = (string[count + 1]) * 256 + (string[count])
        csum += thisVal
        csum &= 0xffffffff
        count += 2

    if countTo < len(string):
        csum += (string[len(string) - 1])
        csum &= 0xffffffff

    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer



def receiveOnePing(mySocket, ID, timeout, destAddr):
    timeLeft = timeout

    while 1:
        startedSelect = time.time()
        whatReady = select.select([mySocket], [], [], timeLeft)
        howLongInSelect = (time.time() - startedSelect)
        if whatReady[0] == []:  # Timeout
            return "Request timed out."

        timeReceived = time.time()
        recPacket, addr = mySocket.recvfrom(1024)

        # Fill in start
        # Fetch the ICMP header from the IP packet
        global packet_min, packet_max, packet_sum , stdev_var , roundTrip_cnt
        
        type, code, checksum, id, seq = struct.unpack('bbHHh', recPacket[20:28])
        if type != 0:
            return 'expected type=0, but got {}'.format(type)
        if code != 0:
            return 'expected code=0, but got {}'.format(code)
        if ID != id:
            return 'expected id={}, but got {}'.format(ID, id)
        trans_time, = struct.unpack('d', recPacket[28:])
        roundTrip = (timeReceived - trans_time) * 1000
        stdev_var.append(roundTrip)
        
        roundTrip_cnt += 1
        packet_sum += roundTrip
        packet_min = min(packet_min, roundTrip)
        packet_max = max(packet_max, roundTrip)
        ip_pkt_head = struct.unpack('!BBHHHBBH4s4s', recPacket[:20])
        ttl = ip_pkt_head[5]
        saddr = inet_ntoa(ip_pkt_head[8])
        length = len(recPacket) - 20
        return 'Reply from {}: bytes={} time={:.7f}ms TTL={}'.format(saddr,length, roundTrip,ttl)

        # Fill in end
        timeLeft = timeLeft - howLongInSelect
        if timeLeft <= 0:
            return "Request timed out."


def sendOnePing(mySocket, destAddr, ID):
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)

    myChecksum = 0
    # Make a dummy header with a 0 checksum
    # struct -- Interpret strings as packed binary data
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    data = struct.pack("d", time.time())
    # Calculate the checksum on the data and the dummy header.
    myChecksum = checksum(header + data)

    # Get the right checksum, and put in the header

    if sys.platform == 'darwin':
        # Convert 16-bit integers from host to network  byte order
        myChecksum = htons(myChecksum) & 0xffff
    else:
        myChecksum = htons(myChecksum)


    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    packet = header + data

    mySocket.sendto(packet, (destAddr, 1))  # AF_INET address must be tuple, not str


    # Both LISTS and TUPLES consist of a number of objects
    # which can be referenced by their position number within the object.

def doOnePing(destAddr, timeout):
    icmp = getprotobyname("icmp")


    # SOCK_RAW is a powerful socket type. For more details:   http://sockraw.org/papers/sock_raw
    mySocket = socket(AF_INET, SOCK_RAW, icmp)

    myID = os.getpid() & 0xFFFF  # Return the current process i
    sendOnePing(mySocket, destAddr, myID)
    delay = receiveOnePing(mySocket, myID, timeout, destAddr)
    mySocket.close()
    return delay


def ping(host, timeout=1):
    global packet_min, packet_max, packet_sum , stdev_var , roundTrip_cnt
    packet_min = float('+inf')
    packet_max = float('-inf')
    packet_sum = 0
    count = 0
    roundTrip_cnt = 0
    stdev_var = []
    
    # timeout=1 means: If one second goes by without a reply from the server,  	# the client assumes that either the client's ping or the server's pong is lost
    dest = gethostbyname(host)
    print("Pinging " + dest + " using Python:")
    print("")
    
    for i in range(0,4):
        count += 1
        delay = doOnePing(dest, timeout)
        print(delay)
        time.sleep(1)  # one second
    if(len(stdev_var)==0):
        packet_min = 0
        packet_max = 0
        stdev_var.append(0)
        stdev_var.append(0)
    packet_avg = packet_sum/4
    # Calculate vars values and return them
    vars = [str(round(packet_min, 2)), str(round(packet_avg, 2)), str(round(packet_max, 2)),str(round(stdev(stdev_var), 2))]
    # Send ping requests to a server separated by approximately one second
    if count != 0:
        print('\n--- {} ping statistics ---'.format(host))
        print('{} packets transmitted, {} packets received, {:.1f}% packet loss'.format(count, roundTrip_cnt,
                                                                                        100.0 - roundTrip_cnt * 100.0 / count))
        print('round-trip min/avg/max/stddev {}/{}/{}/{} ms'.format(vars[0] , vars[1] , vars[2], vars[3]))
        
    return vars

if __name__ == '__main__':
    ping("google.co.il")
