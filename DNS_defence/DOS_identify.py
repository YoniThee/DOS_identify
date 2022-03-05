"""
Auther: Yehonatan Thee
description: This script is get an pcap file with Dos attack.
The purpose is to identify all the fishy IP that attacking the server.
all one IP address that send SYN to the server and not waiting for ACK is fishy, because here is no reason to do this
unless the intention is to overload on the server
"""
from scapy.all import *

ACK = 0x010
SYN = 0x002
SYNACK = 0x012
ATTACKED_IP = "69.90.200.90"
DEFAULT_TIMEOUT = 0.003


def get_all_syn(packet_list):
    """
    :param packet_list: all the packet that was sniffed in the file
    :return: list of tuples with all the SYN packets
    """
    temp_ack_list = []
    get_src_seq = lambda packet: (packet[IP].src, packet[TCP].time)

    for pack in packet_list:
        if pack[TCP].flags == 'S' and pack[IP].dst == ATTACKED_IP:
            temp_ack_list.append(get_src_seq(pack))
    return temp_ack_list


def compare(IP1, IP2, time_sniffed1, time_sniffed2):
    """
    This function get IP and time sniffed of 2 packets, if the same ip is send 2 SYN  request and not waiting to
     get back ACK is fishy, because he suppose to wait up to timeout and not send more and more SYN
    """
    if IP1 == IP2 and remainder(time_sniffed1,time_sniffed2):
        return IP1


def remainder(time1,time2):
    """
    This function is check the remainder between to times, and return true if the result is less of the default timeout
    in TCP
    """
    if time2-time1 < DEFAULT_TIMEOUT:
        return True
    else:
        return False


def get_the_fishy(SYN_list):
    """
    :param SYN_list: List of tuples with all the IP addresses of ack from file and their SYN
    :return: All the fishy IP addresses by the logic that I wrote in the compare function
    """
    # We start at to put the same IP linked so sort the list by IP
    SYN_list.sort(key = lambda x:x[0])

    fishy = []
    # Compare between all pair IP's if they are the same, if they have also the same, or very close to the same time
    for i in range(0, len(SYN_list) - 1):
        temp = compare(SYN_list[i][0], SYN_list[i + 1][0], SYN_list[i][1], SYN_list[i + 1][1])
        # If temp isn't None so this is fishy IP!
        if temp != None:
            fishy.append(temp)

    result = []
    # Delete the duplicates IP's
    [result.append(x) for x in fishy if x not in result]
    print(len(result))
    print(result)
    return result


def export_to_file(fishies):
    text_file = open("fishyIP.txt", "w")
    text_file.write('All of this IP is fishy!\n')
    for element in fishies:
        text_file.write(element + "\n")
    text_file.close()
    print("the fishies IP is in the file!")


def main():
    pcapFile = rdpcap(r"C:\Users\Thee\PycharmProjects\DNS_defence\SynFloodSample.pcap")
    SYN_list = get_all_syn(pcapFile)
    fishies = get_the_fishy(SYN_list)
    export_to_file(fishies)



if __name__ == '__main__':
    main()

