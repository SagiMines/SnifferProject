import subprocess
from subprocess import run
import socket
from tkinter import *
import tkinter.messagebox
from tkinter.ttk import *
from tkinter import scrolledtext
import datetime
from datetime import datetime, timedelta
import os
import platform
import uuid
import pyodbc
from scapy import *
from scapy.layers.inet import TCP, UDP, IP
from scapy.all import *
import ipaddress
from urllib.request import *
import json
from threading import *

global B
all_packets = []

ROUND_NUM = 20
UDP_IP = '10.100.102.7'
UDP_PORT = 5005
BUFFER_SIZE = 1024
NETSTAT = "netstat -nb"
ROOT = Tk()

def get_country_of_ip(ip):
    """
    This function gets the country by the given IP.
    param ip: ip address
    type ip: string
    return: The IP's country
    rtype: string
    """
    try:
        return urlopen(FREE_GEOIP_CSV_URL % ip).read().decode()
    except:
        return ""

def analyze_packets_and_report():
    """
    This function adds countries data and reports all the packets to the server.
    return: None
    rtype: None
    """
    global B
    global all_packets
    B.insert(INSERT, "trying to send " + str(len(all_packets)) +  " packets")
    ROOT.update()  # updates the Tkinter form
    time.sleep(1)
    B.insert(INSERT, "\n")
    send_to_manager(all_packets)
    B.insert(INSERT, "Reported " + str(len(all_packets)) + " Packets to manager")
    ROOT.update()  # updates the Tkinter form
    time.sleep(1)
    B.insert(INSERT, "\n")

def is_private(ip):
    """
    param ip: ip address
    type ip: string
    return: True if the address is allocated for private network, otherwise False
    rtype: bool
    """
    return ipaddress.ip_address(str(ip)).is_private

def is_outgoing(src_ip, dst_ip):
    """
    param src_ip: source ip address
    param dst_ip: destination ip address
    type src_ip: string
    type dst_ip: string
    return: True if the addressis allocated for privatr network, otherwise False
    rtype: bool
    """
    return is_private(src_ip)

def get_processes():
    """
    This function organized information on processes and ports on the ccomputer.
    return: Dictionary that contains port as key and program as value
    rtype: dict
    """
    output = subprocess.run(NETSTAT, shell=True, stdout=subprocess.PIPE, universal_newlines=True, timeout=10)
    lines = output.stdout.split("\n")
    get_next = False
    all_src_ports = {}
    for line in lines:
        if get_next:
            if ".exe" in line:  # if it's really the app name
                clean_line = line.strip("[] ")
                all_src_ports[current_port] = clean_line
            get_next = False
        if "TCP" in line or "UDP" in line:
            x = line.find(":")  # location of the ':'
            current_port = 0
            try:
                current_port = int(line[x + 1: x + 6])
            except:
                pass
            get_next = True

    return all_src_ports

def get_src_dst_ip_port(packet):
    """
    param packet: packet from the sniffing
    type packet: packet
    return: The destination and the source port and ip
    rtype: 4 int
    """
    srcport, dstport = 0, 0
    if TCP in packet:
        srcport = packet[TCP].sport
        dstport = packet[TCP].dport
    if UDP in packet:
        srcport = packet[UDP].sport
        dstport = packet[UDP].dport
    return packet[IP].src, packet[IP].dst, srcport, dstport

def filter_packets(packet):
    """
    :param packet:
    type packet: packet
    :return: If the packet contains IP
    :rtype string
    """
    return IP in packet

def get_application_for_packet(packet, our_port):
    """
    This function gets the application for the given port.
    param packet: packet from the sniffing
    param out_port: source port
    :type packet: packet
    type our_port: string
    return: The app of the source code
    rtype: string
    """
    src_ports = get_processes()

    # Check the app for the relevant port, if there are any
    if our_port in src_ports:
        app = src_ports[our_port]
        return app
    return "Unknown"

def handle_packet(packet):
    """
    This function organized all the data into json structures and puts every json into a list
    :param packet:sniffed packed
    type packet: packet
    return: None
    rtype: None
    """
    global B
    global all_packets

    # get src and dst ip and port regadless of the protocol (udp/tcp)
    ip_ports = get_src_dst_ip_port(packet)
    src_ip, dst_ip, src_port, dst_port = ip_ports

    src_mac = getmacbyip(packet[IP].src).upper()
    if packet[IP].src == '10.100.102.7':
        src_mac = str(':'.join(['{:02x}'.format((uuid.getnode() >> i) & 0xff) for i in range(0, 8 * 6, 8)][::-1])).upper()

    #sending to sql database
    sql = str(packet[IP].src)+"$"+str(src_port)+"$"+str(packet[IP].dst)+"$"+str(dst_port)+"$"+str(src_mac)
    send_message2(sql)

    message = "Source IP: " + str(packet[IP].src) + ", Source port: " + str(src_port) + ", Destination IP: " + str(packet[IP].dst) + ", Destination port: " + str(dst_port) + ", Source MAC: " + str(src_mac)
    send_message2(message)

    # check if the packet is outgoing or incoming (works only if our ip is private)
    outgoing = is_outgoing(src_ip, dst_ip)

    # set properties according to incoming /outgoing
    our_port = 0
    external_port = 0
    external_ip = ""

    if outgoing:
        our_port = src_port
        external_port = dst_port
        external_ip = dst_ip
    else:
        our_port = dst_port
        external_port = src_port
        external_ip = src_ip

    ## APP STUFF ##
    app = get_application_for_packet(packet, our_port)

    packet_dict = {}
    packet_dict["Source IP"] = packet[IP].src
    packet_dict["Source port"] =src_port
    packet_dict["Destination IP"] = packet[IP].dst
    packet_dict["Destination port"] = dst_port
    all_packets.append(packet_dict)
    ROOT.update()  # updates the Tkinter form


def send_to_manager(all_packets):
    """
    This function sends the json to the manager.
    param all_packets: all the packets and their data
    type all_packets: list
    return: None
    rtype: None
    """
    # Create a non_specific UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = (UDP_IP, UDP_PORT)

    # Creating message and sending
    data = json.dumps(all_packets)
    #sock.sendto(str.encode(data), server_address)

    #sock.close()

def get_user_mac():
    """
    This function collects the user's MAC address.
    :return: str
    """
    return str(':'.join(['{:02x}'.format((uuid.getnode() >> i) & 0xff) for i in range(0, 8 * 6, 8)][::-1])).upper()

def get_user_computer_name():
    """
    This function collects the user's computer name.
    :return: str
    """
    #platform.node()
    cmp_name = socket.gethostname() #socket.gethostname()
    cmp_namestr = str(cmp_name)
    return cmp_namestr

def get_user_ip():
    """
    This function collects the user's IP.
    :return: str
    """
    hostname = socket.gethostname()
    IPAddr = socket.gethostbyname(hostname)
    ipstr = str(IPAddr)
    return ipstr

def user_current_time():
    """
    This function collects the current time from the user.
    :return: str
    """
    date = datetime.now() + timedelta(days=0)
    timestr = str(date)
    return timestr

def send_message(str1):
    """
    This function sends a message for the server and inserts a message to the GUI
    confirming that the message was send.
    return: None
    """
    global B
    msg = str1.encode()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect((UDP_IP, UDP_PORT))
    s.send(msg)
    s.close()
    B.insert(INSERT, "Message sent to server.\n")
    ROOT.update()  # updates the Tkinter form
    time.sleep(1)
    return

def send_message2(str1):
    """
    This function sends a message for the server without inserting a message to the GUI
    confirming that the message was send.
    return: None
    """
    ROOT.update()
    msg = str1.encode()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect((UDP_IP, UDP_PORT))
    s.send(msg)
    s.close()
    ROOT.update()
    return

def set_GUI():
    """
    This function sets the Tkinter platfom.
    return: tkinter.scrolledtext.ScrolledText
    """
    ROOT.title('Sniffer Client')
    ROOT.iconbitmap(r'C:\Users\sagi1\PycharmProjects\untitled6\venv\BOSSSNIFFER\boss 2\Photos\Sniffer Icon.ico')
    ROOT.geometry("1100x800")
    txt = scrolledtext.ScrolledText(ROOT, width = 135, height = 50)
    txt.grid(column = 1, row = 1)
    return txt

def countdown():
    """
    This function counts down from 120 to 0 after a successfull message was sent to the server.
    :return: None
    """
    global B
    for i in range(120, 0, -1):
        B.insert(INSERT, i)
        ROOT.update()  # updates the Tkinter form
        time.sleep(1)
        B.insert(INSERT, "\n")

def main():
    global B
    B = set_GUI()
    while (True):
        user_time = user_current_time()
        user_ip = get_user_ip()
        user_cmp = get_user_computer_name()
        user_mac = get_user_mac()
        a = "time: " + user_time + "\n" + "ip: " + user_ip + "\n" + "compuet name: " + user_cmp + "\n" + "mac: " + user_mac + "\n"
        sql = user_time +"$"+ user_ip +"$"+ user_cmp +"$"+ user_mac
        send_message(sql)
        del all_packets[:]
        B.insert(INSERT, "Starting to sniff\n")
        ROOT.update()  # updates the Tkinter form
        #threading.Thread(target= sniff(count = ROUND_NUM, prn = handle_packet, lfilter = filter_packets), daemon=True).start()
        sniff(count=ROUND_NUM, prn=handle_packet, lfilter=filter_packets)
        B.insert(INSERT, "Done!\n")
        ROOT.update()  # updates the Tkinter form
        time.sleep(1)
        analyze_packets_and_report()
        send_message(a)
        B.insert(INSERT, "\nThe timer is set for 120 seconds. After that, 'Sniffer' will start again.\n")
        ROOT.update()  # updates the Tkinter form
        time.sleep(1)
        countdown()
    ROOT.mainloop()


if __name__=='__main__':
    main()
