#!/usr/bin/python3

import nmap # type: ignore

scanner = nmap.PortScanner()

print ("Welcome, this is a simple nmap automation tool")
print ("--------------------------------------------")

ip_addr = input("Please enter the IP address you want to scan: ")
print ("The IP you entered is: ", ip_addr)
type(ip_addr)

resp = input("""\nPlease enter the type of scan you want to run: 
             1) SYN ACK Scan
             2) UDP Scan
             3) Comprehensive Scan \n""")
print ("You have selected option: ", resp)

if resp == "1":
    print ("You have selected SYN ACK Scan")
    scanner.scan(ip_addr, arguments="-sS")
elif resp == "2":
    print ("You have selected UDP Scan")
    scanner.scan(ip_addr, arguments="-sU")
elif resp == "3":
    print ("You have selected Comprehensive Scan")
    scanner.scan(ip_addr, arguments="-sS -sU -A")
else:
    print ("Invalid option selected")
print ("Scanning in progress...")

if resp == "1":
    print ("Nmap Version: ", scanner.nmap_version())
    scanner.scan(ip_addr, '1-1024', '-v -sS')
    print ("Scan Info: ", scanner.scaninfo())
    print ("IP Status: ", scanner[ip_addr].state())
    print (scanner[ip_addr].all_protocols())
    print ("Open Ports: ", scanner[ip_addr]['tcp'].keys())
elif resp == "2":
    print ("Nmap Version: ", scanner.nmap_version())
    scanner.scan(ip_addr, '1-1024', '-v -sU')
    print ("Scan Info: ", scanner.scaninfo())
    print ("IP Status: ", scanner[ip_addr].state())
    print (scanner[ip_addr].all_protocols())
    print ("Open Ports: ", scanner[ip_addr]['udp'].keys())
elif resp == "3":
    print ("Nmap Version: ", scanner.nmap_version())
    scanner.scan(ip_addr, '1-1024', '-v -sS -sU -A')
    print ("Scan Info: ", scanner.scaninfo())
    print ("IP Status: ", scanner[ip_addr].state())
    print (scanner[ip_addr].all_protocols())
    print ("Open TCP Ports: ", scanner[ip_addr]['tcp'].keys())
    print ("Open UDP Ports: ", scanner[ip_addr]['udp'].keys())