#!/usr/bin/env python3

import ipaddress
import re
import socket
import sys

if len(sys.argv) == 1:
    # print("Usage: subnetcalc.py [Address{/{Netmask|Prefix}}] {Netmask|Prefix} {-n} {-uniquelocal|-uniquelocalhq} {-nocolour|-nocolor}")
    print("Usage: subnetcalc.py [Address{/{Netmask|Prefix}}]")
    sys.exit(1)

try:
    address = ipaddress.ip_interface(sys.argv[1])
except ValueError:
    print("ERROR: Bad address " + sys.argv[1] + "!")
    sys.exit(1)
else:
    if address.network.prefixlen == 32 or address.network.prefixlen == 128:
        max_hosts_deduct = 0
        host_range = "{ " + str(address.network[0]) + " - " + str(address.network[0]) + " }"
        broadcast = "not needed on Point-to-Point links"
    elif address.network.prefixlen == 31 or address.network.prefixlen == 127:
        max_hosts_deduct = 0 
        host_range = "{ " + str(address.network[0]) + " - " + str(address.network[1]) + " }"
        broadcast = "not needed on Point-to-Point links"
    else:
        if address.version == 4:
            max_hosts_deduct = 2
        else:
            max_hosts_deduct = 1
        host_range = "{ " + str(address.network[1]) + " - " + str(address.network[-2]) + " }"
        broadcast = address.network.broadcast_address

    print("Address       =", address.ip)
    print("Network       =", str(address.network).replace("/", " / "))
    print("Netmask       =", address.netmask)
    if address.version == 4:
        print("Broadcast     =", broadcast)
    print("Wildcard Mask =", address.hostmask)
    host_bits = (address.network.max_prefixlen - address.network.prefixlen)
    print("Host Bits     =", host_bits)
    print("Max. Hosts    =", (address.network.num_addresses - max_hosts_deduct), "  (2^" + str(host_bits) + " - " + str(max_hosts_deduct) + ")")
    print("Host Range    =", host_range)
    print("Properties    =")
    if address.version == 4:
        address_splited = re.split(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d+)\b", str(address))
        first_octet = int(address_splited[1])
        if first_octet >= 1 and first_octet <= 127:
            print("   - Class A")
        elif first_octet >= 128 and first_octet <= 191:
            print("   - Class B")
        elif first_octet >= 192 and first_octet <= 223:
            print("   - Class C")
        elif first_octet >= 224 and first_octet <= 239:
            print("   - Class D (Multicast)")
        elif first_octet >= 240 and first_octet <= 255:
            print("   - Class E (Reserved)")
        if address.is_private:
            print("   - Private")
    if address.is_loopback:
        print("   - Loopback address")
    try:
        dns = socket.gethostbyaddr(str(address.ip))[0]
    except (socket.error, socket.herror, socket.gaierror, socket.timeout) as e:
        dns = "(" + e.strerror + ")"
    print("DNS Hostname  =", dns)
