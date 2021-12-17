#!/usr/bin/env python3

import ipaddress
import socket
import sys
import regex

COLOR = 1

if COLOR == 1:
    from rich import print

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
    if address.network.prefixlen in (32, 128):
        MAX_HOSTS_DEDUCT = 0
        HOST_RANGE = "{ " + str(address.network[0]) + " - " + str(address.network[0]) + " }"
        BROADCAST = "not needed on Point-to-Point links"
    elif address.network.prefixlen in (31, 127):
        MAX_HOSTS_DEDUCT = 0
        HOST_RANGE = "{ " + str(address.network[0]) + " - " + str(address.network[1]) + " }"
        BROADCAST = "not needed on Point-to-Point links"
    else:
        if address.version == 4:
            MAX_HOSTS_DEDUCT = 2
        else:
            MAX_HOSTS_DEDUCT = 1
        HOST_RANGE = "{ " + str(address.network[1]) + " - " + str(address.network[-2]) + " }"
        BROADCAST = address.network.broadcast_address

    host_bits = (address.network.max_prefixlen - address.network.prefixlen)
    MY_REGEX = r"(\d{" + str(host_bits) + r"})$"

    print("Address       =", address.ip)
    if address.version == 4:
        address_split = str(address.ip).split(".")
        if COLOR == 1:
            IP2BIN = "".join(map(str, [f"{int(x):08b}" for x in address_split]))
            split = regex.split(MY_REGEX, IP2BIN)
            net_split = regex.split(r"(\d{8})", split[0])
            while "" in net_split:
                net_split.remove("")
            host_split = regex.split(r"(?r)(\d{8})", split[1])
            while "" in host_split:
                host_split.remove("")
            host_split.reverse()
            NET = " . ".join(net_split)
            if host_bits in (8, 16, 24):
                NET = NET + " . "
            HOST = " . ".join(host_split)
            print(f"                   {NET}[yellow]{HOST}")
        else:
            IP2BIN = " . ".join(map(str, [f"{int(x):08b}" for x in address_split]))
            print("                  ", IP2BIN)
    else:
        address_split = str(address.ip.exploded).split(":")
        if COLOR == 1:
            IP2BIN = "".join(map(str, [(bin(int(x, 16))[2:].zfill(16)) for x in address_split]))
            COUNT_A = 1
            ipv6_dict = {}
            for a in IP2BIN:
                if 128 - COUNT_A < host_bits:
                    ipv6_dict[COUNT_A] = {"value": a, "type": "host"}
                else:
                    ipv6_dict[COUNT_A] = {"value": a, "type": "net"}
                COUNT_A += 1
            COUNT_X = 0
            for x in address_split:
                START = 1 + COUNT_X * 16
                END = 17 + COUNT_X * 16
                BINARY = ""
                COUNT_Y = 1
                for y in range(START, END):
                    # print(y)
                    if ipv6_dict[y]['type'] == "host":
                        BINARY += "[yellow]" + ipv6_dict[y]['value']
                    else:
                        BINARY += ipv6_dict[y]['value']
                    if COUNT_Y == 8:
                        BINARY += " "
                    COUNT_Y += 1
                print(f"                   [cyan bold]{x} =", BINARY)
                COUNT_X += 1
        else:
            for x in address_split:
                y = (str(bin(int(x, 16)))[2:].zfill(16))
                print("                  ", x, "=", y[:8], y[8:])
    print("Network       =", str(address.network).replace("/", " / "))
    print("Netmask       =", address.netmask)
    if address.version == 4:
        print("Broadcast     =", BROADCAST)
    print("Wildcard Mask =", address.hostmask)
    if COLOR == 1:
        print(f"Host Bits     = [yellow]{host_bits}")
    else:
        print("Host Bits     =", host_bits)
    print("Max. Hosts    =", (address.network.num_addresses - MAX_HOSTS_DEDUCT), "  (2^" + str(host_bits) + " - " + str(MAX_HOSTS_DEDUCT) + ")")
    print("Host Range    =", HOST_RANGE)
    print("Properties    =")
    if str(address) == str(address.network):
        print("   -", address.ip, "is a NETWORK address")
    elif str(address.ip) == str(BROADCAST):
        print("   -", address.ip, "is the BROADCAST address of", address.network)
    else:
        print("   -", address.ip, "is a HOST address of", address.network)

    if address.version == 4:
        # Check IPv4 properties
        # Get subnet class
        first_octet = int(address_split[0])
        if 1 <= first_octet <= 127:
            print("   - Class A")
        elif 128 <= first_octet <= 191:
            print("   - Class B")
        elif 192 <= first_octet <= 223:
            print("   - Class C")
        elif 224 <= first_octet <= 239:
            print("   - Class D (Multicast)")
        elif 240 <= first_octet <= 255:
            print("   - Class E (Reserved)")
        # Check if subnet is a private subnet
        if address.is_private:
            print("   - Private")
    else:
        if address.is_site_local:
            print("   - Site-Local Unicast Properties:")
        elif address.is_reserved:
            print("   - Reserved Unicast Properties:")
        elif address.is_link_local:
            print("   - Link-Local Unicast Properties:")
        elif address.is_private:
            print("   - Private Unicast Properties:")
        elif address.is_global:
            print("   - Global Unicast Properties:")
        print("      + Interface ID =", str(address.ip.exploded)[-19:])
        print("      + Sol. Node MC = ff02::1:ff" + str(address.ip.exploded)[-7:])
    if address.is_loopback:
        print("   - Loopback address")
    try:
        dns = socket.gethostbyaddr(str(address.ip))[0]
    except (socket.error, socket.herror, socket.gaierror, socket.timeout) as e:
        dns = "(" + e.strerror + ")"
    print("DNS Hostname  =", dns)
