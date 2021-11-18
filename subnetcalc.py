#!/usr/bin/env python3

import ipaddress
import regex
import socket
import sys

color = 1

if color == 1:
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

    host_bits = (address.network.max_prefixlen - address.network.prefixlen)
    my_regex = r"(\d{" + str(host_bits) + r"})$"

    print("Address       =", address.ip)
    if address.version == 4:
        address_split = str(address.ip).split(".")
        if color == 1:
            ip2bin = "".join(map(str, ["{0:08b}".format(int(x)) for x in address_split]))
            split = regex.split(my_regex, ip2bin)
            net_split = regex.split(r"(\d{8})", split[0])
            while("" in net_split):
                net_split.remove("")
            host_split = regex.split(r"(?r)(\d{8})", split[1])
            while("" in host_split):
                host_split.remove("")
            host_split.reverse()
            net = " . ".join(net_split)
            if host_bits == 8 or host_bits == 16 or host_bits == 24:
                net = net + " . "
            host = " . ".join(host_split)
            print(f"                   {net}[yellow]{host}")
        else:
            ip2bin = " . ".join(map(str, ["{0:08b}".format(int(x)) for x in address_split]))
            print("                  ", ip2bin)
    else:
        address_split = str(address.ip.exploded).split(":")
        if color == 1:
            ip2bin = "".join(map(str, [(bin(int(x, 16))[2:].zfill(16)) for x in address_split]))
            count_a = 1
            ipv6_dict = {}
            for a in ip2bin:
                if 128 - count_a < host_bits:
                    ipv6_dict[count_a] = {"value": a, "type": "host"}
                else:
                    ipv6_dict[count_a] = {"value": a, "type": "net"}
                count_a += 1
            count_x = 0
            for x in address_split:
                start = 1 + count_x * 16
                end = 17 + count_x * 16
                binary = ""
                count_y = 1
                for y in range(start, end):
                    # print(y)
                    if ipv6_dict[y]['type'] == "host":
                        binary += "[yellow]" + ipv6_dict[y]['value']
                    else:
                        binary += ipv6_dict[y]['value']
                    if count_y == 8:
                        binary += " "
                    count_y += 1
                print(f"                   [cyan bold]{x} =", binary)
                count_x += 1
        else:
            for x in address_split:
                y = (str(bin(int(x, 16)))[2:].zfill(16))
                print("                  ", x, "=", y[:8], y[8:])
    print("Network       =", str(address.network).replace("/", " / "))
    print("Netmask       =", address.netmask)
    if address.version == 4:
        print("Broadcast     =", broadcast)
    print("Wildcard Mask =", address.hostmask)
    if color == 1:
        print(f"Host Bits     = [yellow]{host_bits}")
    else:
        print("Host Bits     =", host_bits)
    print("Max. Hosts    =", (address.network.num_addresses - max_hosts_deduct), "  (2^" + str(host_bits) + " - " + str(max_hosts_deduct) + ")")
    print("Host Range    =", host_range)
    print("Properties    =")
    if address.version == 4:
        # Check IPv4 properties
        if str(address) == str(address.network):
            print("   -", address.ip, "is a NETWORK address")
        elif str(address.ip) == str(broadcast):
            print("   -", address.ip, "is the BROADCAST address of", address.network)
        else:
            print("   -", address.ip, "is a HOST address of", address.network)

        # Get subnet class
        first_octet = int(address_split[1])
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

        # Check if subnet is a private subnet
        if address.is_private:
            print("   - Private")
    if address.is_loopback:
        print("   - Loopback address")
    try:
        dns = socket.gethostbyaddr(str(address.ip))[0]
    except (socket.error, socket.herror, socket.gaierror, socket.timeout) as e:
        dns = "(" + e.strerror + ")"
    print("DNS Hostname  =", dns)
