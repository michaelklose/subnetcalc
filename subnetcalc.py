#!/usr/bin/env python3
"""
IP Subnet Calculator with CLI Coloring
Author: Michael Klose
"""

import argparse
import ipaddress
import os
import socket
import sys

from typing import Union, Optional

# Global printer defaults to built-in print, but may be overridden to rich.print in main()
printer = print

def parse_args() -> argparse.Namespace:
    """Parse and return command-line arguments."""
    usage_str = '%(prog)s [Address{/{Netmask|Prefix}}] {Netmask|Prefix} {-n} {-nocolour|-nocolor}'
    parser = argparse.ArgumentParser(usage=usage_str)
    parser.add_argument("prefix", nargs='*',
                        help="[Address{/{Netmask|Prefix}}] {Netmask|Prefix}")
    parser.add_argument("-nocolor", "-nocolour", action='store_true',
                        help="no colors")
    parser.add_argument("-n", action='store_true',
                        help="no reverse lookup")
    args = parser.parse_args()
    if not args.prefix:
        sys.exit("usage: " + os.path.basename(__file__) +
                 " [Address{/{Netmask|Prefix}}] {Netmask|Prefix} {-n} {-nocolour|-nocolor}")
    # Join prefix arguments into a single string
    if isinstance(args.prefix, list):
        args.prefix = "/".join(args.prefix)
    return args

def split_into_octets(bits: str) -> str:
    """Split a bit string into octets separated by ' . '."""
    return " . ".join([bits[i:i+8] for i in range(0, len(bits), 8)]) if bits else ""

def print_ipv4_binary(ip: ipaddress.IPv4Address, prefix: int, color: bool) -> None:
    """
    Print IPv4 address and its binary representation.
    The host bits are highlighted in yellow if color is enabled.
    """
    binary_ip = f"{int(ip):032b}"
    # Split into network and host parts
    network_bits = binary_ip[:prefix]
    host_bits_str = binary_ip[prefix:]
    network_display = split_into_octets(network_bits)
    host_display = split_into_octets(host_bits_str)
    if color and host_display:
        host_display = f"[yellow]{host_display}[/yellow]"
    # Append separator dot if network part ends on octet boundary and host exists
    if network_display and host_display and (prefix % 8 == 0):
        network_display += " . "
    printer("Address       =", ip)
    printer("                  ", network_display + host_display)

def print_ipv6_binary(ip: ipaddress.IPv6Address, prefix: int, color: bool) -> None:
    """
    Print IPv6 address and its binary representation.
    The host bits are highlighted in yellow if color is enabled.
    """
    exploded = ip.exploded
    hextets = exploded.split(":")
    printer("Address       =", ip)
    for i, hextet in enumerate(hextets):
        start_bit = i * 16
        hextet_bin = f"{int(hextet, 16):016b}"
        # Process the hextet in two 8-bit groups
        # First octet:
        first_octet = hextet_bin[:8]
        first_net = max(0, min(8, prefix - start_bit))
        first_normal = first_octet[:first_net]
        first_host = first_octet[first_net:]
        if color and first_host:
            first_host = f"[yellow]{first_host}[/yellow]"
        group1 = first_normal + first_host
        # Second octet:
        second_octet = hextet_bin[8:]
        second_net = max(0, min(8, prefix - (start_bit + 8)))
        second_normal = second_octet[:second_net]
        second_host = second_octet[second_net:]
        if color and second_host:
            second_host = f"[yellow]{second_host}[/yellow]"
        group2 = second_normal + second_host
        printer(f"                   [cyan bold]{hextet} = {group1} {group2}")

def print_network_info(interface: Union[ipaddress.IPv4Interface, ipaddress.IPv6Interface],
                       color: bool,
                       max_hosts_deduct: int,
                       host_range: str,
                       broadcast: Optional[Union[str, ipaddress.IPv4Address]]) -> None:
    """Print network details such as netmask, wildcard mask, host bits, etc."""
    printer("Network       =", str(interface.network).replace("/", " / "))
    printer("Netmask       =", interface.netmask)
    if interface.version == 4:
        printer("Broadcast     =", broadcast)
    printer("Wildcard Mask =", interface.hostmask)
    host_bits = interface.network.max_prefixlen - interface.network.prefixlen
    if color:
        printer(f"Host Bits     = [yellow]{host_bits}[/yellow]")
    else:
        printer("Host Bits     =", host_bits)
    max_hosts = interface.network.num_addresses - max_hosts_deduct
    printer("Max. Hosts    =", max_hosts, f"  (2^{host_bits} - {max_hosts_deduct})")
    printer("Host Range    =", host_range)

def print_properties(interface: Union[ipaddress.IPv4Interface, ipaddress.IPv6Interface]) -> None:
    """Print IP address properties and classifications."""
    printer("Properties    =")
    if str(interface) == str(interface.network):
        printer("   -", interface.ip, "is a NETWORK address")
    elif interface.version == 4 and str(interface.ip) == str(interface.network.broadcast_address):
        printer("   -", interface.ip, "is the BROADCAST address of", interface.network)
    else:
        printer("   -", interface.ip, "is a HOST address in", interface.network)
    if interface.version == 4:
        first_octet = int(str(interface.ip).split(".")[0])
        if 1 <= first_octet <= 127:
            printer("   - Class A")
        elif 128 <= first_octet <= 191:
            printer("   - Class B")
        elif 192 <= first_octet <= 223:
            printer("   - Class C")
        elif 224 <= first_octet <= 239:
            printer("   - Class D (Multicast)")
        elif 240 <= first_octet <= 255:
            printer("   - Class E (Reserved)")
        if interface.is_private:
            printer("   - Private")
    else:
        if interface.is_site_local:
            printer("   - Site-Local Unicast Properties:")
        elif interface.is_reserved:
            printer("   - Reserved Unicast Properties:")
        elif interface.is_link_local:
            printer("   - Link-Local Unicast Properties:")
        elif interface.is_private:
            printer("   - Private Unicast Properties:")
        elif interface.is_global:
            printer("   - Global Unicast Properties:")
        printer("      + Interface ID =", str(interface.ip.exploded)[-19:])
        printer("      + Sol. Node MC = ff02::1:ff" + str(interface.ip.exploded)[-7:])
    if interface.is_loopback:
        printer("   - Loopback address")

def print_dns_hostname(ip: Union[ipaddress.IPv4Address, ipaddress.IPv6Address], do_reverse: bool) -> None:
    """Perform reverse DNS lookup and print the result."""
    if do_reverse:
        try:
            dns = socket.gethostbyaddr(str(ip))[0]
        except (socket.error, socket.herror, socket.gaierror, socket.timeout) as e:
            dns = f"({e.strerror})"
        printer("DNS Hostname  =", dns)

def main() -> None:
    """Main function to run the IP Subnet Calculator."""
    args = parse_args()
    color = not args.nocolor

    # Override global printer with rich.print if color is enabled.
    global printer
    if color:
        try:
            from rich import print as rich_print
            printer = rich_print
        except ImportError:
            printer = print
            printer("WARNING: 'rich' module not found. CLI coloring will not be available.")

    try:
        interface = ipaddress.ip_interface(args.prefix)
    except ValueError:
        printer("ERROR: Bad address " + args.prefix + "!")
        sys.exit(1)

    prefix_len = interface.network.prefixlen

    if prefix_len in (32, 128):
        max_hosts_deduct = 0
        host_range = f"{{ {interface.network[0]} - {interface.network[0]} }}"
        broadcast = "not needed on Point-to-Point links" if interface.version == 4 else None
    elif prefix_len in (31, 127):
        max_hosts_deduct = 0
        host_range = f"{{ {interface.network[0]} - {interface.network[1]} }}"
        broadcast = "not needed on Point-to-Point links" if interface.version == 4 else None
    else:
        max_hosts_deduct = 2 if interface.version == 4 else 1
        host_range = f"{{ {interface.network[1]} - {interface.network[-2]} }}"
        broadcast = interface.network.broadcast_address if interface.version == 4 else None

    if interface.version == 4:
        print_ipv4_binary(interface.ip, prefix_len, color)
    else:
        print_ipv6_binary(interface.ip, prefix_len, color)

    print_network_info(interface, color, max_hosts_deduct, host_range, broadcast)
    print_properties(interface)

    if not args.n:
        print_dns_hostname(interface.ip, do_reverse=True)

if __name__ == '__main__':
    main()
