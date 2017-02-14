#!/usr/bin/python3 -u
import sys
from collections import defaultdict

import dns
import dns.resolver
from IPy import IP
import statusbar
import ssl
import socket
from cryptography import x509
from cryptography.hazmat.backends import default_backend

CURSOR_UP_ONE = '\x1b[1A'
ERASE_LINE = '\x1b[2K'

resolver = dns.resolver.Resolver()
resolver.timeout = 10
resolver.lifetime = 10

TRIES = 5

def dns_try_wrapper(f):
    def wrapped(*args, **kwargs):
        for i in range(0, TRIES):
            try:
                return f(*args, **kwargs)
            except dns.resolver.NXDOMAIN:
                return []
            except dns.exception.Timeout:
                return []
            except dns.resolver.NoNameservers:
                pass
        return []
    return wrapped

@dns_try_wrapper
def rev_dns(ip):
    return (
            str(x) for x in resolver.query(
                            dns.reversename.from_address(str(ip)),
                            "PTR"
                    )
    )

@dns_try_wrapper                
def forward_dns(host):
    return (
            str(x) for x in resolver.query(host, 'A')
    )

def ssl_cert_name(ip):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.1)
    wrappedSocket = ssl.wrap_socket(sock)
    try:
        wrappedSocket.connect((ip, 443))
    except:
        response = False
    else:
        der_cert_bin = wrappedSocket.getpeercert(True)
        pem_cert = ssl.DER_cert_to_PEM_cert(wrappedSocket.getpeercert(True))
        wrappedSocket.close()
        cert = x509.load_pem_x509_certificate(bytes(pem_cert, "ascii"), default_backend())
        for attr in cert.subject:
            if attr.oid.dotted_string == "2.5.4.3":
                return [attr.value]
    return []

infile = open(sys.argv[1], "r")
outfile = open(sys.argv[2], "w")
all_hosts = set()
all_ips = set()
revdns = defaultdict(list)
ssldns = defaultdict(list)
fwddns = defaultdict(list)
for line in infile:
    line = line.strip()
    if len(line) == 0:
        continue
    try:
        all_ips = all_ips.union(set([ str(ip) for ip in IP(line)]))
    except ValueError:
        all_hosts.add(line)
while True:
    old_ips = all_ips.copy()
    old_hosts = all_hosts.copy()
    #1. Revdns the ips
    first = True
    done = 0
    for ip in all_ips:
        if not first:   
            print(CURSOR_UP_ONE + ERASE_LINE + CURSOR_UP_ONE)
        else:
            first = False
        bar = statusbar.StatusBar("Reverse DNS")
        bar.add_progress(done+1, "#")
        if (len(all_ips) > done):
            bar.add_progress(len(all_ips) - done, ".")
        print(bar.format_status())
        for host in rev_dns(ip):
            revdns[ip].append(host)
            all_hosts.add(host)
        done += 1
    #2. ssl resolution

    first = True
    done = 0
    for ip in all_ips:
        if not first:   
            print(CURSOR_UP_ONE + ERASE_LINE + CURSOR_UP_ONE)
        else:
            first = False
        bar = statusbar.StatusBar("SSL name")
        bar.add_progress(done+1, "#")
        if (len(all_ips) > done):
            bar.add_progress(len(all_ips) - done, ".")
        print(bar.format_status())
        for host in ssl_cert_name(ip):
            ssldns[ip].append(host)
            all_hosts.add(host)
        done += 1
    #3. resolve the hosts

    first = True
    done = 0
    for host in all_hosts:
        if not first:   
            print(CURSOR_UP_ONE + ERASE_LINE + CURSOR_UP_ONE)
        else:
            first = False
        bar = statusbar.StatusBar("Forward DNS")
        bar.add_progress(done + 1, "#")
        if (len(all_hosts) > done):
            bar.add_progress(len(all_hosts) - done, ".")
        print(bar.format_status())
        fwddns[host] = [ip for ip in forward_dns(host)]
        done += 1
    print(
            "Got %d new hostnames and %d new ips"  % (
                len(all_hosts) - len(old_hosts),len(all_ips) - len(old_ips)
            )
    ) 
    if (len(all_hosts) == len(old_hosts)) and (len(all_ips) == len(old_ips)):
        break
    else:
        all_hosts = all_hosts - old_hosts
        all_ips = all_ips - old_ips

unified = defaultdict(str)
outfile.write('REVERSE DNS\n')
for ip, hosts in sorted(revdns.items()):
    for host in hosts:
        unified[(host, ip)] = "R"
        outfile.write('%s %s\n' % (ip, host))
        outfile.flush()
outfile.write('SSL\n')
for ip, hosts in sorted(ssldns.items()):
    for host in hosts:
        unified[(host, ip)] += "S"
        outfile.write('%s %s\n' % (ip, host))
        outfile.flush()
outfile.write('FORWARD DNS\n')
for host, ips in sorted(fwddns.items()):
    for ip in ips:
        unified[(host, ip)] += "F"
        outfile.write('%s %s\n' % (host, ip))
        outfile.flush()
outfile.write('UNIFIED\n')
for (host, ip), mark in sorted(unified.items()):
    outfile.write('%s %s %s\n' % (host, ip, mark))
