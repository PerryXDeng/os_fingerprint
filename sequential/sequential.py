"""
FILENAME: sequential.py
AUTHOR: Perry Deng pxdeng@pm.me
DATE: 03.05.2019

runs in python3
requires only the standard library
CSEC465 Lab 03 Task 4
sequentially pings hosts from an input file and classify host OS based on response ttl
only works within an IPv4 Network
"""
import socket
import struct
import time
import sys


def _compute_header_checksum(payload):
  s = 0
  for i in range(0, len(payload), 2):
    a = payload[i]
    b = payload[i + 1]
    s = s + (a + (b << 8))
  s = s + (s >> 16)
  s = ~s & 0xffff
  return s


def _create_icmp_request(icmp_id=1, icmp_sequence=0):
  timestamp = int(time.time())
  icmp_type = 8 # type for requests
  icmp_code = 0 # not used for requests
  icmp_checksum = 0 # updated after header constructed
  icmp_data = b'' # data is optional
  struct_format = 'BBHHHQ{}s'.format(len(icmp_data))
  ip_data_field = struct.pack(struct_format,
                              icmp_type,
                              icmp_code,
                              icmp_checksum,
                              icmp_id,
                              icmp_sequence,
                              timestamp,
                              icmp_data)
  icmp_checksum = _compute_header_checksum(ip_data_field)
  ip_data_field = struct.pack(struct_format,
                              icmp_type,
                              icmp_code,
                              icmp_checksum,
                              icmp_id,
                              icmp_sequence,
                              timestamp,
                              icmp_data)
  return ip_data_field


def send_pings(sock, target, trials=2, icmp_id=1):
  print("pinging " + target)
  target_ipaddr = None
  addr_family = 'AF_INET'
  try:
    for ainfo in socket.getaddrinfo(target, 1):
      if ainfo[0].name == addr_family:
        target_ipaddr = ainfo[4]
        break
  except socket.gaierror:
    print('Error: Unable to get {t} address for {h}'.format(t=addr_family,
                                                            h=target),
                                                            file=sys.stderr)
    exit(1)
  ip_payload = None
  for i in range(trials):
    ip_payload = _create_icmp_request(icmp_id, icmp_sequence=i)
    try:
      sock.sendto(ip_payload, target_ipaddr)
    except socket.error:
      etype, evalue, etrb = sys.exc_info()
      print(evalue.args[1], file=sys.stderr)
      exit(1)
  ipheader_size = 20 # ipv4 header size
  icmpheader_size = 8
  icmp_type_reply = 0
  payload_size = len(ip_payload)
  buffer_size = ipheader_size + icmpheader_size + struct.calcsize(
      'Q') + payload_size  # calcsize('Q'): timestamp size
  reply = None
  host = None
  timestamp = time.time()
  timeout = 2
  while time.time() - timestamp < timeout:
    try:
      reply, host = sock.recvfrom(buffer_size)
    except socket.timeout:
      print('Down')
      print()
      return
    except:
      print('Unreachable')
      print()
      return
    ip_payload = struct.unpack('BBHHH', reply[ipheader_size:ipheader_size + icmpheader_size])
    ttl_offset = 8 # ipv4 ttl field offset
    if ip_payload[0] == icmp_type_reply and ip_payload[3] == icmp_id:
      # SUCCESSFUL RESPONSE, PARSE TTL
      ttl = struct.unpack('B', reply[ttl_offset:ttl_offset+1])[0]
      if ttl == 128:
        print("Windows")
        print()
        break
      elif ttl == 64:
        print("Linux")
        print()
        break
      else:
        print("Other")
        print()
        break


def main():
  try:
    f = open(sys.argv[1])
  except:
    print('Error opening input file')
    print('Usage: python3 sequential.py <input>')
    return 1
  import socket
  targets = f.read().strip().split('\n')
  sock_af = socket.AF_INET
  sock_proto = socket.getprotobyname('icmp')
  sock = None
  try:
    sock = socket.socket(sock_af, socket.SOCK_RAW, sock_proto)
  except PermissionError:
    print('Fatal: You must be root to send ICMP packets', file=sys.stderr)
    exit(1)
  except:
    print('Fatal: General error in socket()', file=sys.stderr)
    exit(1)
  sock.settimeout(3) # timeout set to 3 seconds
  for i in range(len(targets)):
    send_pings(sock, targets[i], icmp_id=i)
  sock.close()
  return 0


if __name__ == '__main__':
    main()