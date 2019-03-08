"""
FILENAME: concurrent_icmp_fingerprinting.py
AUTHOR: Perry Deng pxdeng@pm.me
DATE: 03.05.2019

a concurrent tool written in python 3.6 for fingerprinting operating systems of
remote hosts based on TTLs(IPv4) or HL(IPv6), an I/O bound task ripe for single
core concurrency
this implementation uses one thread to send all the requests and another thread
to receive all the responses

requires only Python Standard Library
requires root/administrative privilege due to packet engineering

Usage: python3 concurrent_icmp_fingerprinting.py <inputfile> <response timeout in seconds> <ip version: 4/6>
where input is ascii file containing rows of ipv4/ipv6 addresses

does not work against IPv6 hosts autoconfigured by network routers to have the
same hop limits

for more information, reference:
https://www.sans.org/reading-room/whitepapers/testing/paper/33794
"""
import threading
import socket
import time
import struct
import sys
import queue


def _compute_icmpv4_checksum(payload):
  s = 0
  for i in range(0, len(payload), 2):
    a = payload[i]
    b = payload[i + 1]
    s = s + (a + (b << 8))
  s = s + (s >> 16)
  s = ~s & 0xffff
  return s


def _create_icmp_request(icmp_id=1, icmp_sequence=0, ipv6=False):
  timestamp = int(time.time())
  icmp_type = 8 # type for requests
  if ipv6:
    icmp_type = 128
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
  icmp_checksum = _compute_icmpv4_checksum(ip_data_field)
  ip_data_field = struct.pack(struct_format,
                              icmp_type,
                              icmp_code,
                              icmp_checksum,
                              icmp_id,
                              icmp_sequence,
                              timestamp,
                              icmp_data)
  return ip_data_field


def _send_pings(sock, target, trials=2, icmp_id=1, ipv6=False):
  target_ipaddr = None
  addr_family = 'AF_INET'
  if ipv6:
    addr_family = 'AF_INET6'
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
  for i in range(trials):
    ip_payload = _create_icmp_request(icmp_id, icmp_sequence=i, ipv6=ipv6)
    try:
      sock.sendto(ip_payload, target_ipaddr)
    except socket.error:
      etype, evalue, etrb = sys.exc_info()
      print(evalue.args[1], file=sys.stderr)


def _send_pings_left(sock, targets, left, ipv6=False):
  while not left.empty():
    index = left.get()
    _send_pings(sock, targets[index], trials=2, icmp_id=index, ipv6=ipv6)


def _receive_pings(sock, targets, reached, results, anticipated, payload_size, timeout, holder, ipv6=False):
  contacted = [False] * len(targets)
  ipheader_size = 20  # ipv4 header size
  icmpheader_size = 8
  icmp_type_reply = 0
  src_offset = 12
  src_len = 4
  ttl_offset = 8
  left = queue.Queue()
  if ipv6:
    src_offset = 8
    src_len = 16
    ipheader_size = 40
    icmp_type_reply = 129
    ttl_offset = 7
  buffer_size = ipheader_size + icmpheader_size + struct.calcsize('Q') + payload_size  # calcsize('Q'): timestamp size
  total = 0
  timestamp = time.time()
  while total < anticipated and time.time() - timestamp < timeout:
    try:
      reply, host = sock.recvfrom(buffer_size)
    except socket.timeout:
      print("socket timeout")
      return
    except Exception as e:
      print(str(e))
      return
    icmp_packet = struct.unpack('BBHHH', reply[ipheader_size:ipheader_size + icmpheader_size])
    if icmp_packet[0] == icmp_type_reply:
      src = struct.unpack('B'*src_len, reply[src_offset:src_offset + src_len])
      icmp_id = icmp_packet[3]
      matching_IP = True
      temp = targets[icmp_id].split('.')
      for i in range(len(src)):
        if not src[i] == int(temp[i]):
          matching_IP = False
      if matching_IP:
        # SUCCESSFUL RESPONSE, PARSE TTL
        if not contacted[icmp_id]:
          contacted[icmp_id] = True
          total += 1
          ttl = struct.unpack('B', reply[ttl_offset:ttl_offset + 1])[0]
          results[icmp_id] += ttl
          reached[icmp_id] = True
      else:
        # just a hop
        if not contacted[icmp_id]:
          contacted[icmp_id] = True
          results[icmp_id] += 1
          left.put(icmp_id)
  holder[0] = left


def _get_hop_limits(targets, timeout, ipv6=False):
  n = len(targets) # n must be smaller than 2^16 to allow for concurrent pinging
  results = [0] * n
  indices = {}
  left = queue.Queue()
  reached = [False] * n
  for i in range(n):
    target = targets[i]
    left.put(i)
    indices[target] = i
  total = 0
  max_hops = 64
  sock_af = socket.AF_INET
  sock_proto = socket.getprotobyname('icmp')
  if ipv6:
    sock_af = socket.AF_INET6
    sock_proto = socket.getprotobyname('ipv6-icmp')
  sock = None
  try:
    sock = socket.socket(sock_af, socket.SOCK_RAW, sock_proto)
  except PermissionError:
    print('Fatal: You must be root to send ICMP packets', file=sys.stderr)
    exit(1)
  except:
    print('Fatal: General error in socket()', file=sys.stderr)
    exit(1)
  sock.settimeout(timeout)  # timeout set to 3 seconds
  for i in range(max_hops):
    if ipv6:
      sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, i + 1)
    else:
      sock.setsockopt(socket.SOL_IP, socket.IP_TTL, i + 1)
    anticipated = left.qsize()
    ip_payload_size = 32
    holder = [None]
    r = threading.Thread(target=_receive_pings,
                         args=(sock, targets, reached, results, anticipated, ip_payload_size, timeout, holder, ipv6))
    s = threading.Thread(target=_send_pings_left, args=(sock, targets, left, ipv6))
    r.start()
    s.start()
    s.join()
    r.join()
    #_send_pings_left(sock, targets, left, ipv6)
    #_receive_pings(sock, targets, reached, results, anticipated, ip_payload_size, timeout, holder, ipv6)
    left = holder[0]
    if left is not None:
      total += anticipated - left.qsize()
      if left.empty():
        break
    else:
      break
    if total == n:
      break
  sock.close()
  return results, reached


def get_hop_limits(targets, timeout=5, ipv6=False):
  batch_size = 2^16
  total = len(targets)
  batch_num = total // batch_size
  results = []
  reached = []
  for i in range(batch_num + 1):
    start = i * batch_size
    finish = (i + 1) * batch_size
    if finish > total:
      finish = total
    res, rea = _get_hop_limits(targets[start:finish], timeout, ipv6)
    results += res
    reached += rea
  return results, reached


def main():
  try:
    f = open(sys.argv[1])
    timeout = int(sys.argv[2])
    version = int(sys.argv[3])
    ipv6 = (version == 6)
    targets = f.read().strip().split('\n')
  except:
    print('Usage: python3 concurrent_icmp_fingerprinting.py <inputfile> <response timeout in seconds> <ip version: 4/6>')
    return 1
  results, reached = get_hop_limits(targets, timeout, ipv6)
  for i in range(len(targets)):
    status = 'Unreachable'
    if reached[i]:
      result = results[i]
      if result == 128:
        status = 'Windows'
      elif result == 64:
        status = 'Linux/MacOS'
      else:
        status = 'Other'
    print(targets[i] + ": " + status)
  return 0


if __name__ == '__main__':
  main()