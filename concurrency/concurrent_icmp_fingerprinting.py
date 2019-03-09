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

Usage: python3 concurrent_icmp_fingerprinting.py <inputfile>
  <response timeout in seconds>
  <ping interval in milliseconds> <ip version: 4/6>

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
  """
  copied from somewhere else
  apparently it also works with icmpv6
  :param payload: the content of the icmp packet/ip payload
  :return: the checksum
  """
  s = 0
  for i in range(0, len(payload), 2):
    a = payload[i]
    b = payload[i + 1]
    s = s + (a + (b << 8))
  s = s + (s >> 16)
  s = ~s & 0xffff
  return s


def _create_icmp_request(icmp_id=1, icmp_sequence=0, ipv6=False):
  """
  constructs the bit structure of the icmp packet, which is the payload for IP
  :param icmp_id: identification, which is also the index position of the target
  :param icmp_sequence: depends on how many pings sent for the host
  :param ipv6: whether ipv6 is enabled
  :return: the bit structure of the payload
  """
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
  """
  sending trials # of icmp requests to the target with the socket
  :param sock: socket
  :param target: string of target ip address
  :param trials: number of icmp requests to send
  :param icmp_id: identification of the icmp packet, which in this implementation
    is also the index of the target in the array of targets
  :param ipv6: whether ipv6 is enabled
  """
  # parses the string of ip address
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
    return
  # constructs icmp packets and send them
  for i in range(trials):
    ip_payload = _create_icmp_request(icmp_id, icmp_sequence=i, ipv6=ipv6)
    try:
      sock.sendto(ip_payload, target_ipaddr)
    except socket.error:
      etype, evalue, etrb = sys.exc_info()
      print(evalue.args[1], file=sys.stderr)


def _send_pings_left(sock, targets, left, ipv6=False, sleep=0):
  """
  sends pings to reachable targets that have not been reached
  :param sock: socket used
  :param targets: array of targets
  :param left: indices/icmp_id of reachable targets that have not been reached
  :param ipv6: whether ipv6 is enabled
  :param sleep: how long to sleep for between sending pings
  """
  while not left.empty():
    index = left.get()
    _send_pings(sock, targets[index], trials=2, icmp_id=index, ipv6=ipv6)
    if sleep != 0:
      time.sleep(sleep/1000)


def _receive_pings(sock, targets, contacted, reached, hops, anticipated, payload_size,
                   timeout, holder, ipv6=False):
  """
  the function that keeps receiving and parsing icmp responses until timeout
  or receiving from the anticipated amount of responders
  :param sock: socket
  :param targets: target hosts
  :param contacted: array of sets for dropping packets from responders that have
    already responded to a particular icmp request
  :param reached: for keeping records of whether a target host has responded
  :param hops: for keeping records of the number of hops it takes to get to
    the targets, or the calculated ttl configuration if target reached
  :param anticipated: anticipated amount of responders
  :param payload_size: size of the icmp packet, used for buffering
  :param timeout: time it takes to move on from no response
  :param holder: a mutable array for holding the returned queue of list of
    addresses that are reachable but have not been reached
  :param ipv6: whether ipv6 is enabled
  """
  # following variables are for buffering and dissecting the packets
  ipheader_size = 20
  icmpheader_size = 8
  icmp_type_reply = 0
  icmp_type_ttl_exceeded = 11
  src_offset = 12
  src_len = 4
  ttl_offset = 8
  if ipv6:
    src_offset = 8
    src_len = 16
    ipheader_size = 40
    icmp_type_reply = 129
    icmp_type_ttl_exceeded = 3
    ttl_offset = 7
  buffer_size = ipheader_size + icmpheader_size + struct.calcsize(
      'Q') + payload_size  # calcsize('Q'): timestamp size
  # the queue for this function to push icmp_ids of unreached, but reachable targets
  # hosts, which will be pinged the next iteration with higher hop counts
  # icmp_ids are the same as their index in the array of targets
  left = queue.Queue()
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
    src_ip = struct.unpack('B' * src_len, reply[src_offset:src_offset + src_len])
    icmp_packet = struct.unpack('BBHHH', reply[ipheader_size:ipheader_size + icmpheader_size])
    icmp_type = icmp_packet[0]
    icmp_id = icmp_packet[3]
    if not src_ip in contacted[icmp_id]:
      contacted[icmp_id].add(src_ip)
      total += 1
      if icmp_type == icmp_type_reply:
        target_ip = targets[icmp_id].split('.')
        matching_IP = True
        for i in range(len(src_ip)):
          if not src_ip[i] == int(target_ip[i]):
            matching_IP = False
        if matching_IP:
          # RESPONSE FROM HOST
          ttl = struct.unpack('B', reply[ttl_offset:ttl_offset + 1])[0]
          # host ttl = # of hops + response ttl
          hops[icmp_id] += ttl
          reached[icmp_id] = True
        else:
          print("Error: inconsistent icmp identification, source IP address, and response type")
      elif icmp_type == icmp_type_ttl_exceeded:
        hops[icmp_id] += 1
        # iterates through the same host next time with higher hop count
        left.put(icmp_id)
  holder[0] = left


def _get_hop_limits(targets, timeout, ipv6=False, sleep=0):
  """
  a wrapped function since it does not work for more than 2^16 hosts at one time
  2^16 being the cardinality of the ICMP identification field
  :param targets: strings of ip addresses
  :param timeout: how long it takes for a response to timeout
  :param ipv6: whether ipv6 is enabled
  :param sleep: how long to sleep for in between requests
  :return: the number of hops it takes to ping them and whether they are reached
  """
  n = len(targets) # n must be smaller than 2^16 to allow for concurrent pinging
  hops = [0] * n
  # the queue for pushing icmp_ids of unreached, but reachable targets
  # hosts, which will be pinged the next iteration with higher hop counts
  # icmp_ids are the same as their index in the array of targets
  left = queue.Queue()
  reached = [False] * n
  contacted = [set() for _ in range(n)]
  for i in range(n):
    left.put(i)
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
  # increments the max hops for targets that are reachable but not yet reached
  # to calculate the original host ttl configuration by adding the # of hops
  # to the response ttl
  for i in range(max_hops):
    if ipv6:
      sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, i + 1)
    else:
      sock.setsockopt(socket.SOL_IP, socket.IP_TTL, i + 1)
    anticipated = left.qsize()
    ip_payload_size = 32
    holder = [None]
    r = threading.Thread(target=_receive_pings,
                         args=(sock, targets, contacted, reached, hops, anticipated, ip_payload_size, timeout, holder, ipv6))
    s = threading.Thread(target=_send_pings_left, args=(sock, targets, left, ipv6, sleep))
    r.start()
    s.start()
    s.join()
    r.join()
    #_send_pings_left(sock, targets, left, ipv6)
    #_receive_pings(sock, targets, reached, hops, anticipated, ip_payload_size, timeout, holder, ipv6)
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
  return hops, reached


def get_hop_limits(targets, timeout=5, ipv6=False, sleep=0):
  """
  infer the hop limits/ttls configuration of the target hosts based on the IP
  response to ICMP requests and the number of hops it takes for ICMP requests
  to reach them
  :param targets: strings of ip addresses
  :param timeout: how long it takes for a response to timeout
  :param ipv6: whether ipv6 is enabled
  :param sleep: how long to sleep for
  :return: hops/ttl configuration of target hosts and whether they are
    actually reached. if they are not reached, the hops is not the configuration
    but rather the number of hops the program has tried in order to reach the
    host
  """
  batch_size = 2^16
  total = len(targets)
  batch_num = total // batch_size
  hops = []
  reached = []
  for i in range(batch_num + 1):
    start = i * batch_size
    finish = (i + 1) * batch_size
    if finish > total:
      finish = total
    res, rea = _get_hop_limits(targets[start:finish], timeout, ipv6, sleep)
    hops += res
    reached += rea
  return hops, reached


def main():
  """
  part that runs as main, parses the command line arguments, interprets
  TTLs/hop limits of hosts, and prints to stdout the expected OSes of
  ip addresses from the input file
  """
  try:
    f = open(sys.argv[1])
    timeout = int(sys.argv[2])
    sleep = int(sys.argv[3])
    version = int(sys.argv[4])
    ipv6 = (version == 6)
    targets = f.read().strip().split('\n')
  except:
    print('Usage: python3 concurrent_icmp_fingerprinting.py <inputfile> '
          '<response timeout in seconds> <ping interval in milliseconds> '
          '<ip version: 4/6>')
    return
  hops, reached = get_hop_limits(targets, timeout, ipv6, sleep)
  for i in range(len(targets)):
    status = 'Unreachable'
    if reached[i]:
      config = hops[i]
      if config == 128:
        status = 'Windows'
      elif config == 64:
        status = 'Linux/MacOS'
      else:
        status = 'Other'
    print(targets[i] + ": " + status)


if __name__ == '__main__':
  main()