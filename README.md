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
