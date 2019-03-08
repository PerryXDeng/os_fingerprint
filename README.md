FILENAME: concurrent_icmp_fingerprinting.py
AUTHOR: Perry Deng pxdeng@pm.me
DATE: 03.05.2019

a concurrent tool written in python 3.6 for fingerprinting operating systems of
remote hosts based on TTLs(IPv4) or HL(IPv6), an I/O bound task ripe for single
core concurrency

this implementation uses one thread to send all the requests and another thread
to receive all the responses

requires only Python Standard Library

may require root/administrative privilege due to packet engineering and usage of raw sockets

Usage: python3 concurrent_icmp_fingerprinting.py inputfile response_timeout_in_seconds 
ping_interval_in_milliseconds
ip_version:_4/6

where input file is an ascii file containing the ip addresses,
response timeout is a natural number for the maximum time to wait for response,
ping interval is a natural number to reduce the frequency of pinging (0 for most frequent),
and ip version should be 4 or 6


does not work against IPv6 hosts autoconfigured by network routers to have the
same hop limits


ttl fingerprinting over internet is a feature in development


for more information on how this works, reference:
https://www.sans.org/reading-room/whitepapers/testing/paper/33794
