FILENAME: concurrent_icmp_fingerprinting.py
AUTHOR: Perry Deng pxdeng@pm.me
DATE: 03.05.2019

This is a concurrent tool written in python 3.6 for fingerprinting operating systems of
remote hosts based on TTLs(IPv4) or HL(IPv6), an I/O bound task ripe for vast performance
increase single core concurrency.

This implementation uses one thread to send all the requests and another thread
to receive all the responses, and then disects the packets for ttl configuration. Since it is done concurrently, it is 
much faster than similar techniques done sequentially, because it does not have to wait for response from one host to
start pinging the next. The memory usage of the concurrent implementation scales linearly as it needs to keep track of
all the "traceroute" responders for a particular IP address, which is acceptable given that the sequential version takes
hours if not days to run for large number of hosts.

This implementation is much faster than existing implementations due to not having to wait for response from one host to
start fingerprinting the next.

If the target host is outside the network, the program will run a DIY traceroute implmentation which will take more time
than LAN targets.

Running the script requires only Python 3 Standard Library and no reliance on bash or powershell commands. It may require
root/administrative privilege due to packet engineering and usage of raw sockets.

Usage: 
python3 concurrent_icmp_fingerprinting.py inputfile response_timeout_in_seconds 
ping_interval_in_milliseconds
ip_version:4/6

where input file is an ascii file containing the ip addresses,
response timeout is a natural number for the maximum time to wait for response,
ping interval is a natural number to reduce the frequency of pinging (0 for most frequent),
and ip version should be 4 or 6. Example: python3 concurrent_icmp_fingerprinting.py addresses.txt 3 0 4, which will parses
addresses.txt for IPv4 addresses and ping/traceroute them all for ttl fingerprinting with 3 second response timeout and 
0 milliseconds requests interval.


The program does not work against IPv6 hosts autoconfigured by network routers to have the
same hop limits.

For more information on how this works and can be used in penetration testing, reference
https://www.sans.org/reading-room/whitepapers/testing/paper/33794

The ipv6 feature has not been thoroughly tested and is still in development.
