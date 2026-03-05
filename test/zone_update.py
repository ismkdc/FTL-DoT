#!/bin/python3
# Pi-hole: A black hole for Internet advertisements
# (c) 2023 Pi-hole, LLC (https://pi-hole.net)
# Network-wide ad blocking via your own hardware.
#
# FTL Engine - auxiliary files
# Send a dynamic update to the DNS server to update the a zone
#
# This file is copyright under the latest version of the EUPL.
# Please see LICENSE file for your rights under this license.

import sys
import dns.query
import dns.update
import dns.rcode

# Usage: python3 zone_update.py [proto = tcp] [port = 5300] [server = 127.0.0.1]

# Get the protocol, server, and port from command line arguments or use defaults
proto = sys.argv[1] if len(sys.argv) > 1 else 'tcp'
port = int(sys.argv[2]) if len(sys.argv) > 2 else 5300
server = sys.argv[3] if len(sys.argv) > 3 else '127.0.0.1'

# Create a new update object
update = dns.update.Update('example.com')

# Add a new A record
update.add('www.example.com', 300, 'A', server)

# Send the update to the DNS server and print the response
if proto == 'udp':
	response = dns.query.udp(update, server, port = port)
	print("UDP response: " + dns.rcode.to_text(response.rcode()))
elif proto == 'tcp':
	response = dns.query.tcp(update, server, port = port)
	print("TCP response: " + dns.rcode.to_text(response.rcode()))
