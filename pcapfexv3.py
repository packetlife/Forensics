#!/usr/bin/env python3
# -*- coding: utf-8 -*-
__author__ = 'Viktor Winkelmann'

import argparse
import os
from scapy.all import rdpcap, Raw
import magic
VERSION = "1.1"

parser = argparse.ArgumentParser(description='Extract payloads from a pcap-file and detect file types.')
parser.add_argument('input', metavar='PCAP_FILE', help='the input file')
parser.add_argument('output', metavar='OUTPUT_FOLDER', help='the target folder for extraction',
                    nargs='?', default='output')
parser.add_argument("-e", dest='entropy', help="use entropy based rawdata extraction",
                    action="store_true", default=False)
parser.add_argument("-nv", dest='verifyChecksums', help="disable IP/TCP/UDP checksum verification",
                    action="store_false", default=True)
parser.add_argument("--T", dest='udpTimeout', help="set timeout for UDP-stream heuristics",
                    type=int, default=120)

print(f'pcapfex - Packet Capture Forensic Evidence Extractor - version {VERSION}')
print('----------=------===-----=--------=---------=------------------' + '-' * len(VERSION) + '\n')

args = parser.parse_args()

if not args.verifyChecksums:
    print('Packet checksum verification disabled.')
if args.entropy:
    print('Using entropy and statistical analysis for raw extraction and classification of unknown data.')

# Create output folder if it doesn't exist
os.makedirs(args.output, exist_ok=True)

# Load packets
packets = rdpcap(args.input)

# Initialize magic for file type detection
mime = magic.Magic(mime=True)

extracted_count = 0

# Extract payloads and detect file types
for i, pkt in enumerate(packets):
    if Raw in pkt:
        payload = bytes(pkt[Raw].load)
        if payload:
            # Detect file type
            detected_type = mime.from_buffer(payload)
            extension = detected_type.split('/')[-1]
            if extension == 'plain':
                extension = 'txt'
            filename = os.path.join(args.output, f"payload_{i}.{extension}")
            with open(filename, "wb") as f:
                f.write(payload)
            extracted_count += 1

print(f"\nExtracted {extracted_count} payloads to folder: {args.output}")

