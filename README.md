pcapfex - Packet Capture Forensic Evidence Extractor
====================================================

Version: 1.3
Author: packetlife

Overview:
---------
This script is designed to extract payloads from a packet capture (PCAP) file and detect the file types of those payloads. It is useful for forensic analysis, malware investigation, and network traffic inspection.

Features:
---------
- Reads packets from a PCAP file using Scapy.
- Extracts raw payloads from packets that contain data.
- Detects the MIME type of each payload using libmagic (via python-magic).
- Saves each payload to a file with an appropriate extension based on its detected type.
- Supports optional entropy-based extraction and checksum verification flags.

Usage:
------
Run the script from the command line:

    python pcapfex.py <PCAP_FILE> [OUTPUT_FOLDER] [-e] [-nv] [--T UDP_TIMEOUT]

Arguments:
----------
- PCAP_FILE: Path to the input .pcap file.
- OUTPUT_FOLDER: Directory where extracted payloads will be saved (default: 'output').
- -e: Enable entropy-based raw data extraction (currently placeholder).
- -nv: Disable IP/TCP/UDP checksum verification.
- --T: Set timeout for UDP-stream heuristics (default: 120 seconds).

Requirements:
-------------
- Python 3.x
- scapy
- python-magic
- libmagic (system dependency for python-magic)

Installation:
-------------
Install required Python packages:

    pip install scapy python-magic

On macOS, you may also need to install libmagic:

    brew install libmagic

Output:
-------
- Extracted payloads are saved in the specified output folder.
- Each file is named as 'payload_<index>.<extension>' based on its detected MIME type.

Example:
--------
    python pcapfex.py traffic.pcap extracted_payloads -nv

This will extract payloads from 'traffic.pcap' and save them in the 'extracted_payloads' folder.

Notes:
------
- The script currently extracts payloads from packets containing a Raw layer.
- MIME type detection helps identify file formats such as text, images, executables, etc.
- Entropy-based extraction is not yet implemented.

