#!/usr/bin/env python3

from scapy.all import *
import random

# Define target node and port
target_node = "dtn://node1"
target_port = 4556

# Define bundle protocol fields and payloads to be fuzzed
bundle_fields = {
    "primary": {
        "version": 6,
        "proc_flags": random.randint(0, 255),
        "crc_type": random.randint(0, 255),
        "block_length": random.randint(0, 65535),
    },
    "source": {
        "eid": "dtn://source",
    },
    "destination": {
        "eid": target_node,
    },
    "custody": {
        "custody_flags": random.randint(0, 255),
        "custody_signal": random.choice(["none", "accept", "discard"]),
    },
    "payload": {
        "data": b"Fuzzing payload goes here",
    },
}

# Define fuzzing parameters
num_packets = 1000
min_payload_size = 1
max_payload_size = 100
payload_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()_+-=[]{}\\|;:'\",.<>/?`~ "

# Generate and send fuzzed bundles
for i in range(num_packets):
    # Generate random payload
    payload_size = random.randint(min_payload_size, max_payload_size)
    payload = "".join(random.choices(payload_chars, k=payload_size)).encode()

    # Update bundle fields with fuzzed values
    bundle_fields["primary"]["proc_flags"] = random.randint(0, 255)
    bundle_fields["primary"]["crc_type"] = random.randint(0, 255)
    bundle_fields["primary"]["block_length"] = random.randint(0, 65535)
    bundle_fields["custody"]["custody_flags"] = random.randint(0, 255)
    bundle_fields["custody"]["custody_signal"] = random.choice(["none", "accept", "discard"])
    bundle_fields["payload"]["data"] = payload

    # Construct and send bundle
    bundle = Bundle() / BundlePrimaryBlock(**bundle_fields["primary"]) / BundleSourceBlock(**bundle_fields["source"]) / BundleDestinationBlock(**bundle_fields["destination"]) / BundleCustodySignalBlock(**bundle_fields["custody"]) / BundlePayloadBlock(**bundle_fields["payload"])
    send(bundle, verbose=0)
    print(f"Sent bundle #{i+1}")
