# pcap-parallel: split and parallel process a PCAP file

## About

This package enables processing a PCAP file (for example, one produced
by `tcpdump`) to be processed in parallel on a multi-core machine.  It
achieves this by reading the entire file using the `dpkt` module to
scan only each packet as quickly as possible to identify where the
packet boundaries are within the file.  Then sections of the file are
loaded into `io.ByteIO` sections and handed to callback routines for
processing.  The callback routines are spun off as separate processes,
enabling them to do deeper (aka slower) packet processing.

Code: https://github.com/hardaker/pcap-parallel

### Notes

- It loads the entire file into memory!!  You've been warned.
    - TODO: offer using file pointers instead with a length to read
- Your code must not care about packet ordering since parts of the
  module will be processed by one function, and a future part by
  another even though a TCP stream or similar might be split across
  the multiple calls.
- It will attempt to calculate a split size and a maximum_cores value
  for you, but it will not do a good job (especially on compressed
  files).  You may (should) specify your own values when creating a
  class.
- This will not a huge speed benefit if you aren't doing fairly
  complex processing (the example below only does minimal processing).
  If you're using something like `scapy`, though, it will definitely
  help.
- It can handle compressed files (gzip, bz2, and xz) assuming you have
  the needed decompression modules installed.
- It returns a list of `Future` objects, so make sure to call
  `.result()` on each item in the list in order to ensure you get the
  actual results from your callback.
- Because the results are run within a separate process, the contents
  to return from each callback should be pickleable.

# Installation

    pip install pcap-parallel

# Usage

The following example uses the `dpkt` module to count all the source
IP addresses seen in a PCAP file and display the results.  Note that
this is not super intensive processing, but at least demonstrates how
the module should work.

``` python
import dpkt
import ipaddress
from pcap_parallel import PCAPParallel
from collections import Counter

def process_partial_pcap(file_handle):
    """Process a chunk of a larger PCAP file

    Note: this will be launched multiple times in separate processes"""

    # store counters of data
    srcs = Counter()

    # read the pcap in and count all the sources
    pcap = dpkt.pcap.Reader(file_handle)
    for timestamp, packet in pcap:
        eth = dpkt.ethernet.Ethernet(packet)
        if isinstance(eth.data, dpkt.ip.IP):
            try:
                ip = eth.data
                srcs[str(ipaddress.ip_address(ip.src))] += 1
            except Exception:
                pass

    return srcs

ps = PCAPParallel(
    "test.pcap",
    callback=process_partial_pcap,
)
partial_results = ps.split()

# merge the results
total_counts = partial_results.pop(0).result()
for partial in partial_results:
    next_counts = partial.result()
    for key in next_counts:
        total_counts[key] += next_counts[key]

# print the results
for key in total_counts:
    print(f"{key:<30} {str(total_counts[key]):>8}")
```

# License

See the [./LICENSE] file for the details of the Apache 2.0 license.

# Author

Wes Hardaker <opensource magic_email_symbol hardakers.net>
USC/ISI
https://www.isi.edu/~hardaker

# Acknowledgments

This module is a spin-off of a larger research project of Wes
Hardaker's at USC/ISI that is funded by Comcast.  We thank Comcast for
their support in making this module possible.
