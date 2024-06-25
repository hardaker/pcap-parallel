import os
import time
from logging import debug
from pcap_parallel import PCAPParallel
import dpkt


def buffer_callback(pcap_io_buffer):
    count = 0
    pcap = dpkt.pcap.Reader(pcap_io_buffer)
    for packet in pcap:
        count += 1
    return count


def test_pcap_parallel(*args, **kwargs):
    """tests that the class works -- requires a test.pcap or similar file to exist.

    Adding additional args/kwargs will be passed to the PCAPParallel init.
    """
    for test_pcap in [
        "test.pcap",
        "testgz.pcap.gz",
        "testbz2.pcap.bz2",
        "testxz.pcap.xz",
    ]:
        debug(f"===== trying to load {test_pcap} ====")
        if not os.path.exists(test_pcap):
            print(f"a test requires a {test_pcap} file to read and parse")
            continue

        time.time()

        split_size = 100
        maximum_count = 0

        ps = PCAPParallel(
            test_pcap,
            *args,
            split_size=split_size,
            callback=buffer_callback,
            maximum_count=maximum_count,
            **kwargs,
        )
        results = ps.split()

        assert len(results) > 0

        one_result = results[0].result()
        assert isinstance(one_result, int)


if __name__ == "__main__":
    test_pcap_parallel()
