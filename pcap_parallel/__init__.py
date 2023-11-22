"""Loads a PCAP file and counts contents with various levels of storage"""

import io
import os
import multiprocessing
from typing import List
import dpkt
from concurrent.futures import ProcessPoolExecutor, Future
from logging import debug, info


class PCAPParallel:
    """Quickly reads a PCAP file and splits the contents.

    Each file is split into multiple io.BytesIO streams, which will
    result in loading the entire contents into memory.  Callbacks for
    each section will be executed in a separate process.
    """

    def __init__(
        self,
        pcap_file: str,
        callback=None,
        split_size: int = 0,
        maximum_count: int = 0,
        pcap_filter: str | None = None,
        maximum_cores: int | None = None,
    ) -> List[io.BytesIO]:
        self.pcap_file: str = pcap_file
        self.callback = callback
        self.split_size: int = split_size
        self.maximum_count: int = maximum_count
        self.pcap_filter: str | None = pcap_filter
        self.maximum_cores = maximum_cores

        self.header: bytes = None
        self.buffer: bytes = None
        self.packets_read: int = 0
        self.dpkt_data = None
        self.our_data = None
        self.results: List[io.BytesIO] = []
        self.process_pool = ProcessPoolExecutor()

        if not os.path.exists(self.pcap_file):
            raise ValueError(f"failed to find pcap file '{self.pcap_file}'")

    def set_split_size(self):
        "Attempt to calculate a reasonable split size"
        if self.split_size:
            info(f"split size already set to {self.split_size}")
            return self.split_size

        cores = multiprocessing.cpu_count()
        if self.maximum_cores and cores > self.maximum_cores:
            cores = self.maximum_cores

        if self.maximum_count and self.maximum_count > 0:
            # not ideal math, but better than nothing
            self.split_size = int(self.maximum_count / cores)
        else:
            if isinstance(self.our_data, io.BufferedReader):
                # raw uncompressed file
                divide_size = 1200
            else:
                # likely a compressed file
                divide_size = 5000

            # even worse math and assumes generally large packets
            stats = os.stat(self.pcap_file)
            file_size = stats.st_size
            self.split_size = int(file_size / divide_size / cores)
            debug(
                f"split info: {file_size=}, {divide_size=}, {cores=}, {self.split_size=}"
            )

        # even 1000 is kinda silly to split, but is better than nothing
        self.split_size = max(self.split_size, 1000)
        debug(f"setting PCAPSplitter split size to {self.split_size} for {cores} cores")

    # TODO: how is this not a base package somewhere?
    @staticmethod
    def open_maybe_compressed(filename):
        """Opens a pcap file, potentially decompressing it."""

        magic_dict = {
            bytes([0x1F, 0x8B, 0x08]): "gz",
            bytes([0x42, 0x5A, 0x68]): "bz2",
            bytes([0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00]): "xz",
        }
        max_len = max(len(x) for x in magic_dict)

        base_handle = open(filename, "rb")
        file_start = base_handle.read(max_len)
        base_handle.close()

        for magic, filetype in magic_dict.items():
            if file_start.startswith(magic):
                try:
                    if filetype == "gz":
                        import gzip

                        return_handle = gzip.open(filename, "rb")
                        return return_handle
                    elif filetype == "bz2":
                        import bz2

                        return_handle = bz2.open(filename, "rb")
                        setattr(return_handle, "name", filename)
                        return return_handle
                    elif filetype == "xz":
                        import lzma

                        return_handle = lzma.open(filename, "rb")
                        return return_handle
                    else:
                        raise ValueError("unknown compression error")
                except Exception:
                    # likely we failed to find a compression module
                    debug(f"failed to use {filetype} module to decode the input stream")
                    raise ValueError("cannot decode file")

        # return a raw file and hope it's not compressed'
        return open(filename, "rb")

    def split(self) -> List[io.BytesIO] | List[Future]:
        "Does the actual reading and splitting"

        # open one for the dpkt reader and one for us independently
        self.our_data = self.open_maybe_compressed(self.pcap_file)
        self.dpkt_data = self.open_maybe_compressed(self.pcap_file)

        self.set_split_size()

        # read the first 24 bytes which is the pcap header
        self.header = self.our_data.read(24)

        # now process with dpkt to pull out each packet
        pcap = dpkt.pcap.Reader(self.dpkt_data)
        if self.pcap_filter:
            pcap.setfilter(self.pcap_filter)
        pcap.dispatch(self.maximum_count, self.dpkt_callback)

        # TODO: need to process the remaining bytes
        self.save_packets()

        self.process_pool.shutdown(wait=True, cancel_futures=False)

        return self.results

    def save_packets(self):
        "Saves the contents seen to this point into a new io.BytesIO"
        self.buffer = bytes(self.header)

        # read from our files current position to where the dpkt reader is
        bytes_to_read: int = self.dpkt_data.tell() - self.our_data.tell()
        self.buffer += self.our_data.read(bytes_to_read)

        if self.callback:
            self.results.append(
                self.process_pool.submit(self.callback, io.BytesIO(self.buffer))
            )
        else:
            self.results.append(io.BytesIO(self.buffer))

        # if we've collected data, call the callback

    def dpkt_callback(self, timestamp: float, packet: bytes):
        "Handles each packet received by dpkt"
        self.packets_read += 1

        if self.packets_read % self.split_size == 0:
            self.save_packets()
