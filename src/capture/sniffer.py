"""Live packet sniffer with 5-tuple flow assembly for AI-NIDS."""

from __future__ import annotations

import logging
import os
import signal
import struct
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Deque, Dict, Optional

import numpy as np
from scapy.all import IP, TCP, UDP, ICMP
from scapy.layers.inet import IP
from scapy.packet import Packet

LOGGER = logging.getLogger(__name__)
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

SNIFF_IFACE_ENV = "SNIFF_IFACE"
FLOW_TIMEOUT_ENV = "FLOW_TIMEOUT"
PACKET_QUEUE_SIZE_ENV = "PACKET_QUEUE_SIZE"

DEFAULT_IFACE = "eth0"
DEFAULT_FLOW_TIMEOUT = 60
DEFAULT_QUEUE_SIZE = 1000


@dataclass(flow=False)
class PacketInfo:
    """Container for parsed packet information."""

    timestamp: float
    size: int
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    flags: int
    direction: str


@dataclass
class Flow:
    """Container for assembled network flow."""

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    packets: list[PacketInfo] = field(default_factory=list)
    start_time: float = 0.0
    end_time: float = 0.0
    byte_count: int = 0
    packet_count: int = 0

    def to_dict(self) -> Dict:
        """Convert flow to dictionary for feature extraction."""
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "packets": [
                {
                    "timestamp": p.timestamp,
                    "size": p.size,
                    "flags": p.flags,
                    "direction": p.direction,
                }
                for p in self.packets
            ],
            "start_time": self.start_time,
            "end_time": self.end_time,
        }

    def duration(self) -> float:
        """Get flow duration in seconds."""
        return self.end_time - self.start_time


def _get_flow_key(packet: PacketInfo) -> tuple:
    """Generate 5-tuple flow key from packet."""
    protocol = packet.protocol
    if protocol == 6:
        proto_tuple = (TCP,)
    elif protocol == 17:
        proto_tuple = (UDP,)
    elif protocol == 1:
        proto_tuple = (ICMP,)
    else:
        proto_tuple = (packet.protocol,)
    
    src = (packet.src_ip, packet.src_port, packet.direction)
    dst = (packet.dst_ip, packet.dst_port)
    
    return (src, dst, proto_tuple)


def _parse_packet_to_info(packet: Packet) -> Optional[PacketInfo]:
    """Parse raw Scapy packet into PacketInfo."""
    if IP not in packet:
        return None
    
    ip_layer = packet[IP]
    timestamp = float(packet.time)
    size = len(packet)
    
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    protocol = ip_layer.proto
    
    src_port = 0
    dst_port = 0
    flags = 0
    
    if protocol == 6 and TCP in packet:
        tcp_layer = packet[TCP]
        src_port = tcp_layer.sport
        dst_port = tcp_layer.dport
        flags = tcp_layer.flags
    elif protocol == 17 and UDP in packet:
        udp_layer = packet[UDP]
        src_port = udp_layer.sport
        dst_port = udp_layer.dport
    elif protocol == 1 and ICMP in packet:
        icmp_layer = packet[ICMP]
        src_port = icmp_layer.type
        dst_port = icmp_layer.code
    
    direction = "fwd"
    
    return PacketInfo(
        timestamp=timestamp,
        size=size,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        flags=flags,
        direction=direction,
    )


class FlowTable:
    """Thread-safe flow storage with timeout management."""

    def __init__(self, timeout: int = 60):
        self._flows: Dict[tuple, Flow] = {}
        self._lock = threading.RLock()
        self._timeout = timeout

    def get_or_create(self, key: tuple, packet: PacketInfo) -> Flow:
        """Get existing flow or create new one."""
        with self._lock:
            if key not in self._flows:
                self._flows[key] = Flow(
                    src_ip=packet.src_ip,
                    dst_ip=packet.dst_ip,
                    src_port=packet.src_port,
                    dst_port=packet.dst_port,
                    protocol=packet.protocol,
                    start_time=packet.timestamp,
                    end_time=packet.timestamp,
                )
            return self._flows[key]

    def add_packet(self, key: tuple, packet: PacketInfo) -> Optional[Flow]:
        """Add packet to flow. Returns completed flow if timeout exceeded."""
        with self._lock:
            flow = self.get_or_create(key, packet)
            flow.packets.append(packet)
            flow.end_time = packet.timestamp
            flow.byte_count += packet.size
            flow.packet_count += 1
            
            time_since_last = packet.timestamp - flow.packets[0].timestamp
            if time_since_last > self._timeout:
                completed = flow
                del self._flows[key]
                return completed
            
            return None

    def get_completed_flows(self) -> list[Flow]:
        """Get and remove all timed-out flows."""
        current_time = time.time()
        completed = []
        
        with self._lock:
            timed_out_keys = []
            for key, flow in self._flows.items():
                if current_time - flow.end_time > self._timeout:
                    timed_out_keys.append(key)
                    completed.append(flow)
            
            for key in timed_out_keys:
                del self._flows[key]
        
        return completed

    def __len__(self) -> int:
        with self._lock:
            return len(self._flows)

    def clear(self) -> None:
        """Clear all flows."""
        with self._lock:
            self._flows.clear()


class PacketSniffer:
    """Live packet sniffer with flow assembly for real-time NIDS.
    
    This class captures packets from a network interface, assembles them
    into bidirectional flows by 5-tuple, and yields completed flows to
    a callback function for feature extraction and ML inference.
    
    Example:
        >>> def on_flow(flow_dict):
        ...     print(f"Flow complete: {flow_dict['src_ip']} -> {flow_dict['dst_ip']}")
        ...
        >>> sniffer = PacketSniffer(on_flow_complete=on_flow)
        >>> sniffer.start()
        >>> # ... after some time ...
        >>> sniffer.stop()
    """

    def __init__(
        self,
        interface: str | None = None,
        flow_timeout: int | None = None,
        packet_queue_size: int | None = None,
        on_flow_complete: Callable[[Dict], None] | None = None,
        bpf_filter: str = "tcp or udp or icmp",
    ):
        """Initialize packet sniffer.
        
        Args:
            interface: Network interface to sniff on (default: from env or eth0)
            flow_timeout: Flow timeout in seconds (default: from env or 60)
            packet_queue_size: Maximum packets to queue (default: 1000)
            on_flow_complete: Callback function when a flow completes
            bpf_filter: Berkeley Packet Filter expression
        """
        self._interface = interface or os.getenv(SNIFF_IFACE_ENV, DEFAULT_IFACE)
        self._flow_timeout = flow_timeout or int(os.getenv(FLOW_TIMEOUT_ENV, DEFAULT_FLOW_TIMEOUT))
        self._queue_size = packet_queue_size or int(os.getenv(PACKET_QUEUE_SIZE_ENV, DEFAULT_QUEUE_SIZE))
        self._bpf_filter = bpf_filter
        self._on_flow_complete = on_flow_complete
        
        self._flow_table = FlowTable(timeout=self._flow_timeout)
        self._packet_queue: Deque[Packet] = deque(maxlen=self._queue_size)
        
        self._running = False
        self._lock = threading.Lock()
        self._sniff_thread: threading.Thread | None = None
        self._process_thread: threading.Thread | None = None
        self._stats = {
            "packets_captured": 0,
            "flows_completed": 0,
            "bytes_captured": 0,
        }
        
        LOGGER.info(
            "PacketSniffer initialized: interface=%s, timeout=%ds, queue_size=%d",
            self._interface,
            self._flow_timeout,
            self._queue_size,
        )

    def _sniff_packets(self) -> None:
        """Background thread: capture packets from interface."""
        try:
            from scapy.all import sniff
            
            sniff(
                iface=self._interface,
                filter=self._bpf_filter,
                prn=self._packet_queue.append,
                store=False,
                stop_filter=self._should_stop,
            )
        except Exception as e:
            LOGGER.error("Sniffing error: %s", e)
            self._running = False

    def _should_stop(self, packet: Optional[Packet] = None) -> bool:
        """Check if sniffer should stop."""
        return not self._running

    def _process_packets(self) -> None:
        """Background thread: process queued packets into flows."""
        while self._running:
            try:
                while self._packet_queue:
                    try:
                        packet = self._packet_queue.popleft()
                    except IndexError:
                        break
                    
                    packet_info = _parse_packet_to_info(packet)
                    if packet_info is None:
                        continue
                    
                    with self._lock:
                        self._stats["packets_captured"] += 1
                        self._stats["bytes_captured"] += packet_info.size
                    
                    forward_key = (
                        (packet_info.src_ip, packet_info.src_port, "fwd"),
                        (packet_info.dst_ip, packet_info.dst_port),
                        (packet_info.protocol,),
                    )
                    
                    backward_key = (
                        (packet_info.dst_ip, packet_info.dst_port, "bwd"),
                        (packet_info.src_ip, packet_info.src_port),
                        (packet_info.protocol,),
                    )
                    
                    completed = self._flow_table.add_packet(forward_key, packet_info)
                    if completed is None:
                        completed = self._flow_table.add_packet(backward_key, packet_info)
                    
                    if completed and self._on_flow_complete:
                        with self._lock:
                            self._stats["flows_completed"] += 1
                        try:
                            self._on_flow_complete(completed.to_dict())
                        except Exception as e:
                            LOGGER.error("Flow callback error: %s", e)
                
                timed_out_flows = self._flow_table.get_completed_flows()
                for flow in timed_out_flows:
                    if self._on_flow_complete:
                        with self._lock:
                            self._stats["flows_completed"] += 1
                        try:
                            self._on_flow_complete(flow.to_dict())
                        except Exception as e:
                            LOGGER.error("Flow callback error: %s", e)
                
                time.sleep(0.01)
                
            except Exception as e:
                LOGGER.error("Packet processing error: %s", e)
                time.sleep(1)

    def start(self) -> None:
        """Start packet capture in background threads."""
        if self._running:
            LOGGER.warning("Sniffer already running")
            return
        
        with self._lock:
            self._running = True
        
        self._sniff_thread = threading.Thread(target=self._sniff_packets, daemon=True)
        self._process_thread = threading.Thread(target=self._process_packets, daemon=True)
        
        self._sniff_thread.start()
        self._process_thread.start()
        
        LOGGER.info("Sniffer started on interface %s", self._interface)

    def stop(self) -> None:
        """Stop packet capture gracefully."""
        if not self._running:
            return
        
        LOGGER.info("Stopping sniffer...")
        
        with self._lock:
            self._running = False
        
        if self._sniff_thread:
            self._sniff_thread.join(timeout=2.0)
        if self._process_thread:
            self._process_thread.join(timeout=2.0)
        
        remaining_flows = self._flow_table.get_completed_flows()
        for flow in remaining_flows:
            if self._on_flow_complete:
                try:
                    self._on_flow_complete(flow.to_dict())
                except Exception as e:
                    LOGGER.error("Final flow callback error: %s", e)
        
        self._flow_table.clear()
        LOGGER.info("Sniffer stopped. Final stats: %s", self._stats)

    def is_running(self) -> bool:
        """Check if sniffer is currently capturing."""
        return self._running

    def get_stats(self) -> Dict:
        """Get sniffer statistics."""
        with self._lock:
            return self._stats.copy()

    @property
    def interface(self) -> str:
        """Get configured interface."""
        return self._interface

    @property
    def flow_timeout(self) -> int:
        """Get flow timeout in seconds."""
        return self._flow_timeout


def create_sniffer(
    on_flow_complete: Callable[[Dict], None],
    interface: str | None = None,
    flow_timeout: int | None = None,
) -> PacketSniffer:
    """Convenience factory to create and start a sniffer.
    
    Args:
        on_flow_complete: Callback for completed flows
        interface: Network interface (default: eth0)
        flow_timeout: Flow timeout in seconds (default: 60)
        
    Returns:
        Started PacketSniffer instance
    """
    sniffer = PacketSniffer(
        interface=interface,
        flow_timeout=flow_timeout,
        on_flow_complete=on_flow_complete,
    )
    sniffer.start()
    return sniffer


__all__ = [
    "PacketSniffer",
    "PacketInfo",
    "Flow",
    "FlowTable",
    "create_sniffer",
]
