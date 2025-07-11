from scapy.all import sniff, IP, TCP
from collections import defaultdict
import threading
import queue


"""
Name: PacketCapture
Description: Basis of our IDS
"""
class PacketCapture:
    def __init__(self):
        # Initialize class to store captured packets
        self.packet_queue = queue.Queue()
        # Threading event to control when the packet capture should stop
        self.stop_capture = threading.Event()
    
    # Handler for each captured packet
    def packet_callback(self, packet):
        # Checks if packet contains both IP and TCP layers
        if IP in packet and TCP in packet:
                self.packet_queue.put(packet)

    # Start capturing packets on a specified interface
    #   - Default to eth0 to capture packets from the Ethernet interface
    def start_capture(self, interface="eth0"):
        # Continuously monitors the interface for packets
        def capture_thread():
                sniff(iface=interface,
                    prn = self.packet_callback,
                    store = 0,
                    stop_filter = lambda _: self.stop_capture.is_set()
                    )
        self.capture_thread = threading.thread(target=capture_thread)
        self.capture_thread.start()

    def stop(self):
        # Stops the capture 
        self.stop_capture.set()
        # Wait for thread to finish executing
        # Terminates cleanly
        self.capture_thread.join()