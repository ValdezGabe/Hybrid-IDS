import numpy as np
import threading
import queue


from scapy.all import sniff, IP, TCP
from collections import defaultdict
from sklearn.ensemble import IsolationForest

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


"""
Name: TrafficAnalyzer
Description: Analyzes network traffic. Tracks connection flows and calculate statistics for packets in real time
"""
class TrafficAnalyzer:

    # Organize data by unique flows using defaultdict()
    def __init__(self):
            # Initialize connection attribute to store lists of related packets for each flow
          self.connections = defaultdict(list)
            # Initialize flow_stats attribute to store aggregated statistics for each flow:
            #   - packet count, byte count, start time, time of the most recent packet
          self.flow_stats = defaultdict(lambda: {
               'packet_count': 0,
               'byte_count': 0,
               'start_time': None,
               'last_time': None
          })

    # Process each packet
    def analyze_packet(self, packet):
        # If the packet contains IP/TCP layers
        # Extract the source and destination IPs and ports
        if IP in packet and TCP in packet:
              ip_src = packet[IP].src
              ip_dst = packet[IP].dst
              port_src = packet[TCP].sport
              port_dst = packet[TCP].dport
        
        # Create flow key from the source and destination IPs and ports
        # Identifies flow
        flow_key = (ip_src, ip_dst, port_src, port_dst)

        # Updates the statistics for the flow
        stats = self.flow_stats[flow_key]
        stats['packet_count'] += 1
        stats['byte_count'] += len(packet)
        curr_time = packet.time

        if not stats['start_time']:
            stats['start_time'] = curr_time
        stats['last_time'] = curr_time

        # Calculate and return metrics
        return self.extract_features(packet, stats)
    

    # Compute detailed characteristics of the flow and current packet
    def extract_features(self, packet, stats): 
        return {
            'packet_size': len(packet),
            'flow_duration': stats['last_time'] - stats['start_time'],
            'packet_rate': stats['packet_count'] / (stats['last_time'] - stats['start_time']),
            'byte_rate': stats['byte_count'] / (stats['last_time'] - stats['start_time']),
            'tcp_flags': packet[TCP].flags,
            'window_size': packet[TCP].window
        }

"""
Name: DetectionEngine
Description: Hybrid detection system that is signature based and anomaly based
"""
class DetectionEngine:
    def __init__(self):
        # Isolation Forest Model to detect anomalies 
        # Predifined rules for specifc attack patterns
        self.anomaly_detector = IsolationForest(
            contamination=0.1,
            random_state=42
        )

    def load_signature_rules(self):
        return {
            'syn_flood': {
                'condition': lambda features: (
                    features['tcp_flags'] == 2 and # SYN flag
                    features['packet_rate'] > 100
                )
            },
            'port_scan': {
                'condition': lambda features: (
                    features['packet_size'] < 100 and 
                    features['packet_rate'] > 50
                )
            }
        }

    # Train model using a dataset of normal traffic features
    def train_anomaly_detector(self, normal_traffic_data):
        self.anomaly_detector.fit(normal_traffic_data)

    # Evaluate network traffic features for potential threats
    def detect_threats(self, features):
        threats = []

        # Signature-based detection
        # - Iteratively go through each rule
        # - Apply condition to the rule
        # - If it matches, then the threat is recorded with high confidence
        for rule_name, rule in self.load_signature_rules.items():
             if rule['condition'](features):
                threats.append({
                    'type': 'signature',
                    'rule': rule_name,
                    'confidence': 1.0
                  })

        # Anomaly-based detection
        # - Processes the packet size, packet rate, and byte rate in the feature vector throguh the IF model
        # - Calculate the anomaly score
        # - If score indicates unusual behavior, then it is an anomaly and produces a high confidence score based on its severity
        feature_vector = np.array([[
            features['packet_size'],
            features['packet_rate'],
            features['byte_rate']
        ]])

        anomaly_score = self.anomaly_detector.score_samples(feature_vector)[0]
        if anomaly_score < -0.5: # Threshold for anomaly detection
            threats.append({
                'type': 'anomaly',
                'score':anomaly_score,
                'confidence':min(1.0, abs(anomaly_score))
            })

        # Return the aggregated list of threats
        return threats
    
