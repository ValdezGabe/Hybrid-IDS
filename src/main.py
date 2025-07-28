import numpy as np
import threading
import queue
import logging
import json
import time

from scapy.all import sniff, IP, TCP
from collections import defaultdict
from sklearn.ensemble import IsolationForest
from datetime import datetime

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
        self.capture_thread = None
    
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
                prn=self.packet_callback,
                store=0,
                stop_filter=lambda _: self.stop_capture.is_set()
                )
        self.capture_thread = threading.Thread(target=capture_thread)
        self.capture_thread.start()

    def stop(self):
        # Stops the capture 
        self.stop_capture.set()
        # Wait for thread to finish executing
        # Terminates cleanly
        if self.capture_thread:
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
            
            # Handle packet time - use current time if packet.time is not available
            try:
                curr_time = packet.time
            except AttributeError:
                curr_time = time.time()

            if not stats['start_time']:
                stats['start_time'] = curr_time
            stats['last_time'] = curr_time

            # Calculate and return metrics
            return self.extract_features(packet, stats)
        
        return None
    
    # Compute detailed characteristics of the flow and current packet
    def extract_features(self, packet, stats): 
        duration = stats['last_time'] - stats['start_time']
        duration = duration if duration > 0 else 1e-6
        return {
            'packet_size': len(packet),
            'flow_duration': duration,
            'packet_rate': stats['packet_count'] / duration,
            'byte_rate': stats['byte_count'] / duration,
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
        # Predefined rules for specific attack patterns
        self.anomaly_detector = IsolationForest(
            contamination=0.1,
            random_state=42
        )
        self.signature_rules = self.load_signature_rules()
        self.is_trained = False
        
        # Generate and train on synthetic normal traffic data
        self._train_with_synthetic_data()

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

    def _generate_synthetic_normal_traffic(self, num_samples=1000):
        """Generate synthetic normal traffic data for training"""
        np.random.seed(42)
        
        # Generate realistic normal traffic patterns
        normal_data = []
        for _ in range(num_samples):
            # Normal packet sizes (typically 64-1500 bytes)
            packet_size = np.random.normal(400, 200)
            packet_size = max(64, min(1500, packet_size))
            
            # Normal packet rates (1-50 packets per second)
            packet_rate = np.random.exponential(10)
            packet_rate = max(0.1, min(50, packet_rate))
            
            # Normal byte rates
            byte_rate = packet_size * packet_rate * np.random.uniform(0.5, 2.0)
            
            normal_data.append([packet_size, packet_rate, byte_rate])
        
        return np.array(normal_data)

    def _train_with_synthetic_data(self):
        """Train the anomaly detector with synthetic normal traffic data"""
        normal_traffic_data = self._generate_synthetic_normal_traffic()
        self.train_anomaly_detector(normal_traffic_data)

    # Train model using a dataset of normal traffic features
    def train_anomaly_detector(self, normal_traffic_data):
        self.anomaly_detector.fit(normal_traffic_data)
        self.is_trained = True
        print(f"Anomaly detector trained with {len(normal_traffic_data)} samples")

    # Evaluate network traffic features for potential threats
    def detect_threats(self, features):
        threats = []

        # Signature-based detection
        # - Iteratively go through each rule
        # - Apply condition to the rule
        # - If it matches, then the threat is recorded with high confidence
        for rule_name, rule in self.signature_rules.items():
            try:
                if rule['condition'](features):
                    threats.append({
                        'type': 'signature',
                        'rule': rule_name,
                        'confidence': 1.0
                    })
            except Exception as e:
                # Handle any errors in rule evaluation
                print(f"Error evaluating rule {rule_name}: {e}")
                continue

        # Anomaly-based detection
        # Only perform anomaly detection if model is trained
        if self.is_trained:
            try:
                # Processes the packet size, packet rate, and byte rate in the feature vector through the IF model
                # Calculate the anomaly score
                # If score indicates unusual behavior, then it is an anomaly and produces a high confidence score based on its severity
                feature_vector = np.array([[
                    features['packet_size'],
                    features['packet_rate'],
                    features['byte_rate']
                ]])

                anomaly_score = self.anomaly_detector.score_samples(feature_vector)[0]
                if anomaly_score < -0.5:  # Threshold for anomaly detection
                    threats.append({
                        'type': 'anomaly',
                        'score': anomaly_score,
                        'confidence': min(1.0, abs(anomaly_score))
                    })
            except Exception as e:
                print(f"Error in anomaly detection: {e}")

        # Return the aggregated list of threats
        return threats


class AlertSystem:
    def __init__(self, log_file="ids_alerts.log"):
        self.logger = logging.getLogger("IDS_Alerts")
        self.logger.setLevel(logging.INFO)

        # Clear any existing handlers
        self.logger.handlers.clear()

        handler = logging.FileHandler(log_file)
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )

        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def generate_alert(self, threat, packet_info):
        alert = {
            'timestamp': datetime.now().isoformat(),
            'threat_type': threat['type'],
            'source_ip': packet_info.get('source_ip'),
            'destination_ip': packet_info.get('destination_ip'),
            'confidence': threat.get('confidence', 0.0),
            'details': threat
        }

        self.logger.warning(json.dumps(alert))

        if threat['confidence'] > 0.8: 
            self.logger.critical(
                f"High confidence threat detected: {json.dumps(alert)}"
            )
            # implement additional notification methods here
            # (e.g., email, Slack, SIEM integration)


class IntrusionDetectionSystem:
    def __init__(self, interface='eth0'):
        self.packet_capture = PacketCapture()
        self.traffic_analyzer = TrafficAnalyzer()
        self.detection_engine = DetectionEngine()
        self.alert_system = AlertSystem()
        self.interface = interface

    def start(self):
        print(f"Starting IDS on interface {self.interface}")
        self.packet_capture.start_capture(self.interface)

        try:
            while True:
                try:
                    packet = self.packet_capture.packet_queue.get(timeout=1)
                    features = self.traffic_analyzer.analyze_packet(packet)

                    if features:
                        threats = self.detection_engine.detect_threats(features)

                        for threat in threats:
                            packet_info = {
                                'source_ip': packet[IP].src,
                                'destination_ip': packet[IP].dst,
                                'source_port': packet[TCP].sport,
                                'destination_port': packet[TCP].dport
                            }
                            self.alert_system.generate_alert(threat, packet_info)
                            print(f"THREAT DETECTED: {threat['type']} - {threat}")

                # 2 Exceptions: 
                # - No packets available for processing
                # - Stop IDS gracefully by halting packet capture and exiting the loop
                except queue.Empty:
                    continue
        except KeyboardInterrupt:
            print("Stopping IDS...")
            self.packet_capture.stop()


def test_ids():
    # Create test packets to simulate various scenarios
    test_packets = [
        # Normal traffic
        IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=1234, dport=80, flags="A"),
        IP(src="192.168.1.3", dst="192.168.1.4") / TCP(sport=1235, dport=443, flags="P"),

        # SYN flood simulation
        IP(src="10.0.0.1", dst="192.168.1.2") / TCP(sport=5678, dport=80, flags="S"),
        IP(src="10.0.0.2", dst="192.168.1.2") / TCP(sport=5679, dport=80, flags="S"),
        IP(src="10.0.0.3", dst="192.168.1.2") / TCP(sport=5680, dport=80, flags="S"),

        # Port scan simulation
        IP(src="192.168.1.100", dst="192.168.1.2") / TCP(sport=4321, dport=22, flags="S"),
        IP(src="192.168.1.100", dst="192.168.1.2") / TCP(sport=4321, dport=23, flags="S"),
        IP(src="192.168.1.100", dst="192.168.1.2") / TCP(sport=4321, dport=25, flags="S"),
    ]

    ids = IntrusionDetectionSystem()

    # Simulate packet processing and threat detection
    print("Starting IDS Test...")
    for i, packet in enumerate(test_packets, 1):
        print(f"\nProcessing packet {i}: {packet.summary()}")

        # Analyze the packet
        features = ids.traffic_analyzer.analyze_packet(packet)

        if features:
            print(f"Features: packet_size={features['packet_size']}, "
                  f"packet_rate={features['packet_rate']:.2f}, "
                  f"byte_rate={features['byte_rate']:.2f}")
            
            # Detect threats based on features
            threats = ids.detection_engine.detect_threats(features)

            if threats:
                print(f"Detected threats: {threats}")
                # Generate alerts for detected threats
                packet_info = {
                    'source_ip': packet[IP].src,
                    'destination_ip': packet[IP].dst,
                    'source_port': packet[TCP].sport,
                    'destination_port': packet[TCP].dport
                }
                for threat in threats:
                    ids.alert_system.generate_alert(threat, packet_info)
            else:
                print("No threats detected.")
        else:
            print("Packet does not contain IP/TCP layers or is ignored.")

    print("\nIDS Test Completed.")


if __name__ == "__main__":
    # Uncomment if you want to test
    # test_ids()
    
    # Run the live IDS
    ids = IntrusionDetectionSystem(interface="en0")
    ids.start()