#!/usr/bin/env python3
"""
Advanced Intrusion Detection System (AIDS) v2.0
"""

import tkinter as tk
from tkinter import ttk, messagebox
from scapy.all import AsyncSniffer, IP, TCP, UDP, ICMP, ARP
from datetime import datetime
import threading
import json
import os
import logging
from logging.handlers import RotatingFileHandler
import pickle
import numpy as np
from sklearn.ensemble import IsolationForest
from collections import deque
import yaml
import platform
import subprocess

# ---------------- CONFIG ---------------- #
class ConfigManager:
    DEFAULT_CONFIG = {
        'thresholds': {
            'port_scan': 10,
            'syn_flood': 50,
            'arp_spoof': 5,
            'connection_rate': 100
        },
        'alerting': {
            'email': {
                'enabled': False,
                'smtp_server': '',
                'port': 587,
                'username': '',
                'password': '',
                'recipients': []
            },
            'sound': True
        },
        'logging': {
            'file': 'aids.log',
            'max_size': 10,
            'backup_count': 5
        },
        'gui': {
            'theme': 'dark',
            'graph_refresh': 5
        },
        'ml_model': {
            'path': 'ml_model.pkl',
            'train_interval': 3600
        }
    }

    def __init__(self, config_file='config.yaml'):
        self.config_file = config_file
        self.load_config()

    def load_config(self):
        try:
            with open(self.config_file) as f:
                self.config = yaml.safe_load(f)
            for section, values in self.DEFAULT_CONFIG.items():
                self.config.setdefault(section, values)
        except:
            self.config = self.DEFAULT_CONFIG
            self.save_config()

    def save_config(self):
        with open(self.config_file, 'w') as f:
            yaml.dump(self.config, f)

config = ConfigManager()

# ---------------- LOGGER ---------------- #
def setup_logger():
    logger = logging.getLogger("aids")
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    handler = RotatingFileHandler(
        config.config['logging']['file'],
        maxBytes=config.config['logging']['max_size'] * 1024 * 1024,
        backupCount=config.config['logging']['backup_count']
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger

logger = setup_logger()

# ---------------- ML DETECTOR ---------------- #
class AnomalyDetector:
    def __init__(self):
        self.model = None
        self.features = []
        self.load_model()

    def load_model(self):
        try:
            with open(config.config['ml_model']['path'], 'rb') as f:
                self.model = pickle.load(f)
            logger.info("ML model loaded")
        except:
            self.model = IsolationForest(contamination=0.05)
            logger.info("New ML model initialized")

    def save_model(self):
        with open(config.config['ml_model']['path'], 'wb') as f:
            pickle.dump(self.model, f)

    def extract_features(self, pkt):
        features = {
            'size': len(pkt),
            'proto': 0,
            'ttl': 0
        }

        if pkt.haslayer(IP):
            features['ttl'] = pkt[IP].ttl
        if pkt.haslayer(TCP):
            features['proto'] = 1
        elif pkt.haslayer(UDP):
            features['proto'] = 2
        elif pkt.haslayer(ICMP):
            features['proto'] = 3
        elif pkt.haslayer(ARP):
            features['proto'] = 4

        return features

    def detect(self, feats):
        if not self.model or len(feats) < 10:
            return []
        X = np.array([[f['size'], f['proto'], f['ttl']] for f in feats])
        preds = self.model.predict(X)
        return [i for i, p in enumerate(preds) if p == -1]

# ---------------- ALERTING ---------------- #
class AlertManager:
    def __init__(self, callback=None):
        self.history = deque(maxlen=1000)
        self.callback = callback

    def alert(self, level, title, msg, pkt=None):
        time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        data = {'time': time, 'level': level, 'title': title, 'msg': msg}
        self.history.append(data)
        logger.warning(f"[{level}] {title}: {msg}")
        if self.callback:
            self.callback(data)
        if config.config['alerting']['sound']:
            try:
                if platform.system() == "Linux":
                    subprocess.call(['paplay', '/usr/share/sounds/freedesktop/stereo/dialog-warning.oga'])
            except:
                pass

# ---------------- PACKET ANALYZER ---------------- #
class PacketAnalyzer:
    def __init__(self, alert_mgr, ml_detector):
        self.alert_mgr = alert_mgr
        self.ml = ml_detector
        self.packet_log = []
        self.syn_count = {}
        self.scan_attempts = {}

    def analyze(self, pkt):
        self.packet_log.append(pkt)
        feats = self.ml.extract_features(pkt)
        self.ml.features.append(feats)

        if pkt.haslayer(TCP):
            ip = pkt[IP].src
            if pkt[TCP].flags == 'S':
                self.syn_count[ip] = self.syn_count.get(ip, 0) + 1
                if self.syn_count[ip] > config.config['thresholds']['syn_flood']:
                    self.alert_mgr.alert("HIGH", "SYN Flood Detected", f"{ip} sent too many SYNs")

        if len(self.ml.features) % 20 == 0:
            anomalies = self.ml.detect(self.ml.features[-100:])
            if anomalies:
                self.alert_mgr.alert("MEDIUM", "Anomaly Detected", f"{len(anomalies)} suspicious packets")

# ---------------- GUI ---------------- #
class AIDS_GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("AIDS v2.0 - Advanced Intrusion Detection System")
        self.root.geometry("850x550")
        self.root.configure(bg="#0d1117")

        self.text_area = tk.Text(root, bg="#0d1117", fg="#ffffff", insertbackground='white', font=("Consolas", 10))
        self.text_area.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

        self.status = tk.Label(root, text="Status: Stopped", bg="#0d1117", fg="#00ff00")
        self.status.pack(fill=tk.X)

        self.start_btn = ttk.Button(root, text="Start", command=self.start_sniff)
        self.start_btn.pack(side=tk.LEFT, padx=5, pady=5)
        self.stop_btn = ttk.Button(root, text="Stop", command=self.stop_sniff)
        self.stop_btn.pack(side=tk.LEFT, padx=5, pady=5)
        self.clear_btn = ttk.Button(root, text="Clear", command=lambda: self.text_area.delete(1.0, tk.END))
        self.clear_btn.pack(side=tk.LEFT, padx=5, pady=5)

        self.sniffer = None
        self.analyzer = PacketAnalyzer(AlertManager(self.update_gui), AnomalyDetector())

    def update_gui(self, alert):
        msg = f"[{alert['time']}] [{alert['level']}] {alert['title']}: {alert['msg']}\n"
        self.text_area.insert(tk.END, msg)
        self.text_area.see(tk.END)

    def start_sniff(self):
        if not self.sniffer:
            self.status.config(text="Status: Running", fg="yellow")
            self.sniffer = AsyncSniffer(prn=self.analyzer.analyze, store=False)
            self.sniffer.start()

    def stop_sniff(self):
        if self.sniffer:
            self.sniffer.stop()
            self.sniffer = None
            self.status.config(text="Status: Stopped", fg="#00ff00")

# ---------------- MAIN ---------------- #
if __name__ == '__main__':
    root = tk.Tk()
    app = AIDS_GUI(root)
    root.mainloop()
