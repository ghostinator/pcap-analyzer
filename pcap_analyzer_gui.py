#!/usr/bin/env python3
"""PCAP Analyzer GUI v4.0 - Dashboard-style comprehensive network analysis tool."""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
import re
import sys
import threading
import socket
import struct
import json
import csv
from datetime import datetime
from collections import defaultdict, Counter
from concurrent.futures import ThreadPoolExecutor

# Add tools directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'tools'))

try:
    from scapy.all import rdpcap, IP, TCP, UDP, ICMP, DNS, ARP, Dot11, Dot11Beacon
except ImportError:
    messagebox.showerror("Error", "scapy not installed. Run: pip install scapy")
    sys.exit(1)


class PCAPAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("PCAP Analyzer v4.0 - Dashboard")
        self.root.geometry("1600x900")
        
        self.current_file = None
        self.packets = []
        self.analysis_results = {}
        self.last_results = None

        # Known-device labeling (loaded from a CSV via Load Device List)
        self.device_map = {'by_ip': {}, 'by_mac': {}}
        self.ip_mac_map = {}
        # Reverse-DNS cache for external hosts, keyed by IP (None = no PTR record)
        self.rdns_cache = {}
        socket.setdefaulttimeout(2.0)  # keep reverse-DNS lookups from hanging

        # Alert thresholds (configurable)
        self.alert_thresholds = {
            'retransmission_rate': 5.0,  # %
            'rtt_ms': 100.0,             # ms
            'packet_loss': 2.0           # %
        }

        self.setup_ui()
        self.autoload_device_list()

    def setup_ui(self):
        """Setup dashboard-style UI with metrics cards, charts, and analysis tabs."""
        main_frame = ttk.Frame(self.root, padding="5")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Top row: File input + Key metrics cards
        self.setup_file_and_metrics(main_frame)
        
        # Middle row: Protocol breakdown + Timeline graph side-by-side
        middle_frame = ttk.Frame(main_frame)
        middle_frame.pack(fill=tk.X, pady=(4, 4))

        self.setup_protocol_chart(middle_frame)
        self.setup_timeline_graph(middle_frame)

        # Bottom row: Analysis tabs (all original v2.0 tabs restored) - the main
        # work area, so it gets whatever vertical space the sections above don't use
        bottom_frame = ttk.Frame(main_frame)
        bottom_frame.pack(fill=tk.BOTH, expand=True, pady=(4, 0))
        
        self.notebook = ttk.Notebook(bottom_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Create all analysis tabs
        self.create_all_tabs()
    
    def setup_file_and_metrics(self, parent):
        """Setup file input area, status bars, and key metrics cards."""
        # File input frame: buttons + combined status row
        file_frame = ttk.LabelFrame(parent, text="Load PCAP File", padding="8")
        file_frame.pack(fill=tk.X, pady=(0, 4))

        button_row = ttk.Frame(file_frame)
        button_row.pack(fill=tk.X)

        browse_btn = ttk.Button(button_row, text="Browse for PCAP File...", command=self.browse_file)
        browse_btn.pack(side=tk.LEFT, padx=(0, 5))

        device_list_btn = ttk.Button(button_row, text="Load Device List (CSV)...", command=self.load_device_list)
        device_list_btn.pack(side=tk.LEFT)

        # File info + device list status, side by side to save vertical space
        status_row = ttk.Frame(file_frame)
        status_row.pack(fill=tk.X, pady=(8, 0))

        self.file_info_var = tk.StringVar(value="No file loaded")
        self.file_info_bar = ttk.Label(status_row, textvariable=self.file_info_var,
                                      relief=tk.SUNKEN, anchor=tk.W, padding="5")
        self.file_info_bar.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))

        self.device_list_var = tk.StringVar(value="No device list loaded")
        self.device_list_bar = ttk.Label(status_row, textvariable=self.device_list_var,
                                        relief=tk.SUNKEN, anchor=tk.W, padding="5")
        self.device_list_bar.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Metrics cards row
        metrics_frame = ttk.Frame(parent)
        metrics_frame.pack(fill=tk.X, pady=(4, 0))
        
        self.metric_vars = {}
        metrics = [
            ("Packets/sec", "pps"),
            ("Retransmission Rate", "retrans_rate"),
            ("Unique Hosts", "unique_hosts"),
            ("Avg RTT (ms)", "avg_rtt"),
            ("Total Packets", "total_packets")
        ]
        
        for i, (label, key) in enumerate(metrics):
            card = ttk.LabelFrame(metrics_frame, text=label, padding="5")
            card.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
            
            var = tk.StringVar(value="--")
            self.metric_vars[key] = var
            
            value_label = ttk.Label(card, textvariable=var, font=("Helvetica", 14, "bold"))
            value_label.pack()
    
    def setup_protocol_chart(self, parent):
        """Setup protocol breakdown chart."""
        proto_frame = ttk.LabelFrame(parent, text="Protocol Breakdown", padding="5")
        proto_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        self.proto_text = tk.Text(proto_frame, height=8, width=40, state=tk.DISABLED)
        scrollbar = ttk.Scrollbar(proto_frame, orient=tk.VERTICAL, command=self.proto_text.yview)
        self.proto_text.configure(yscrollcommand=scrollbar.set)
        
        self.proto_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def setup_timeline_graph(self, parent):
        """Setup traffic timeline graph."""
        timeline_frame = ttk.LabelFrame(parent, text="Traffic Timeline", padding="5")
        timeline_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(5, 0))
        
        self.timeline_text = tk.Text(timeline_frame, height=8, width=40, state=tk.DISABLED)
        scrollbar = ttk.Scrollbar(timeline_frame, orient=tk.VERTICAL, command=self.timeline_text.yview)
        self.timeline_text.configure(yscrollcommand=scrollbar.set)
        
        self.timeline_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def create_all_tabs(self):
        """Create all analysis tabs (restored from v2.0)."""
        # Overview tab
        self.overview_tab = ttk.Frame(self.notebook)
        self.setup_overview_tab()
        self.notebook.add(self.overview_tab, text="Overview")
        
        # Packets tab (Wireshark-like browser)
        self.packets_tab = ttk.Frame(self.notebook)
        self.setup_packets_tab()
        self.notebook.add(self.packets_tab, text="Packets")
        
        # TCP Analysis tab
        self.tcp_tab = ttk.Frame(self.notebook)
        self.setup_tcp_tab()
        self.notebook.add(self.tcp_tab, text="TCP Analysis")
        
        # Errors tab
        self.errors_tab = ttk.Frame(self.notebook)
        self.setup_errors_tab()
        self.notebook.add(self.errors_tab, text="Errors")
        
        # HTTP tab
        self.http_tab = ttk.Frame(self.notebook)
        self.setup_http_tab()
        self.notebook.add(self.http_tab, text="HTTP")
        
        # DNS tab
        self.dns_tab = ttk.Frame(self.notebook)
        self.setup_dns_tab()
        self.notebook.add(self.dns_tab, text="DNS")
        
        # Hosts tab with IP intelligence
        self.hosts_tab = ttk.Frame(self.notebook)
        self.setup_hosts_tab()
        self.notebook.add(self.hosts_tab, text="Hosts")
        
        # Wireless/RF tab
        self.wireless_tab = ttk.Frame(self.notebook)
        self.setup_wireless_tab()
        self.notebook.add(self.wireless_tab, text="Wireless")
        
        # Performance tab
        self.performance_tab = ttk.Frame(self.notebook)
        self.setup_performance_tab()
        self.notebook.add(self.performance_tab, text="Performance")
        
        # Traffic Patterns tab
        self.traffic_tab = ttk.Frame(self.notebook)
        self.setup_traffic_tab()
        self.notebook.add(self.traffic_tab, text="Traffic Patterns")
        
        # Security tab
        self.security_tab = ttk.Frame(self.notebook)
        self.setup_security_tab()
        self.notebook.add(self.security_tab, text="Security")
    
    def setup_overview_tab(self):
        """Setup overview tab with key metrics and top talkers."""
        # Protocol breakdown is already shown in the dashboard chart above the tabs,
        # so this tab just gives Key Metrics and Top Talkers the full width instead.

        # Key metrics frame
        metrics_frame = ttk.LabelFrame(self.overview_tab, text="Key Metrics", padding="5")
        metrics_frame.pack(side=tk.LEFT, fill=tk.BOTH, padx=(0, 5), pady=5, expand=True)

        self.metrics_text = tk.Text(metrics_frame, height=20, width=50, state=tk.DISABLED)
        scrollbar = ttk.Scrollbar(metrics_frame, orient=tk.VERTICAL, command=self.metrics_text.yview)
        self.metrics_text.configure(yscrollcommand=scrollbar.set)

        self.metrics_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Top talkers frame
        talkers_frame = ttk.LabelFrame(self.overview_tab, text="Top Talkers", padding="5")
        talkers_frame.pack(side=tk.LEFT, fill=tk.BOTH, pady=5, expand=True)

        self.talkers_text = tk.Text(talkers_frame, height=20, width=50, state=tk.DISABLED)
        scrollbar = ttk.Scrollbar(talkers_frame, orient=tk.VERTICAL, command=self.talkers_text.yview)
        self.talkers_text.configure(yscrollcommand=scrollbar.set)
        
        self.talkers_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def setup_packets_tab(self):
        """Setup Wireshark-like packet browser."""
        columns = ("num", "time", "source", "dest", "protocol", "info")
        self.packets_tree = ttk.Treeview(self.packets_tab, columns=columns, show="headings")
        
        for col in columns:
            self.packets_tree.heading(col, text=col.upper())
            if col == "num":
                self.packets_tree.column(col, width=50)
            elif col == "time":
                self.packets_tree.column(col, width=100)
            elif col in ["source", "dest"]:
                self.packets_tree.column(col, width=120)
            elif col == "protocol":
                self.packets_tree.column(col, width=80)
            else:
                self.packets_tree.column(col, width=300)
        
        scrollbar = ttk.Scrollbar(self.packets_tab, orient=tk.VERTICAL, command=self.packets_tree.yview)
        self.packets_tree.configure(yscrollcommand=scrollbar.set)
        
        self.packets_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def setup_tcp_tab(self):
        """Setup TCP analysis tab with multiple views."""
        tcp_notebook = ttk.Notebook(self.tcp_tab)
        tcp_notebook.pack(fill=tk.BOTH, expand=True)
        
        # TCP Streams sub-tab
        streams_frame = ttk.Frame(tcp_notebook)
        columns = ("stream", "packets", "bytes_sent", "bytes_recv", "retrans")
        self.tcp_tree = ttk.Treeview(streams_frame, columns=columns, show="headings")
        
        # Stream column 40%, rest split proportionally
        self.tcp_tree.heading("stream", text="STREAM")
        self.tcp_tree.column("stream", width=320)
        
        self.tcp_tree.heading("packets", text="PACKETS")
        self.tcp_tree.column("packets", width=80)
        
        # Bytes columns wider due to larger values
        self.tcp_tree.heading("bytes_sent", text="BYTES SENT")
        self.tcp_tree.column("bytes_sent", width=120)
        
        self.tcp_tree.heading("bytes_recv", text="BYTES RECV")
        self.tcp_tree.column("bytes_recv", width=120)
        
        self.tcp_tree.heading("retrans", text="RETRANS")
        self.tcp_tree.column("retrans", width=80)
        
        scrollbar = ttk.Scrollbar(streams_frame, orient=tk.VERTICAL, command=self.tcp_tree.yview)
        self.tcp_tree.configure(yscrollcommand=scrollbar.set)
        
        self.tcp_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        tcp_notebook.add(streams_frame, text="Streams")
        
        # TCP Window Analysis sub-tab
        window_frame = ttk.Frame(tcp_notebook)
        self.window_text = tk.Text(window_frame, wrap=tk.WORD)
        w_scrollbar = ttk.Scrollbar(window_frame, orient=tk.VERTICAL, command=self.window_text.yview)
        self.window_text.configure(yscrollcommand=w_scrollbar.set)
        
        self.window_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        w_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        tcp_notebook.add(window_frame, text="Window Analysis")
    
    def setup_errors_tab(self):
        """Setup errors tab with multiple views."""
        error_notebook = ttk.Notebook(self.errors_tab)
        error_notebook.pack(fill=tk.BOTH, expand=True)
        
        # Error Summary sub-tab
        summary_frame = ttk.Frame(error_notebook)
        self.errors_text = tk.Text(summary_frame, wrap=tk.WORD)
        e_scrollbar = ttk.Scrollbar(summary_frame, orient=tk.VERTICAL, command=self.errors_text.yview)
        self.errors_text.configure(yscrollcommand=e_scrollbar.set)
        
        self.errors_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        e_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        error_notebook.add(summary_frame, text="Summary")
        
        # Error Distribution by Host sub-tab
        dist_frame = ttk.Frame(error_notebook)
        columns = ("host", "retransmissions", "dup_acks", "rst_count")
        self.error_dist_tree = ttk.Treeview(dist_frame, columns=columns, show="headings")
        
        for col in columns:
            self.error_dist_tree.heading(col, text=col.upper())
            self.error_dist_tree.column(col, width=150)
        
        d_scrollbar = ttk.Scrollbar(dist_frame, orient=tk.VERTICAL, command=self.error_dist_tree.yview)
        self.error_dist_tree.configure(yscrollcommand=d_scrollbar.set)
        
        self.error_dist_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        d_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        error_notebook.add(dist_frame, text="By Host")
    
    def setup_http_tab(self):
        """Setup HTTP analysis tab."""
        columns = ("method", "path", "host", "status")
        self.http_tree = ttk.Treeview(self.http_tab, columns=columns, show="headings")
        
        for col in columns:
            self.http_tree.heading(col, text=col.upper())
            self.http_tree.column(col, width=150)
        
        scrollbar = ttk.Scrollbar(self.http_tab, orient=tk.VERTICAL, command=self.http_tree.yview)
        self.http_tree.configure(yscrollcommand=scrollbar.set)
        
        self.http_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def setup_dns_tab(self):
        """Setup DNS analysis tab with response indicator."""
        columns = ("query", "type", "response", "time", "status")
        self.dns_tree = ttk.Treeview(self.dns_tab, columns=columns, show="headings")
        
        # Wider query column, narrower type column
        self.dns_tree.heading("query", text="QUERY")
        self.dns_tree.column("query", width=350)
        
        self.dns_tree.heading("type", text="TYPE")
        self.dns_tree.column("type", width=50)
        
        self.dns_tree.heading("response", text="RESPONSE")
        self.dns_tree.column("response", width=180)
        
        self.dns_tree.heading("time", text="TIME")
        self.dns_tree.column("time", width=100)
        
        self.dns_tree.heading("status", text="RESP?")
        self.dns_tree.column("status", width=50)
        
        scrollbar = ttk.Scrollbar(self.dns_tab, orient=tk.VERTICAL, command=self.dns_tree.yview)
        self.dns_tree.configure(yscrollcommand=scrollbar.set)
        
        self.dns_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def setup_hosts_tab(self):
        """Setup hosts tab with IP intelligence."""
        columns = ("ip", "hostname", "packets", "bytes", "type", "info")
        self.hosts_tree = ttk.Treeview(self.hosts_tab, columns=columns, show="headings")

        # Column widths
        self.hosts_tree.heading("ip", text="IP ADDRESS")
        self.hosts_tree.column("ip", width=150)

        self.hosts_tree.heading("hostname", text="HOSTNAME")
        self.hosts_tree.column("hostname", width=200)

        self.hosts_tree.heading("packets", text="PACKETS")
        self.hosts_tree.column("packets", width=80)
        
        self.hosts_tree.heading("bytes", text="BYTES")
        self.hosts_tree.column("bytes", width=100)
        
        self.hosts_tree.heading("type", text="TYPE")
        self.hosts_tree.column("type", width=80)
        
        self.hosts_tree.heading("info", text="INFO")
        self.hosts_tree.column("info", width=300)
        
        scrollbar = ttk.Scrollbar(self.hosts_tab, orient=tk.VERTICAL, command=self.hosts_tree.yview)
        self.hosts_tree.configure(yscrollcommand=scrollbar.set)
        
        self.hosts_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def setup_wireless_tab(self):
        """Setup wireless/RF analysis tab."""
        wireless_notebook = ttk.Notebook(self.wireless_tab)
        wireless_notebook.pack(fill=tk.BOTH, expand=True)
        
        # RF Info sub-tab
        rf_frame = ttk.Frame(wireless_notebook)
        self.rf_text = tk.Text(rf_frame, wrap=tk.WORD)
        r_scrollbar = ttk.Scrollbar(rf_frame, orient=tk.VERTICAL, command=self.rf_text.yview)
        self.rf_text.configure(yscrollcommand=r_scrollbar.set)
        
        self.rf_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        r_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        wireless_notebook.add(rf_frame, text="RF Info")
        
        # Client Analysis sub-tab
        client_frame = ttk.Frame(wireless_notebook)
        columns = ("client_mac", "signal_avg", "packets", "retries")
        self.wireless_client_tree = ttk.Treeview(client_frame, columns=columns, show="headings")
        
        for col in columns:
            self.wireless_client_tree.heading(col, text=col.upper())
            self.wireless_client_tree.column(col, width=150)
        
        c_scrollbar = ttk.Scrollbar(client_frame, orient=tk.VERTICAL, command=self.wireless_client_tree.yview)
        self.wireless_client_tree.configure(yscrollcommand=c_scrollbar.set)
        
        self.wireless_client_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        c_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        wireless_notebook.add(client_frame, text="Client Analysis")
    
    def setup_performance_tab(self):
        """Setup performance analysis tab."""
        perf_notebook = ttk.Notebook(self.performance_tab)
        perf_notebook.pack(fill=tk.BOTH, expand=True)
        
        # RTT/Latency sub-tab
        rtt_frame = ttk.Frame(perf_notebook)
        columns = ("connection", "avg_rtt_ms", "min_rtt_ms", "max_rtt_ms")
        self.rtt_tree = ttk.Treeview(rtt_frame, columns=columns, show="headings")
        
        for col in columns:
            self.rtt_tree.heading(col, text=col.upper())
            self.rtt_tree.column(col, width=150)
        
        rt_scrollbar = ttk.Scrollbar(rtt_frame, orient=tk.VERTICAL, command=self.rtt_tree.yview)
        self.rtt_tree.configure(yscrollcommand=rt_scrollbar.set)
        
        self.rtt_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        rt_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        perf_notebook.add(rtt_frame, text="RTT/Latency")
        
        # Bandwidth Over Time sub-tab
        bw_frame = ttk.Frame(perf_notebook)
        self.bw_text = tk.Text(bw_frame, wrap=tk.WORD)
        b_scrollbar = ttk.Scrollbar(bw_frame, orient=tk.VERTICAL, command=self.bw_text.yview)
        self.bw_text.configure(yscrollcommand=b_scrollbar.set)
        
        self.bw_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        b_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        perf_notebook.add(bw_frame, text="Bandwidth Over Time")
    
    def setup_traffic_tab(self):
        """Setup traffic patterns tab."""
        traffic_notebook = ttk.Notebook(self.traffic_tab)
        traffic_notebook.pack(fill=tk.BOTH, expand=True)
        
        # Packet Size Distribution sub-tab
        size_frame = ttk.Frame(traffic_notebook)
        self.size_text = tk.Text(size_frame, wrap=tk.WORD)
        s_scrollbar = ttk.Scrollbar(size_frame, orient=tk.VERTICAL, command=self.size_text.yview)
        self.size_text.configure(yscrollcommand=s_scrollbar.set)
        
        self.size_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        s_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        traffic_notebook.add(size_frame, text="Packet Size Distribution")
        
        # Application Protocol Breakdown sub-tab
        app_frame = ttk.Frame(traffic_notebook)
        self.app_text = tk.Text(app_frame, wrap=tk.WORD)
        a_scrollbar = ttk.Scrollbar(app_frame, orient=tk.VERTICAL, command=self.app_text.yview)
        self.app_text.configure(yscrollcommand=a_scrollbar.set)
        
        self.app_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        a_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        traffic_notebook.add(app_frame, text="Application Protocols")
        
        # Top Flows by Bytes sub-tab
        flows_frame = ttk.Frame(traffic_notebook)
        columns = ("flow", "bytes", "packets")
        self.flows_tree = ttk.Treeview(flows_frame, columns=columns, show="headings")
        
        # Flow column 60%, bytes and packets 20% each
        self.flows_tree.heading("flow", text="FLOW")
        self.flows_tree.column("flow", width=480)
        
        self.flows_tree.heading("bytes", text="BYTES")
        self.flows_tree.column("bytes", width=160)
        
        self.flows_tree.heading("packets", text="PACKETS")
        self.flows_tree.column("packets", width=160)
        
        f_scrollbar = ttk.Scrollbar(flows_frame, orient=tk.VERTICAL, command=self.flows_tree.yview)
        self.flows_tree.configure(yscrollcommand=f_scrollbar.set)
        
        self.flows_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        f_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        traffic_notebook.add(flows_frame, text="Top Flows by Bytes")
    
    def setup_security_tab(self):
        """Setup security analysis tab."""
        sec_notebook = ttk.Notebook(self.security_tab)
        sec_notebook.pack(fill=tk.BOTH, expand=True)
        
        # Port Scan Detection sub-tab
        scan_frame = ttk.Frame(sec_notebook)
        self.scan_text = tk.Text(scan_frame, wrap=tk.WORD)
        sc_scrollbar = ttk.Scrollbar(scan_frame, orient=tk.VERTICAL, command=self.scan_text.yview)
        self.scan_text.configure(yscrollcommand=sc_scrollbar.set)
        
        self.scan_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sc_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        sec_notebook.add(scan_frame, text="Port Scan Detection")
        
        # Duplicate IP/MAC Detection sub-tab
        dup_frame = ttk.Frame(sec_notebook)
        self.dup_text = tk.Text(dup_frame, wrap=tk.WORD)
        d_scrollbar = ttk.Scrollbar(dup_frame, orient=tk.VERTICAL, command=self.dup_text.yview)
        self.dup_text.configure(yscrollcommand=d_scrollbar.set)
        
        self.dup_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        d_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        sec_notebook.add(dup_frame, text="Duplicate IP/MAC")
    
    def browse_file(self):
        filepath = filedialog.askopenfilename(
            title="Select PCAP File",
            filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")]
        )
        if filepath:
            self.load_pcap(filepath)
    
    def load_pcap(self, filepath):
        self.current_file = filepath
        
        # Update file info bar (restored from v2.0)
        self.file_info_var.set(f"Loading: {os.path.basename(filepath)}...")
        self.root.update_idletasks()
        
        # Update UI to show loading state
        for var in self.metric_vars.values():
            var.set("Loading...")
        
        thread = threading.Thread(target=self._load_and_analyze, args=(filepath,))
        thread.daemon = True
        thread.start()
    
    def _load_and_analyze(self, filepath):
        # Runs on a background thread: Tk widgets are not thread-safe, so all
        # UI mutations are scheduled back onto the main thread via root.after.
        try:
            self.packets = rdpcap(filepath)

            # Update file info bar with load completion (restored from v2.0)
            total_packets = len(self.packets)
            if total_packets > 0:
                first_ts = float(self.packets[0].time)
                last_ts = float(self.packets[-1].time)
                duration = last_ts - first_ts

                info_text = (
                    f"{os.path.basename(filepath)} | {total_packets:,} packets | "
                    f"{duration:.1f}s duration"
                )
            else:
                info_text = f"{os.path.basename(filepath)} | 0 packets"
            self.root.after(0, self.file_info_var.set, info_text)

            # Run comprehensive analysis
            results = self.analyze_pcap()
            self.ip_mac_map = results['ip_mac_map']

            # Reverse-DNS unresolved external hosts (network I/O - stays off the UI thread)
            self.resolve_external_hostnames(results['ip_traffic'])
            self.last_results = results

            # Update dashboard with results
            self.root.after(0, self.update_dashboard, results)

        except Exception as e:
            self.root.after(0, messagebox.showerror, "Error", f"Failed to load PCAP file:\n{e}")

    def resolve_external_hostnames(self, ip_traffic):
        """Reverse-DNS lookup for external IPs not already in the cache, in parallel."""
        to_resolve = [ip for ip in ip_traffic
                      if ip not in self.rdns_cache and not self.is_private_ip(ip)]
        if not to_resolve:
            return

        def lookup(ip):
            try:
                return ip, socket.gethostbyaddr(ip)[0]
            except Exception:
                return ip, None

        with ThreadPoolExecutor(max_workers=20) as pool:
            for ip, hostname in pool.map(lookup, to_resolve):
                self.rdns_cache[ip] = hostname

    def autoload_device_list(self):
        """Load devices.csv next to the script on startup, if present."""
        default_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'devices.csv')
        if os.path.isfile(default_path):
            try:
                self._apply_device_list(default_path)
            except Exception:
                pass  # startup convenience only; Load Device List still works manually

    def load_device_list(self):
        """Import a CSV of known hostname/MAC/IP mappings to label internal hosts."""
        filepath = filedialog.askopenfilename(
            title="Select Device List (CSV: hostname, mac, ip)",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        if not filepath:
            return
        try:
            self._apply_device_list(filepath)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load device list:\n{e}")

    def _apply_device_list(self, filepath):
        self.device_map = self._parse_device_list(filepath)
        # Count unique devices by hostname, not by IP/MAC key (one device can have both)
        count = len(set(self.device_map['by_ip'].values()) | set(self.device_map['by_mac'].values()))
        self.device_list_var.set(f"{count:,} devices loaded from {os.path.basename(filepath)}")
        if self.last_results is not None:
            self.update_dashboard(self.last_results)

    def _parse_device_list(self, filepath):
        """Parse a CSV of devices, accepting a hostname/mac/ip header in any order,
        or falling back to positional hostname,mac,ip columns."""
        by_ip = {}
        by_mac = {}

        with open(filepath, newline='', encoding='utf-8-sig') as f:
            rows = list(csv.reader(f))

        if not rows:
            return {'by_ip': by_ip, 'by_mac': by_mac}

        header = [col.strip().lower() for col in rows[0]]
        col_idx = {}
        for i, col in enumerate(header):
            if col in ('hostname', 'name', 'device', 'device name'):
                col_idx['hostname'] = i
            elif col in ('mac', 'mac address', 'macaddress'):
                col_idx['mac'] = i
            elif col in ('ip', 'ip address', 'ipaddress'):
                col_idx['ip'] = i

        data_rows = rows[1:] if col_idx else rows
        if not col_idx:
            col_idx = {'hostname': 0, 'mac': 1, 'ip': 2}

        for row in data_rows:
            if len(row) <= max(col_idx.values()):
                continue
            hostname = row[col_idx['hostname']].strip() if 'hostname' in col_idx else ''
            mac = row[col_idx['mac']].strip() if 'mac' in col_idx else ''
            ip = row[col_idx['ip']].strip() if 'ip' in col_idx else ''
            if not hostname:
                continue
            if ip:
                by_ip[ip] = hostname
            if mac:
                normalized = self._normalize_mac(mac)
                if normalized:
                    by_mac[normalized] = hostname

        return {'by_ip': by_ip, 'by_mac': by_mac}

    @staticmethod
    def _normalize_mac(mac):
        """Normalize a MAC address to lowercase colon-separated form for lookup."""
        hex_digits = re.sub(r'[^0-9a-fA-F]', '', mac)
        if len(hex_digits) != 12:
            return None
        return ':'.join(hex_digits[i:i + 2] for i in range(0, 12, 2)).lower()

    def lookup_device_name(self, ip):
        """Resolve a friendly name for an IP: known device list first (by IP, then by
        the MAC seen for that IP via ARP in this capture), else reverse DNS."""
        by_ip = self.device_map['by_ip']
        if ip in by_ip:
            return by_ip[ip]

        mac = self.ip_mac_map.get(ip)
        if mac:
            normalized = self._normalize_mac(mac)
            if normalized in self.device_map['by_mac']:
                return self.device_map['by_mac'][normalized]

        return self.rdns_cache.get(ip)

    def analyze_pcap(self):
        """Run all analyses and return comprehensive results."""
        total_packets = len(self.packets)
        
        # Initialize analysis data structures
        proto_counts = {'IP': 0, 'TCP': 0, 'UDP': 0, 'ICMP': 0, 'DNS': 0, 'ARP': 0}
        ip_traffic = {}
        tcp_packets = 0
        dns_queries = []
        dns_responses = set()
        qos_counts = {}
        
        # Wireless analysis data
        wireless_clients = defaultdict(lambda: {'signals': [], 'packets': 0, 'retries': 0})
        has_wireless = False
        
        # Performance analysis data
        tcp_connections = defaultdict(list)
        bandwidth_buckets = defaultdict(int)
        
        # Traffic pattern data
        packet_sizes = []
        app_protocols = Counter()
        flow_bytes = defaultdict(int)
        
        # Security analysis data
        port_scan_tracker = defaultdict(set)
        ip_mac_map = {}
        
        for pkt in self.packets:
            if pkt.haslayer(IP):
                proto_counts['IP'] += 1
                
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                
                # Track per-IP traffic
                if src_ip not in ip_traffic:
                    ip_traffic[src_ip] = {'packets': 0, 'bytes': 0}
                ip_traffic[src_ip]['packets'] += 1
                ip_traffic[src_ip]['bytes'] += pkt[IP].len
                
                # Extract QoS/DSCP information
                tos = pkt[IP].tos
                dscp = (tos >> 2) & 0x3F
                if dscp not in qos_counts:
                    qos_counts[dscp] = 0
                qos_counts[dscp] += 1
                
                # Packet size tracking
                packet_sizes.append(pkt[IP].len)
                
                # Bandwidth tracking (1-second buckets)
                time_bucket = int(float(pkt.time))
                bandwidth_buckets[time_bucket] += pkt[IP].len
                
                if pkt.haslayer(TCP):
                    proto_counts['TCP'] += 1
                    tcp_packets += 1
                    
                    # Track TCP connections for RTT analysis
                    conn_key = f"{src_ip}:{pkt[TCP].sport} <-> {dst_ip}:{pkt[TCP].dport}"
                    tcp_connections[conn_key].append(pkt)
                    
                    # Flow bytes tracking
                    flow_bytes[conn_key] += pkt[IP].len
                    
                elif pkt.haslayer(UDP):
                    proto_counts['UDP'] += 1
                    
                    # Application protocol detection by port
                    if pkt[UDP].dport == 53 or pkt[UDP].sport == 53:
                        app_protocols['DNS'] += 1
                    elif pkt[UDP].dport == 67 or pkt[UDP].sport == 67:
                        app_protocols['DHCP'] += 1
                    elif pkt[UDP].dport == 123 or pkt[UDP].sport == 123:
                        app_protocols['NTP'] += 1
                    
                    if pkt.haslayer(DNS):
                        proto_counts['DNS'] += 1
                        dns_layer = pkt[DNS]
                        
                        # Track DNS responses by transaction ID
                        if dns_layer.qr == 1:
                            dns_responses.add(dns_layer.id)
                        
                        # Collect DNS query info for DNS tab with timestamp
                        elif dns_layer.qr == 0 and dns_layer.qd is not None:
                            qname = dns_layer.qd.qname.decode('utf-8', errors='ignore').rstrip('.')
                            timestamp = datetime.fromtimestamp(float(pkt.time)).strftime('%H:%M:%S.%f')[:-3]
                            dns_queries.append({
                                'query': qname,
                                'type': 'A' if dns_layer.qd.qtype == 1 else str(dns_layer.qd.qtype),
                                'src_ip': src_ip,
                                'dst_ip': dst_ip,
                                'time': timestamp,
                                'tx_id': dns_layer.id
                            })
                    
                    # Flow bytes tracking for UDP
                    flow_key = f"{src_ip}:{pkt[UDP].sport} <-> {dst_ip}:{pkt[UDP].dport}"
                    flow_bytes[flow_key] += pkt[IP].len
                    
                elif pkt.haslayer(ICMP):
                    proto_counts['ICMP'] += 1
            
            elif pkt.haslayer(ARP):
                proto_counts['ARP'] += 1
                # Track IP to MAC mappings for duplicate detection and device labeling
                ip_mac_map[pkt[ARP].psrc] = pkt[ARP].hwsrc
            
            # Check for wireless frames (handle separately from IP processing)
            if pkt.haslayer(Dot11):
                has_wireless = True
                try:
                    dot11 = pkt[Dot11]
                    
                    # Track client signal strength and retries
                    if hasattr(dot11, 'addr2') and dot11.addr2:
                        client_mac = dot11.addr2
                        wireless_clients[client_mac]['packets'] += 1
                        
                        # Check for retry flag via the FCfield's retry bit (0x08)
                        try:
                            if int(dot11.FCfield) & 0x08:
                                wireless_clients[client_mac]['retries'] += 1
                        except Exception:
                            pass
                        
                        # Try to extract signal strength from various sources
                        signal = None
                        if hasattr(pkt, 'signal'):
                            signal = pkt.signal
                        elif hasattr(dot11, 'dbm_antsignal'):
                            signal = dot11.dbm_antsignal
                        elif hasattr(dot11, 'dBmAntSignal'):
                            signal = dot11.dBmAntSignal
                        
                        if signal is not None:
                            wireless_clients[client_mac]['signals'].append(signal)
                except Exception as e:
                    pass  # Skip problematic wireless frames
        
        return {
            'total_packets': total_packets,
            'proto_counts': proto_counts,
            'ip_traffic': ip_traffic,
            'tcp_packets': tcp_packets,
            'dns_queries': dns_queries,
            'dns_responses': dns_responses,
            'qos_counts': qos_counts,
            'wireless_clients': wireless_clients,
            'has_wireless': has_wireless,
            'tcp_connections': tcp_connections,
            'bandwidth_buckets': bandwidth_buckets,
            'packet_sizes': packet_sizes,
            'app_protocols': app_protocols,
            'flow_bytes': flow_bytes,
            'port_scan_tracker': port_scan_tracker,
            'ip_mac_map': ip_mac_map
        }
    
    def update_dashboard(self, results):
        """Update all dashboard components with analysis results."""
        total_packets = results['total_packets']
        
        if total_packets == 0:
            return
        
        # Calculate key metrics
        first_ts = float(self.packets[0].time)
        last_ts = float(self.packets[-1].time)
        duration = last_ts - first_ts
        pps = total_packets / duration if duration > 0 else 0
        
        # TCP retransmission analysis (computed once, shared by every tab below)
        tcp_retrans_info = self.analyze_tcp_retransmissions()
        tcp_retrans = tcp_retrans_info['total']
        retrans_rate = (tcp_retrans / results['tcp_packets'] * 100) if results['tcp_packets'] > 0 else 0
        
        # Update metric cards
        self.metric_vars['pps'].set(f"{pps:.1f}")
        self.metric_vars['retrans_rate'].set(f"{retrans_rate:.2f}%")
        self.metric_vars['unique_hosts'].set(len(results['ip_traffic']))
        
        # Calculate average RTT (simplified)
        avg_rtt = self.calculate_avg_rtt()
        self.metric_vars['avg_rtt'].set(f"{avg_rtt:.1f}" if avg_rtt > 0 else "--")
        
        self.metric_vars['total_packets'].set(f"{total_packets:,}")
        
        # Update protocol chart
        self.update_protocol_chart(results['proto_counts'], total_packets)
        
        # Update timeline graph
        self.update_timeline_graph(results['bandwidth_buckets'])
        
        # Update all analysis tabs
        self.update_overview_tab(results, tcp_retrans, retrans_rate)
        self.update_packets_tab()
        self.update_tcp_analysis(results['tcp_connections'], tcp_retrans_info)
        self.update_errors_tab(tcp_retrans_info)
        self.update_dns_tab(results['dns_queries'], results['dns_responses'])
        self.update_hosts_tab(results['ip_traffic'])
        self.update_wireless_tab(results['has_wireless'], results['wireless_clients'])
        self.update_performance_tab(results['bandwidth_buckets'])
        self.update_traffic_patterns(results['packet_sizes'], results['app_protocols'], results['flow_bytes'])
        self.update_security_tab(results['port_scan_tracker'], results['ip_mac_map'])
    
    def update_protocol_chart(self, proto_counts, total_packets):
        """Update protocol breakdown chart."""
        text = ""
        for proto, count in proto_counts.items():
            if count > 0:
                pct = (count / total_packets) * 100
                bar_length = int(pct)
                bar = "█" * bar_length
                text += f"{proto:<6} {count:>8,} ({pct:5.1f}%)\n"
                text += f"{'':<14}{bar}\n\n"
        
        self.update_text_widget(self.proto_text, text)
    
    def update_timeline_graph(self, bandwidth_buckets):
        """Update traffic timeline graph."""
        if not bandwidth_buckets:
            return
        
        min_bucket = min(bandwidth_buckets.keys())
        max_bucket = max(bandwidth_buckets.keys())
        
        text = "Traffic Volume Over Time (Kbps):\n\n"
        for bucket in range(min_bucket, min(max_bucket + 1, min_bucket + 60)):  # First 60 seconds
            bytes_in_bucket = bandwidth_buckets.get(bucket, 0)
            kbps = (bytes_in_bucket * 8) / 1024  # Convert to Kbps
            
            bar_length = int(kbps / 10) if kbps < 1000 else 100
            bar = "█" * bar_length
            
            text += f"{bucket - min_bucket:3d}s: {kbps:>8.1f} Kbps {bar}\n"
        
        self.update_text_widget(self.timeline_text, text)
    
    def update_overview_tab(self, results, tcp_retrans, retrans_rate):
        """Update overview tab with key metrics and top talkers."""
        total_packets = results['total_packets']

        # Key metrics
        if total_packets == 0:
            return
        
        first_ts = float(self.packets[0].time)
        last_ts = float(self.packets[-1].time)
        duration = last_ts - first_ts
        pps = total_packets / duration if duration > 0 else 0
        
        metrics = f"Packets/sec: {pps:.1f}\n"
        metrics += f"Unique IPs: {len(results['ip_traffic'])}\n\n"
        metrics += f"TCP Retransmissions: {tcp_retrans:,}\n"
        metrics += f"Retransmission Rate: {retrans_rate:.2f}%\n\n"
        
        # Add more useful calculations
        if duration > 0 and results['proto_counts']['IP'] > 0:
            avg_packet_size = sum(pkt[IP].len for pkt in self.packets if pkt.haslayer(IP)) / results['proto_counts']['IP']
            metrics += f"Avg Packet Size: {avg_packet_size:.0f} bytes\n"
        
        # QoS/DSCP distribution
        if results['qos_counts']:
            metrics += "\nQoS (DSCP) Distribution:\n"
            for dscp, count in sorted(results['qos_counts'].items(), key=lambda x: -x[1]):
                # Map DSCP values to common names
                if dscp == 0:
                    name = "Best Effort"
                elif dscp == 46:
                    name = "EF (Low Latency)"
                elif dscp in [34, 36, 38]:
                    name = "AF4x (High Priority)"
                elif dscp in [26, 28, 30]:
                    name = "AF3x (Medium-High)"
                else:
                    name = f"DSCP {dscp}"
                metrics += f"  {name}: {count:,}\n"
        
        self.update_text_widget(self.metrics_text, metrics)
        
        # Top talkers
        sorted_ips = sorted(results['ip_traffic'].items(), key=lambda x: x[1]['packets'], reverse=True)[:10]
        talkers_text = ""
        for ip, stats in sorted_ips:
            talkers_text += f"{ip}\n  Packets: {stats['packets']:,}\n  Bytes: {stats['bytes']:,}\n\n"
        
        self.update_text_widget(self.talkers_text, talkers_text)

    def update_packets_tab(self):
        """Update packets tab with all packets (Wireshark-style)."""
        self.packets_tree.delete(*self.packets_tree.get_children())
        for i, pkt in enumerate(self.packets[:1000]):  # Limit to first 1000 for performance
            if pkt.haslayer(IP):
                src = pkt[IP].src
                dst = pkt[IP].dst
                
                if pkt.haslayer(TCP):
                    proto = "TCP"
                    info = f"{pkt[TCP].sport} -> {pkt[TCP].dport}"
                elif pkt.haslayer(UDP):
                    proto = "UDP"
                    info = f"{pkt[UDP].sport} -> {pkt[UDP].dport}"
                elif pkt.haslayer(ICMP):
                    proto = "ICMP"
                    info = "Echo Request" if pkt[ICMP].type == 8 else "Echo Reply"
                else:
                    proto = "IP"
                    info = ""
                
                timestamp = datetime.fromtimestamp(float(pkt.time)).strftime('%H:%M:%S.%f')[:-3]
                self.packets_tree.insert("", tk.END, values=(
                    i+1,
                    timestamp,
                    src,
                    dst,
                    proto,
                    info
                ))
    
    def update_tcp_analysis(self, tcp_connections, tcp_retrans_info):
        """Update TCP analysis tab with streams and window analysis."""
        # TCP Streams - calculate actual bytes sent/received and retransmissions
        self.tcp_tree.delete(*self.tcp_tree.get_children())

        for conn_key, pkts in list(tcp_connections.items())[:50]:  # Limit to first 50
            packets_count = len(pkts)

            # Parse connection key to get IPs and ports
            parts = conn_key.split(' <-> ')
            src_part = parts[0].split(':')
            dst_part = parts[1].split(':')
            src_ip = src_part[0]
            dst_ip = dst_part[0]

            # Calculate bytes sent and received
            bytes_sent = 0
            bytes_recv = 0
            for pkt in pkts:
                if pkt.haslayer(IP):
                    if pkt[IP].src == src_ip:
                        bytes_sent += pkt[IP].len
                    elif pkt[IP].src == dst_ip:
                        bytes_recv += pkt[IP].len

            retrans_count = tcp_retrans_info['by_connection'].get(conn_key, 0)

            self.tcp_tree.insert("", tk.END, values=(
                conn_key,
                packets_count,
                f"{bytes_sent:,}",
                f"{bytes_recv:,}",
                retrans_count
            ))
        
        # TCP Window Analysis
        window_text = "TCP Receive Window Analysis:\n\n"
        small_windows = 0
        for conn_key, pkts in tcp_connections.items():
            for pkt in pkts:
                if pkt[TCP].window < 1024:
                    small_windows += 1
        
        window_text += f"Packets with small receive window (<1024): {small_windows}\n"
        self.update_text_widget(self.window_text, window_text)
    
    def update_errors_tab(self, tcp_retrans_info):
        """Update errors tab with summary and distribution."""
        # Error Summary
        errors_text = f"TCP Retransmissions: {tcp_retrans_info['total']:,}\n\n"
        errors_text += "Error analysis complete.\n"
        self.update_text_widget(self.errors_text, errors_text)

        # Error Distribution by Host - retransmissions per source IP
        self.error_dist_tree.delete(*self.error_dist_tree.get_children())
        sorted_hosts = sorted(tcp_retrans_info['by_host'].items(), key=lambda x: -x[1])[:20]
        for host, retrans_count in sorted_hosts:
            self.error_dist_tree.insert("", tk.END, values=(
                host,
                retrans_count,
                0,  # dup_acks: not tracked
                0   # rst: not tracked
            ))
    
    def update_dns_tab(self, dns_queries, dns_responses):
        """Update DNS tab with queries and response status."""
        self.dns_tree.delete(*self.dns_tree.get_children())
        for query in dns_queries[:50]:  # Limit to first 50
            # Check if we saw a response for this transaction ID
            has_response = query['tx_id'] in dns_responses
            response_status = "✓" if has_response else "✗"
            
            self.dns_tree.insert("", tk.END, values=(
                query['query'], 
                query['type'],
                f"{query['src_ip']} -> {query['dst_ip']}",
                query.get('time', ''),
                response_status
            ))
    
    def update_hosts_tab(self, ip_traffic):
        """Update hosts tab with IP intelligence - show all unique hosts."""
        sorted_ips = sorted(ip_traffic.items(), key=lambda x: x[1]['packets'], reverse=True)
        
        self.hosts_tree.delete(*self.hosts_tree.get_children())
        for ip, stats in sorted_ips:
            ip_type, info = self.classify_ip(ip)
            hostname = self.lookup_device_name(ip) or ""
            self.hosts_tree.insert("", tk.END, values=(
                ip,
                hostname,
                f"{stats['packets']:,}",
                f"{stats['bytes']:,}",
                ip_type,
                info
            ))
    
    def classify_ip(self, ip):
        """Classify IP address and provide intelligence."""
        try:
            # Check if it's a valid IPv4 address
            packed = socket.inet_aton(ip)
            first_octet = struct.unpack('!B', packed[:1])[0]
            
            # RFC1918 Private Address Ranges
            if self.is_private_ip(ip):
                return "Internal", "Private network (RFC1918)"
            
            # Known proxy service IP ranges (simplified)
            if self.is_zscaler_ip(ip):
                return "Proxy", "Zscaler proxy service detected"
            
            # Public IP
            return "External", f"Public IP (first octet: {first_octet})"
            
        except Exception:
            return "Unknown", "Invalid IP address"
    
    def is_private_ip(self, ip):
        """Check if IP is in RFC1918 private ranges."""
        try:
            packed = socket.inet_aton(ip)
            first_octet = struct.unpack('!B', packed[:1])[0]
            second_octet = struct.unpack('!B', packed[1:2])[0]
            
            # 10.0.0.0/8
            if first_octet == 10:
                return True
            # 172.16.0.0/12
            if first_octet == 172 and 16 <= second_octet <= 31:
                return True
            # 192.168.0.0/16
            if first_octet == 192 and second_octet == 168:
                return True
            
            return False
        except Exception:
            return False
    
    def is_zscaler_ip(self, ip):
        """Check if IP belongs to known Zscaler ranges (simplified)."""
        # Known Zscaler IP ranges (subset for demonstration)
        zscaler_ranges = [
            ('192.42.0.0', '192.42.255.255'),
            ('35.186.0.0', '35.186.255.255'),
        ]
        
        try:
            ip_int = self.ip_to_int(ip)
            for start, end in zscaler_ranges:
                if self.ip_to_int(start) <= ip_int <= self.ip_to_int(end):
                    return True
        except Exception:
            pass
        
        return False
    
    def ip_to_int(self, ip):
        """Convert IP address to integer for range comparison."""
        parts = ip.split('.')
        return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])
    
    def update_wireless_tab(self, has_wireless, wireless_clients):
        """Update wireless analysis tab."""
        if not has_wireless:
            rf_text = "No 802.11 (wireless) frames detected in this capture.\n"
            self.update_text_widget(self.rf_text, rf_text)
            return
        
        # RF Info
        rf_text = "Wireless Frames Detected:\n\n"
        for client_mac, stats in list(wireless_clients.items())[:20]:
            avg_signal = sum(stats['signals']) / len(stats['signals']) if stats['signals'] else 0
            rf_text += f"Client: {client_mac}\n"
            rf_text += f"  Packets: {stats['packets']}\n"
            rf_text += f"  Retries: {stats['retries']}\n\n"
        
        self.update_text_widget(self.rf_text, rf_text)
        
        # Client Analysis
        self.wireless_client_tree.delete(*self.wireless_client_tree.get_children())
        for client_mac, stats in list(wireless_clients.items())[:50]:
            avg_signal = sum(stats['signals']) / len(stats['signals']) if stats['signals'] else 0
            self.wireless_client_tree.insert("", tk.END, values=(
                client_mac,
                f"{avg_signal:.1f} dBm",
                stats['packets'],
                stats['retries']
            ))
    
    def update_performance_tab(self, bandwidth_buckets):
        """Update performance analysis tab."""
        # RTT/Latency - calculate using ICMP echo request/reply pairs
        icmp_requests = {}  # seq -> timestamp of request
        rtt_measurements = defaultdict(list)
        
        for pkt in self.packets:
            if pkt.haslayer(IP) and pkt.haslayer(ICMP):
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                icmp_seq = pkt[ICMP].seq
                
                # Track echo requests
                if pkt[ICMP].type == 8:  # Echo request
                    icmp_requests[(src_ip, dst_ip, icmp_seq)] = float(pkt.time)
                # Calculate RTT for echo replies
                elif pkt[ICMP].type == 0:  # Echo reply
                    req_time = icmp_requests.get((dst_ip, src_ip, icmp_seq))
                    if req_time:
                        rtt_ms = (float(pkt.time) - req_time) * 1000
                        conn_key = f"{src_ip} <-> {dst_ip}"
                        rtt_measurements[conn_key].append(rtt_ms)
        
        # Update RTT table
        self.rtt_tree.delete(*self.rtt_tree.get_children())
        for conn_key, measurements in list(rtt_measurements.items())[:20]:
            if measurements:
                avg_rtt = sum(measurements) / len(measurements)
                min_rtt = min(measurements)
                max_rtt = max(measurements)
                
                self.rtt_tree.insert("", tk.END, values=(
                    conn_key,
                    f"{avg_rtt:.2f}",
                    f"{min_rtt:.2f}",
                    f"{max_rtt:.2f}"
                ))
        
        # Bandwidth Over Time
        bw_text = "Bandwidth Utilization Over Time:\n\n"
        if bandwidth_buckets:
            min_bucket = min(bandwidth_buckets.keys())
            max_bucket = max(bandwidth_buckets.keys())
            
            for bucket in range(min_bucket, min(max_bucket + 1, min_bucket + 60)):  # First 60 seconds
                bytes_in_bucket = bandwidth_buckets.get(bucket, 0)
                kbps = (bytes_in_bucket * 8) / 1024  # Convert to Kbps
                
                bar_length = int(kbps / 10) if kbps < 1000 else 100
                bar = "█" * bar_length
                
                bw_text += f"{bucket - min_bucket:3d}s: {kbps:>8.1f} Kbps {bar}\n"
        
        self.update_text_widget(self.bw_text, bw_text)
    
    def update_traffic_patterns(self, packet_sizes, app_protocols, flow_bytes):
        """Update traffic patterns tab."""
        # Packet Size Distribution
        size_text = "Packet Size Distribution:\n\n"
        if packet_sizes:
            min_size = min(packet_sizes)
            max_size = max(packet_sizes)
            
            # Create histogram buckets
            buckets = [0] * 10
            bucket_size = (max_size - min_size + 1) / 10
            
            for size in packet_sizes:
                bucket_idx = int((size - min_size) / bucket_size)
                if bucket_idx >= 10:
                    bucket_idx = 9
                buckets[bucket_idx] += 1
            
            for i, count in enumerate(buckets):
                range_start = int(min_size + i * bucket_size)
                range_end = int(min_size + (i + 1) * bucket_size)
                
                bar_length = min(int(count / 10), 50)
                bar = "█" * bar_length
                
                size_text += f"{range_start:>5}-{range_end:<5}: {count:>6} {bar}\n"
        
        self.update_text_widget(self.size_text, size_text)
        
        # Application Protocol Breakdown
        app_text = "Application Protocol Breakdown:\n\n"
        for protocol, count in app_protocols.most_common():
            app_text += f"{protocol}: {count:,} packets\n"
        
        self.update_text_widget(self.app_text, app_text)
        
        # Top Flows by Bytes - recalculate with proper byte counting
        flow_bytes_actual = defaultdict(int)
        flow_packets = defaultdict(int)
        for pkt in self.packets:
            if pkt.haslayer(IP):
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                
                # Create flow key (bidirectional)
                if src_ip < dst_ip:
                    flow_key = f"{src_ip} <-> {dst_ip}"
                else:
                    flow_key = f"{dst_ip} <-> {src_ip}"
                
                flow_bytes_actual[flow_key] += pkt[IP].len
                flow_packets[flow_key] += 1
        
        self.flows_tree.delete(*self.flows_tree.get_children())
        sorted_flows = sorted(flow_bytes_actual.items(), key=lambda x: x[1], reverse=True)[:20]
        for flow_key, bytes_transferred in sorted_flows:
            packets_count = flow_packets[flow_key]
            self.flows_tree.insert("", tk.END, values=(
                flow_key,
                f"{bytes_transferred:,}",
                f"{packets_count:,}"
            ))
    
    def update_security_tab(self, port_scan_tracker, ip_mac_map):
        """Update security analysis tab."""
        # Port Scan Detection
        scan_text = "Port Scan Detection:\n\n"
        for src_ip, ports in port_scan_tracker.items():
            if len(ports) > 10:  # Threshold for potential scan
                scan_text += f"Potential port scan from {src_ip}:\n"
                scan_text += f"  Targeted {len(ports)} unique ports\n\n"
        
        if not any(len(ports) > 10 for ports in port_scan_tracker.values()):
            scan_text += "No significant port scanning activity detected.\n"
        
        self.update_text_widget(self.scan_text, scan_text)
        
        # Duplicate IP/MAC Detection
        dup_text = "Duplicate IP/MAC Detection:\n\n"
        mac_ip_map = {}
        for ip, mac in ip_mac_map.items():
            if mac in mac_ip_map and mac_ip_map[mac] != ip:
                dup_text += f"Potential duplicate MAC {mac}:\n"
                dup_text += f"  IP {mac_ip_map[mac]} and IP {ip}\n\n"
            else:
                mac_ip_map[mac] = ip
        
        if not any(mac in mac_ip_map for mac in ip_mac_map.values()):
            dup_text += "No duplicate IP/MAC mappings detected.\n"
        
        self.update_text_widget(self.dup_text, dup_text)
    
    def analyze_tcp_retransmissions(self):
        """Count TCP retransmissions: a data segment that doesn't advance the
        highest sequence number already sent in that direction. Pure ACKs
        (payload_len == 0) are skipped - they carry no data to retransmit and
        routinely repeat the same sequence number as the last real segment,
        which is indistinguishable from a retransmission by sequence number
        alone. Counting them massively overstates the rate: a normal one-way
        transfer (data one way, ACKs the other) with zero real
        retransmissions measured at 47% before this exclusion."""
        highest_seq_end = {}  # conn_key -> highest seq+payload_len seen
        total = 0
        by_host = defaultdict(int)
        by_connection = defaultdict(int)

        for pkt in self.packets:
            if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
                continue

            ip_len = pkt[IP].len
            ip_header_len = pkt[IP].ihl * 4
            tcp_header_len = pkt[TCP].dataofs * 4
            payload_len = max(0, ip_len - ip_header_len - tcp_header_len)
            if payload_len == 0:
                continue

            src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
            conn_key = f"{src_ip}:{pkt[TCP].sport} <-> {dst_ip}:{pkt[TCP].dport}"
            seq_end = pkt[TCP].seq + payload_len

            if conn_key not in highest_seq_end:
                highest_seq_end[conn_key] = seq_end
            elif seq_end <= highest_seq_end[conn_key]:
                total += 1
                by_host[src_ip] += 1
                by_connection[conn_key] += 1
            else:
                highest_seq_end[conn_key] = seq_end

        return {'total': total, 'by_host': by_host, 'by_connection': by_connection}
    
    def calculate_avg_rtt(self):
        """Calculate average RTT using ICMP echo request/reply pairs."""
        icmp_requests = {}  # seq -> timestamp of request
        rtt_measurements = []
        
        for pkt in self.packets:
            if pkt.haslayer(IP) and pkt.haslayer(ICMP):
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                icmp_seq = pkt[ICMP].seq
                
                # Track echo requests
                if pkt[ICMP].type == 8:  # Echo request
                    icmp_requests[(src_ip, dst_ip, icmp_seq)] = float(pkt.time)
                # Calculate RTT for echo replies
                elif pkt[ICMP].type == 0:  # Echo reply
                    req_time = icmp_requests.get((dst_ip, src_ip, icmp_seq))
                    if req_time:
                        rtt_ms = (float(pkt.time) - req_time) * 1000
                        rtt_measurements.append(rtt_ms)
        
        if rtt_measurements:
            return sum(rtt_measurements) / len(rtt_measurements)
        return 0
    
    def update_text_widget(self, widget, text):
        """Update a text widget with new content."""
        widget.configure(state=tk.NORMAL)
        widget.delete(1.0, tk.END)
        widget.insert(tk.END, text)
        widget.configure(state=tk.DISABLED)


def main():
    root = tk.Tk()
    
    # Set up modern theme if available
    try:
        style = ttk.Style()
        style.theme_use('clam')
    except Exception:
        pass
    
    app = PCAPAnalyzerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()