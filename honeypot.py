import socket
import threading
import time
import tkinter as tk
from collections import defaultdict
from tkinter import messagebox, scrolledtext, ttk

import paramiko


class SSHHoneypotServer(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()

    def check_auth_password(self, username, password):
        print(f"[!] Login attempt with username: '{username}', password: '{password}'")
        # Fail the authentication attempt
        if password == 'passwd':
            return paramiko.OPEN_SUCCEEDED
        else:
            return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

class SSHHoneypotGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SSH Honeypot")
        self.is_running = False
        self.block_ssh_connections = tk.BooleanVar()
        self.block_malicious_ips = tk.BooleanVar()
        self.blocked_ips = set()
        self.connection_counts = defaultdict(int)

        # Main frame to hold all other frames
        main_frame = tk.Frame(self.root)
        main_frame.pack(expand=True, fill="both")

        # Frame for the Treeview widget
        frame = tk.Frame(main_frame)
        frame.pack(expand=True, fill="both")

        # Create a Treeview widget to display the table within the frame
        self.tree = ttk.Treeview(frame, columns=("IP Address", "Connection Count"), show="headings")
        self.tree.heading("IP Address", text="IP Address")
        self.tree.heading("Connection Count", text="Connection Count")
        self.tree.pack(expand=True, fill="both", side="left")

        # Add a scrollbar to the Treeview
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        # Frame for console output
        console_frame = tk.Frame(main_frame)
        console_frame.pack(fill="x")

        # Console output
        self.console_output = scrolledtext.ScrolledText(console_frame, width=70, height=10)
        self.console_output.pack(fill="x")

        # Frame for controls
        controls_frame = tk.Frame(main_frame)
        controls_frame.pack(fill="x")

        # Block SSH checkbox
        self.block_ssh_checkbox = tk.Checkbutton(
            controls_frame,
            text="Block SSH Connections",
            variable=self.block_ssh_connections
        )
        self.block_ssh_checkbox.grid(row=0, column=0, sticky="w")

        # Block Malicious IPs checkbox
        self.malicious_ip_checkbox = tk.Checkbutton(
            controls_frame,
            text="Automatically Block Malicious IPs",
            variable=self.block_malicious_ips
        )
        self.malicious_ip_checkbox.grid(row=0, column=1, sticky="w")

        # Add IP block entry and button
        self.ip_entry = tk.Entry(controls_frame, width=20)
        self.ip_entry.grid(row=1, column=0, sticky="w")
        self.add_ip_button = tk.Button(controls_frame, text="Block IP", command=self.add_blocked_ip)
        self.add_ip_button.grid(row=1, column=1, sticky="w")

        # Add IP unblock entry and button
        self.ip_unblock_entry = tk.Entry(controls_frame, width=20)
        self.ip_unblock_entry.grid(row=2, column=0, sticky="w")
        self.unblock_ip_button = tk.Button(controls_frame, text="UnBlock IP", command=self.unblock_ip)
        self.unblock_ip_button.grid(row=2, column=1, sticky="w")

        # Start and stop buttons
        self.start_button = tk.Button(controls_frame, text="Start Honeypot", command=self.start_honeypot)
        self.start_button.grid(row=3, column=0, sticky="w")

        self.stop_button = tk.Button(controls_frame, text="Stop Honeypot", command=self.stop_honeypot, state=tk.DISABLED)
        self.stop_button.grid(row=3, column=1, sticky="w")

        # Initialize log file and SSH host key
        self.log_file = "ssh_honeypot.log"
        self.hostkey = paramiko.RSAKey.generate(2048)
        self.active_connections = defaultdict(list)

    def log_to_console(self, message):
        self.console_output.insert(tk.END, f"{message}\n")
        self.console_output.see(tk.END)
        self.log_to_file(message)

    def log_to_file(self, message):
        with open(self.log_file, "a") as f:
            f.write(f"{message}\n")

    def add_blocked_ip(self):
        ip = self.ip_entry.get().strip()
        if ip:
            self.blocked_ips.add(ip)
            self.log_to_console(f"IP {ip} has been blocked.")
            self.ip_entry.delete(0, tk.END)
        else:
            messagebox.showwarning("Input Error", "Please enter a valid IP address.")
    
    def unblock_ip(self):
        ip = self.ip_unblock_entry.get().strip()
        if ip in self.blocked_ips:
            self.blocked_ips.remove(ip)
            self.log_to_console(f"IP {ip} has been unblocked.")
        else:
            messagebox.showwarning("Input Error", "IP not blocked to unblock")
        self.ip_unblock_entry.delete(0, tk.END)
        
    def is_malicious_ip(self, ip):
        if self.connection_counts[ip] > 1:
            return True
        return False

    def start_honeypot(self):
        if self.is_running:
            return
        self.is_running = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.honeypot_thread = threading.Thread(target=self.run_honeypot)
        self.honeypot_thread.start()
        self.log_to_console("Honeypot started.")

    def stop_honeypot(self):
        if not self.is_running:
            return
        self.is_running = False
        self.close_all_connections()
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.log_to_console("Honeypot stopped.")

    def run_honeypot(self):
        host, port = "0.0.0.0", 2222
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen(100)
        self.log_to_console(f"Honeypot listening on {host}:{port}")

        while self.is_running:
            try:
                client, addr = sock.accept()
                ip, _ = addr
                self.log_to_console(f"Connection from {ip}")
                if ip in self.blocked_ips:
                    self.log_to_console(f"Connection from {ip} blocked (manually).")
                    self.close_active_connections(ip)
                    client.close()
                    continue
                if self.block_malicious_ips.get() and self.is_malicious_ip(ip):
                    self.log_to_console(f"Connection from {ip} blocked (malicious).")
                    self.blocked_ips.add(ip)
                    self.close_active_connections(ip)
                    client.close()
                    continue
                if self.block_ssh_connections.get():
                    self.log_to_console(f"SSH connection from {ip} blocked.")
                    client.close()
                    continue
                threading.Thread(target=self.handle_ssh_interaction, args=(client, ip)).start()
            except Exception as e:
                self.log_to_console(f"Error accepting connection: {e}")
        sock.close()
    
    def update_treeview(self):
        """Update the Treeview with the latest connection counts."""
        self.tree.delete(*self.tree.get_children())
        for ip, count in self.connection_counts.items():
            if count > 0:
                self.tree.insert("", "end", values=(ip, count)) 

    def close_all_connections(self):
        for ip, connections in self.active_connections.items():
            for conn in connections:
                try:
                    conn.close()
                    self.connection_counts[ip]-=1
                    self.update_treeview()
                    self.log_to_console(f"Closed active connection from {ip}.")
                except Exception as e:
                    self.log_to_console(f"Error closing connection for {ip}: {e}")
        self.active_connections[ip] = []  # Clear the list after closing all connections for the IP

    
    def close_active_connections(self,ip):
        for channel in self.active_connections[ip]:
            try:
                channel.close()
                self.connection_counts[ip]-=1
                self.update_treeview()
            except Exception as e:
                self.log_to_console(f"Error while closing the connection,{e}")
            finally:
                self.active_connections[ip]=[]
                del self.connection_counts[ip]
            
            


    def handle_ssh_interaction(self, client, ip):
        try:
            self.log_to_console(f"Handling SSH interaction with {ip}")
            transport = paramiko.Transport(client)
            transport.add_server_key(self.hostkey)
            server = SSHHoneypotServer()
            transport.start_server(server=server)
            channel = transport.accept(120)
            if channel is None:
                self.log_to_console(f"No channel opened by {ip}")
                return
            channel.send("Welcome to SSH honeypot!\n")
            self.connection_counts[ip]+=1
            self.active_connections[ip].append(channel)
            self.update_treeview()
            time.sleep(60)
            channel.close()
            self.active_connections[ip].remove(channel)
            self.connection_counts[ip]-=1
            self.update_treeview()
            self.log_to_console(f"SSH session with {ip} closed.")
        except Exception as e:
            self.log_to_console(f"Error during SSH interaction with {ip}: {e}")
        finally:
            client.close()

if __name__ == "__main__":
    root = tk.Tk()
    honeypot_gui = SSHHoneypotGUI(root)
    root.mainloop()
