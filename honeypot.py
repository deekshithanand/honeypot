import paramiko
import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox
import time
from collections import defaultdict

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

        # Console output
        self.console_output = scrolledtext.ScrolledText(self.root, width=70, height=20)
        self.console_output.grid(row=0, column=0, columnspan=3)

        # Block SSH checkbox
        self.block_ssh_checkbox = tk.Checkbutton(
            self.root,
            text="Block SSH Connections",
            variable=self.block_ssh_connections
        )
        self.block_ssh_checkbox.grid(row=1, column=0, sticky="w")

        # Block Malicious IPs checkbox
        self.malicious_ip_checkbox = tk.Checkbutton(
            self.root,
            text="Automatically Block Malicious IPs",
            variable=self.block_malicious_ips
        )
        self.malicious_ip_checkbox.grid(row=1, column=1, sticky="w")

        # Add IP block entry and button
        self.ip_entry = tk.Entry(self.root, width=20)
        self.ip_entry.grid(row=2, column=0, sticky="w")
        self.add_ip_button = tk.Button(self.root, text="Block IP", command=self.add_blocked_ip)
        self.add_ip_button.grid(row=2, column=1, sticky="w")

        #Add IP unblock entry and button
        self.ip_unblock_entry = tk.Entry(self.root, width=20)
        self.ip_unblock_entry.grid(row=3, column=0, sticky="w")
        self.unblock_ip_button = tk.Button(self.root, text="UnBlock IP", command=self.unblock_ip)
        self.unblock_ip_button.grid(row=3, column=1, sticky="w")

        # Start and stop buttons
        self.start_button = tk.Button(self.root, text="Start Honeypot", command=self.start_honeypot)
        self.start_button.grid(row=4, column=0, sticky="w")

        self.stop_button = tk.Button(self.root, text="Stop Honeypot", command=self.stop_honeypot, state=tk.DISABLED)
        self.stop_button.grid(row=4, column=1, sticky="w")

        # Initialize log file
        self.log_file = "ssh_honeypot.log"
        self.hostkey  = paramiko.RSAKey.generate(2048)


    def log_to_console(self, message):
        self.console_output.insert(tk.END, f"{message}\n")
        self.console_output.see(tk.END)
        self.log_to_file(self,message)

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
        try:
            self.blocked_ips.remove(ip)
            self.log_to_console(f"IP {ip} has been blocked.")
        except Exception:
             messagebox.showwarning("IP not blocked to unblock")
        self.ip_unblock_entry.delete(0, tk.END)
        
    def is_malicious_ip(self, ip):
        # simple rule for a "malicious" IP: multiple connection attempts
        self.connection_counts[ip] += 1
        if self.connection_counts[ip] > 2:
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

                # Check if IP is in the blocked list
                if ip in self.blocked_ips:
                    self.log_to_console(f"Connection from {ip} blocked (manually).")
                    client.close()
                    continue

                # Check if IP is malicious and should be blocked
                if self.block_malicious_ips.get() and self.is_malicious_ip(ip):
                    self.log_to_console(f"Connection from {ip} blocked (malicious).")
                    self.blocked_ips.add(ip)  # Add to blocked IPs permanently
                    client.close()
                    continue

                # Block all SSH if checkbox is set
                if self.block_ssh_connections.get():
                    self.log_to_console(f"SSH connection from {ip} blocked.")
                    client.close()
                    continue

                # Handle SSH connection in a new thread
                threading.Thread(target=self.handle_ssh_interaction, args=(client, ip)).start()
            except Exception as e:
                self.log_to_console(f"Error accepting connection: {e}")

        sock.close()

    def handle_ssh_interaction(self, client, ip):
        try:
            self.log_to_console(f"Handling SSH interaction with {ip}")
            transport = paramiko.Transport(client)
            
            # Load a temporary server RSA key
            transport.add_server_key(self.hostkey)

            # Start the SSH server
            server = SSHHoneypotServer()
            transport.start_server(server=server)

            # Wait for a client channel request
            channel = transport.accept(120)
            if channel is None:
                self.log_to_console(f"No channel opened by {ip}")
                return
            
            # Send a banner message to the client
            channel.send("Welcome to SSH honeypot!\n")
            time.sleep(200)
            channel.close()

            self.log_to_console(f"SSH session with {ip} closed.")
            # self.log_to_file(f"SSH session with {ip} handled and closed.")
        except Exception as e:
            self.log_to_console(f"Error during SSH interaction with {ip}: {e}")
            # self.log_to_file(f"Error handling SSH connection from {ip}: {e}")
        finally:
            client.close()

if __name__ == "__main__":
    root = tk.Tk()
    honeypot_gui = SSHHoneypotGUI(root)
    root.mainloop()
