"""
Author: Isha
Assignment: #2
Description: Port Scanner — A tool that scans a target machine for open network ports
"""

import socket
import threading
import sqlite3
import os
import platform
import datetime

# Print system info
print("Python Version:", platform.python_version())
print("Operating System:", os.name)

# Dictionary mapping port numbers to service names
common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt"
}

class NetworkTool:
    def __init__(self, target):
        self.__target = target

    @property
    def target(self):
        return self.__target

    @target.setter
    def target(self, value):
        if value != "":
            self.__target = value
        else:
            print("Error: Target cannot be empty")

    def __del__(self):
        print("NetworkTool instance destroyed")


# Q3: What is the benefit of using @property and @target.setter?
# It allows controlled access to private variables. Instead of directly modifying self.__target, we can validate input before setting it. This helps prevent invalid data like empty strings and improves encapsulation and safety.

# Q1: How does PortScanner reuse code from NetworkTool?
# The PortScanner class inherits from NetworkTool, so it automatically gets access to the target attribute and its getter/setter. This avoids rewriting code and allows reuse of validation logic already defined in the parent class.

class PortScanner(NetworkTool):
    def __init__(self, target):
        super().__init__(target)
        self.scan_results = []
        self.lock = threading.Lock()

    def __del__(self):
        print("PortScanner instance destroyed")
        super().__del__()

    # Q4: What would happen without try-except here?
    # If try-except is removed, the program may crash when encountering network errors such as unreachable hosts or connection timeouts. This would stop the entire scanning process and prevent results from being collected.

    def scan_port(self, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)

            result = sock.connect_ex((self.target, port))

            if result == 0:
                status = "Open"
            else:
                status = "Closed"

            service = common_ports.get(port, "Unknown")

            self.lock.acquire()
            self.scan_results.append((port, status, service))
            self.lock.release()

        except socket.error as error:
            print(f"Error scanning port {port}: {error}")

        finally:
            sock.close()

    def get_open_ports(self):
        return [result for result in self.scan_results if result[1] == "Open"]

    # Q2: Why do we use threading instead of scanning one port at a time?
    # Threading allows multiple ports to be scanned simultaneously, which greatly improves performance. If we scanned 1024 ports one by one, it would take much longer since each connection waits for a timeout.

    def scan_range(self, start_port, end_port):
        threads = []

        for port in range(start_port, end_port + 1):
            t = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(t)

        for t in threads:
            t.start()

        for t in threads:
            t.join()


def save_results(target, results):
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            port INTEGER,
            status TEXT,
            service TEXT,
            scan_date TEXT
        )
        """)

        for result in results:
            cursor.execute("""
            INSERT INTO scans (target, port, status, service, scan_date)
            VALUES (?, ?, ?, ?, ?)
            """, (target, result[0], result[1], result[2], str(datetime.datetime.now())))

        conn.commit()
        conn.close()

    except sqlite3.Error as error:
        print("Database error:", error)


def load_past_scans():
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM scans")
        rows = cursor.fetchall()

        for row in rows:
            print(f"[{row[5]}] {row[1]} : Port {row[2]} ({row[4]}) - {row[3]}")

        conn.close()

    except:
        print("No past scans found.")


if __name__ == "__main__":
    try:
        target = input("Enter target IP (default 127.0.0.1): ")
        if target == "":
            target = "127.0.0.1"

        start_port = int(input("Enter start port (1-1024): "))
        end_port = int(input("Enter end port (1-1024): "))

        if start_port < 1 or end_port > 1024 or end_port < start_port:
            print("Port must be between 1 and 1024.")
        else:
            scanner = PortScanner(target)

            print(f"Scanning {target} from port {start_port} to {end_port}...")

            scanner.scan_range(start_port, end_port)

            open_ports = scanner.get_open_ports()

            print(f"--- Scan Results for {target} ---")

            for port, status, service in open_ports:
                print(f"Port {port}: {status} ({service})")

            print("------")
            print("Total open ports found:", len(open_ports))

            save_results(target, scanner.scan_results)

            choice = input("Would you like to see past scan history? (yes/no): ")

            if choice.lower() == "yes":
                load_past_scans()

    except ValueError:
        print("Invalid input. Please enter a valid integer.")


