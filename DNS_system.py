# Part 1: Implement a DNS Security System with On/Off Control
import sqlite3
import socketserver
import threading
from dnslib import DNSRecord, RR, QTYPE, A

# Initialize or connect to the SQLite database
conn = sqlite3.connect('dns_security.db')
cursor = conn.cursor()

# Create a table to store URLs and their threat flags
cursor.execute('''
    CREATE TABLE IF NOT EXISTS dns_security (
        id INTEGER PRIMARY KEY,
        url TEXT NOT NULL,
        threat_flag TEXT NOT NULL
    )
''')
conn.commit()

# Global variable to control DNS security system state
dns_security_active = False

# Function to store URL and flag in the database# Function to store or update URL and flag in the database
def store_url_flag(url, threat_flag):
    threat_flag = threat_flag.lower()
    if threat_flag not in ['safe', 'malicious', 'undetected']:
        print(f"Invalid threat flag '{threat_flag}'. Must be 'safe', 'malicious', or 'undetected'.")
        return
    
    # Check if the URL already exists in the database
    cursor.execute('SELECT id FROM dns_security WHERE url = ?', (url,))
    result = cursor.fetchone()
    
    if result:
        # If URL exists, update the threat flag
        cursor.execute('UPDATE dns_security SET threat_flag = ? WHERE url = ?', (threat_flag, url))
        print(f"Updated threat flag for {url} to '{threat_flag}'.")
    else:
        # If URL does not exist, insert a new entry
        cursor.execute('INSERT INTO dns_security (url, threat_flag) VALUES (?, ?)', (url, threat_flag))
        print(f"Added {url} with threat flag '{threat_flag}' to the database.")
    
    # Commit the changes
    conn.commit()


# Function to check if a URL is malicious and stop it from reaching
def check_and_block_url(url):
    cursor.execute('SELECT threat_flag FROM dns_security WHERE url = ?', (url,))
    result = cursor.fetchone()
    if result:
        if result[0].lower() == 'malicious':
            print(f"Access to {url} is blocked as it is flagged as malicious.")
            return True
        elif result[0].lower() == 'safe':
            print(f"Access to {url} is allowed and it is flagged as safe.")
        elif result[0].lower() == 'undetected':
            print(f"Access to {url} is allowed but its status is undetected.")
    else:
        print(f"Access to {url} is allowed. No threat flag found.")
    return False

# DNS Request Handler Class
class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request[0].strip()
        socket = self.request[1]
        request = DNSRecord.parse(data)
        qname = str(request.q.qname)[:-1]  # Remove trailing dot

        # Check if DNS security is active and if the URL should be blocked
        if dns_security_active and check_and_block_url(qname):
            reply = request.reply()
            reply.add_answer(RR(qname, QTYPE.A, rdata=A("0.0.0.0")))  # Return 0.0.0.0 for blocked URLs
        else:
            reply = request.reply()
            reply.add_answer(RR(qname, QTYPE.A, rdata=A("8.8.8.8")))  # Default to Google DNS for safe URLs

        socket.sendto(reply.pack(), self.client_address)

# Function to start DNS server
def start_dns_server():
    server = socketserver.UDPServer(('localhost', 53), DNSHandler)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    print("DNS server is running on localhost:53")

# Function to toggle DNS security system
def toggle_dns_security(state):
    global dns_security_active
    dns_security_active = state
    if dns_security_active:
        print("DNS Security is activated.")
    else:
        print("DNS Security is deactivated.")

# Close the database connection on exit
def close_database():
    conn.close()