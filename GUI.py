import sqlite3
import threading
from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QMainWindow, QVBoxLayout, QGroupBox, QGridLayout, QLabel, QLineEdit, QPushButton, QComboBox, QTableWidget, QTableWidgetItem, QCheckBox, QMessageBox, QWidget
import sys
from DNS_system import start_dns_server, store_url_flag, check_and_block_url, toggle_dns_security
from test import get_flag_and_report

# Initialize or connect to the SQLite database
conn = sqlite3.connect('dns_security.db')
cursor = conn.cursor()

# Global flag to control if DNS server should run in the background after application is closed
run_dns_in_background = False

# GUI Implementation using PyQt5
class SecurityApp(QMainWindow):
    def __init__(self):
        super(SecurityApp, self).__init__()
        self.setWindowTitle("OSINT & DNS Security System")
        self.setGeometry(100, 100, 600, 500)

        # Central widget
        self.central_widget = QWidget(self)
        self.setCentralWidget(self.central_widget)

        # Main vertical layout
        self.main_layout = QVBoxLayout(self.central_widget)

        # Add URL Group Box
        self.group_add_url = QGroupBox("Add URL to DNS Security")
        self.add_url_layout = QGridLayout(self.group_add_url)
        self.label_url = QLabel("URL:")
        self.url_input = QLineEdit()
        self.label_threat_flag = QLabel("Threat Flag:")
        self.threat_flag_combo = QComboBox()
        self.threat_flag_combo.addItems(["safe", "malicious", "undetected"])
        self.add_button = QPushButton("Add URL")
        self.add_url_layout.addWidget(self.label_url, 0, 0)
        self.add_url_layout.addWidget(self.url_input, 0, 1)
        self.add_url_layout.addWidget(self.label_threat_flag, 1, 0)
        self.add_url_layout.addWidget(self.threat_flag_combo, 1, 1)
        self.add_url_layout.addWidget(self.add_button, 2, 1)
        self.main_layout.addWidget(self.group_add_url)

        # Search URL Group Box
        self.group_search_url = QGroupBox("Search DNS Entries")
        self.search_url_layout = QGridLayout(self.group_search_url)
        self.label_search_url = QLabel("URL:")
        self.search_input = QLineEdit()
        self.search_button = QPushButton("Search")
        self.search_url_layout.addWidget(self.label_search_url, 0, 0)
        self.search_url_layout.addWidget(self.search_input, 0, 1)
        self.search_url_layout.addWidget(self.search_button, 1, 1)
        self.main_layout.addWidget(self.group_search_url)

        # DNS Entries Group Box
        self.group_show_all_entries = QGroupBox("DNS Entries")
        self.show_all_layout = QVBoxLayout(self.group_show_all_entries)
        self.show_all_button = QPushButton("Show All Entries")
        self.entries_table = QTableWidget()
        self.entries_table.setColumnCount(2)
        self.entries_table.setHorizontalHeaderLabels(['URL', 'Threat Flag'])
        self.show_all_layout.addWidget(self.show_all_button)
        self.show_all_layout.addWidget(self.entries_table)
        self.main_layout.addWidget(self.group_show_all_entries)

        # DNS Control Group Box
        self.group_dns_control = QGroupBox("DNS Security Control")
        self.dns_control_layout = QVBoxLayout(self.group_dns_control)
        self.dns_active_checkbox = QCheckBox("Activate DNS Security")
        self.run_in_background_checkbox = QCheckBox("Run DNS Server in Background")
        self.dns_control_layout.addWidget(self.dns_active_checkbox)
        self.dns_control_layout.addWidget(self.run_in_background_checkbox)
        self.main_layout.addWidget(self.group_dns_control)

        # OSINT Group Box
        self.group_osint = QGroupBox("OSINT Analysis")
        self.osint_layout = QGridLayout(self.group_osint)
        self.label_osint_url = QLabel("URL:")
        self.osint_input = QLineEdit()
        self.osint_button = QPushButton("Generate OSINT Report")
        self.osint_layout.addWidget(self.label_osint_url, 0, 0)
        self.osint_layout.addWidget(self.osint_input, 0, 1)
        self.osint_layout.addWidget(self.osint_button, 1, 1)
        self.main_layout.addWidget(self.group_osint)

        # Connect buttons to methods
        self.add_button.clicked.connect(self.add_url)
        self.search_button.clicked.connect(self.search_url)
        self.show_all_button.clicked.connect(self.show_all_entries)
        self.dns_active_checkbox.stateChanged.connect(self.toggle_dns_security)
        self.osint_button.clicked.connect(self.generate_osint_report)
        self.run_in_background_checkbox.stateChanged.connect(self.toggle_dns_background_flag)

    def show_all_entries(self):
        # Clear the table before adding new entries
        self.entries_table.clearContents()
        self.entries_table.setRowCount(0)

        cursor.execute('SELECT url, threat_flag FROM dns_security')
        rows = cursor.fetchall()

        self.entries_table.setRowCount(len(rows))
        for row_idx, row_data in enumerate(rows):
            for col_idx, data in enumerate(row_data):
                self.entries_table.setItem(row_idx, col_idx, QTableWidgetItem(str(data)))

        self.entries_table.resizeColumnsToContents()

    def add_url(self):
        url = self.url_input.text()
        threat_flag = self.threat_flag_combo.currentText().lower()
        if url and threat_flag:
            store_url_flag(url, threat_flag)
            QMessageBox.information(self, "Success", f"URL '{url}' with flag '{threat_flag}' added successfully.")
        else:
            QMessageBox.warning(self, "Input Error", "Please enter both URL and threat flag.")

    def search_url(self):
        url = self.search_input.text()
        if url:
            threat_flag, report = get_flag_and_report(url=url)
            store_url_flag(url, threat_flag)
            cursor.execute('SELECT threat_flag FROM dns_security WHERE url = ?', (url,))
            result = cursor.fetchone()
            if result:
                QMessageBox.information(self, "Search Result", f"URL: {url}\nThreat Flag: {result[0]}\nReport: {report}")
            else:
                QMessageBox.information(self, "Search Result", f"URL: {url} not found in DNS entries.")
        else:
            QMessageBox.warning(self, "Input Error", "Please enter a URL to search.")

    def toggle_dns_security(self):
        state = self.dns_active_checkbox.isChecked()
        toggle_dns_security(state)
        if state:
            QMessageBox.information(self, "DNS Security", "DNS Security is activated.")
        else:
            QMessageBox.information(self, "DNS Security", "DNS Security is deactivated.")

    def generate_osint_report(self):
        url = self.osint_input.text()
        if url:
            threat_flag, report = get_flag_and_report(url=url)
            store_url_flag(url, threat_flag)
            QMessageBox.information(self, "OSINT Report", f"URL: {url}\nThreat Flag: {threat_flag}\nReport: {report}")
        else:
            QMessageBox.warning(self, "Input Error", "Please enter a URL for OSINT analysis.")

    def toggle_dns_background_flag(self):
        global run_dns_in_background
        run_dns_in_background = self.run_in_background_checkbox.isChecked()
        if run_dns_in_background:
            QMessageBox.information(self, "Background DNS", "DNS server will keep running in the background even after closing the application.")
        else:
            QMessageBox.information(self, "Background DNS", "DNS server will stop when the application is closed.")

# Start the DNS server in a separate thread
def start_dns_server_thread():
    server_thread = threading.Thread(target=start_dns_server)
    server_thread.daemon = not run_dns_in_background  # Set daemon based on the flag
    server_thread.start()

if __name__ == "__main__":
    # Start the DNS server
    threading.Thread(target=start_dns_server_thread).start()

    # Start the GUI
    app = QtWidgets.QApplication(sys.argv)
    main_window = SecurityApp()
    main_window.show()
    sys.exit(app.exec_())

    # Close the database connection
    conn.close()
