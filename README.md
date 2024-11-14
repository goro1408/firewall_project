cat << 'EOF' > README.md
# Python Firewall Simulator 🔥

A powerful, customizable firewall simulation tool built in Python using Scapy. This project is designed to capture network packets, filter them based on user-defined rules, and log blocked packets for easy analysis. It’s a practical tool for learning network security concepts and experimenting with packet inspection.

## 🌟 Features
- **Real-Time Packet Capture**: Continuously captures live network packets.
- **Customizable Filtering Rules**: Easily block packets based on:
  - **IP Address**: Block packets from specific IPs.
  - **Port**: Restrict access to certain ports (e.g., HTTP/HTTPS).
  - **Protocol**: Block traffic based on protocol (TCP, UDP).
- **Logging**: Logs all blocked packets to `blocked_packets.log` with timestamps for analysis.
- **Educational Value**: Perfect for those learning about network security and packet filtering.

---

## 🛠️ Project Structure
PythonFirewallSimulator/ ├── src/ │ └── firewall.py # Main script for packet capture and filtering ├── README.md # Project overview and instructions ├── requirements.txt # Project dependencies └── blocked_packets.log # Log file for blocked packets

yaml
Copy code

---

## 🚀 Getting Started

### Prerequisites
- **Python 3.x**
- **Scapy**: For packet capture and inspection.
- **Npcap** (for Windows users): Required for packet capture. Install in WinPcap compatibility mode.

### Installation
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/goro1408/firewall_project.git
   cd firewall_project
Install Dependencies:

bash
Copy code
pip install -r requirements.txt
Install Npcap (Windows users only):

Download Npcap and install it with WinPcap API-compatible mode checked.
### ⚙️ Configuration
You can customize the firewall rules directly in src/firewall.py:

Blocked IPs: Add IPs to BLOCKED_IPS to block traffic from specific IP addresses.
Blocked Ports: Modify BLOCKED_PORTS to restrict specific ports.
Blocked Protocols: Add protocols (e.g., TCP, UDP) to BLOCKED_PROTOCOLS to control protocol-based filtering.
Example configuration:

python
Copy code
BLOCKED_IPS = ["192.168.1.10"]
BLOCKED_PORTS = [80, 443]
BLOCKED_PROTOCOLS = ["UDP"]
### 📝 Usage
To start the firewall simulation, run:

bash
Copy code
python src/firewall.py
Output: Allowed and blocked packets will print to the console in real-time.
Log File: All blocked packets are saved in blocked_packets.log with details including the timestamp, source IP, destination IP, and reason for blocking.
Example Output:

rust
Copy code
Blocked packet from/to IP: 192.168.1.10 -> 10.0.0.2
Blocked UDP packet: 10.0.0.3:12345 -> 192.168.1.1:80
Allowed packet: 10.0.0.4 -> 10.0.0.5
#### 📄 Logs
Blocked packets are recorded in blocked_packets.log in this format:

rust
Copy code
2024-11-14 12:34:56 - Blocked packet from/to IP: 192.168.1.10 -> 10.0.0.2
2024-11-14 12:35:02 - Blocked UDP packet: 10.0.0.3:12345 -> 192.168.1.1:80
The log includes timestamps, which help in analyzing when and how often certain packets were blocked.

#### 🛡️ Security Considerations
This project is intended for learning and experimentation. It should not be used as a replacement for a production-grade firewall. Scapy operates at the application layer and is limited compared to dedicated firewall solutions.

#### 🤔 Why This Project?
This project demonstrates essential skills in network security, packet analysis, and rule-based filtering. It’s ideal for individuals interested in understanding the basics of firewall operations and exploring packet inspection with Python.

### 🤝 Contributions
Contributions are welcome! Feel free to fork the repository, submit pull requests, or open issues to suggest improvements.

📄 License
This project is licensed under the MIT License. See LICENSE for details.

### 📞 Contact
Developed by Orlando Del Valle Sanchez.

Email: goro.14082@gmail.com
LinkedIn: Orlando Del Valle Sanchez
Thank you for checking out the project! 🌐🔒

