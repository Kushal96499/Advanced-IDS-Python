# 🛡️ Advanced Intrusion Detection System (IDS)

A real-time network monitoring and intrusion detection system built with Python and Scapy. This project detects suspicious activities like SYN floods, port scans, DNS spoofing, and ping of death attacks. Designed to be user-friendly, colorful, and informative — perfect for educational, internship, and research purposes.

**COMPANY:** CODEC TECHNOLOGIES INDIA

**NAME:** KUSHAL KUMAWAT

**NCS ID:** E19E86-0116588287923

**DOMAIN:** Cyber Security Intern

**DURATION:** 3 Months

**MENTOR:** Miss.Vaishali
---

## 📌 Project Overview

This project was developed as part of my internship at **CodecTechnologies (2025)**. The goal was to create a feature-rich and user-friendly Intrusion Detection System that can help detect common network-based attacks in real time and log those alerts for further analysis.

---

## ✨ Features

- ✅ Real-time packet sniffing and analysis
- 🔍 Detection of:
  - SYN Flood Attacks
  - Port Scanning
  - Ping of Death
  - DNS Spoofing
- 🎨 Color-coded terminal alerts using `colorama`
- 📂 CSV and Log file export for alerts
- 📡 Built using Scapy for powerful packet inspection
- 🧠 Clean and well-commented Python code
- 📛 Cool ASCII banner with developer details
- 🧘 Graceful shutdown with Ctrl+C and automatic export

---

## 🚀 Technologies Used

- Python 3.x
- [Scapy](https://scapy.net/) – for packet sniffing and manipulation
- [Colorama](https://pypi.org/project/colorama/) – for colorful terminal outputs
- CSV & Logging Modules – to handle alert exports and logs

---

## 📁 File Structure

```bash
Advanced-Intrusion-Detection-System/
├── advanced_ids.py          # Main IDS script
├── ids_alerts.csv           # (Generated) Alert data in CSV format
├── ids_alerts.log           # (Generated) Log file with timestamps
├── README.md                # Project documentation
└── Report.pdf               # Internship report for submission
```

---

⚙️ Setup Instructions
🔧 Requirements
Install the necessary Python packages:
```bash
sudo apt update
sudo apt install python3-pip
pip3 install scapy colorama
```
📌 Note: This script requires root privileges to sniff packets.

---

🏃‍♂️ How to Run (on Kali Linux or any Linux)
Clone or download the project folder.

Run the IDS with sudo:
```bash
sudo python3 advanced_ids.py
```
To stop the monitoring, press Ctrl + C. This will:

Save alerts to ids_alerts.csv

Log data to ids_alerts.log

---

🧪 How to Test
Open a new terminal and simulate common attacks using:

📍 SYN Scan (Nmap):
```bash
nmap -sS <your_kali_ip>
```
📍 Ping of Death:
```bash
ping -s 1500 <your_kali_ip>
```
📍 Port Scan:
```bash
nmap -sF -T4 <your_kali_ip>
```
📍 DNS Spoof Test:
Use a tool like ettercap or custom Scapy spoofing script to simulate.

---

📈 Output

![Image](https://github.com/user-attachments/assets/6e78affa-d31d-47be-967f-119d22b1ecaa)

---

📜 License
This project is for educational use only. You are free to modify and extend it under the MIT License.

---

👨‍💻 Developed By
Kushal Kumawat
Intern at CodecTechnologies (2025)
**🔐 Focus Area:** Cybersecurity Intern
