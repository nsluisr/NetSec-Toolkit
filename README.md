# Python WiFi Audit Toolkit



[![Status](https://img.shields.io/badge/status-active-brightgreen.svg)](#) [![License](https://img.shields.io/badge/License-MIT-blue.svg)](/LICENSE) [![Python Version](https://img.shields.io/badge/python-3.9+-blue.svg)](#)

A suite of command-line tools written in Python for performing network security audits. It includes a deep network scanner and a traffic monitor with Man-in-the-Middle (ARP Spoofing) capabilities.

**Developed and optimized by sluisr.**

---

## ✨ Features

- ✅ **Network Discovery:** Scans the local network to find all active hosts.
- ✅ **Deep Analysis:** Performs a detailed port and service scan on a specific target using Nmap.
- ✅ **Traffic Monitoring:** Captures and analyzes network traffic in real-time.
- ✅ **Service Identification:** Detects connections to popular services (Google, Facebook, WhatsApp, etc.).
- ✅ **Network Visualization:** Generates a graphical map of connections between devices and external services.
- ✅ **Polished User Interface:** Interactive CLI with colors and animations for a better user experience.

---

## 🛠️ Tools Included

| Script                | Description                                                                        |
| --------------------- | ---------------------------------------------------------------------------------- |
| `deep_scanner.py`     | A network scanner to discover hosts and profile a target with Nmap.                |
| `enhanced_monitor.py` | Performs ARP spoofing to capture, analyze, and log network traffic.                |

---

## 🎥 Demo

> A brief demo of the tools in action. (You can record a GIF or short video and place it here).

![Demo GIF](https://place-holder.com/gif-demo.gif)

---

## 📋 Prerequisites

Before you begin, ensure you have the following installed:

- **Python 3.9+**
- **Python Dependencies:** Listed in `requirements.txt`.
- **System Tools:**
  - `nmap`
  - `tshark`
  - `arpspoof` (from the `dsniff` package)
  - `dot` (from the `graphviz` package)

---

## 🚀 Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/nsluisr/NetSec-Toolkit.git
    cd NetSec-Toolkit
    ```

2.  **Create and activate a virtual environment (recommended):**
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

3.  **Install Python dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Install system tools:**
    - **On Arch Linux:**
      ```bash
      sudo pacman -S nmap tshark dsniff graphviz
      ```
    - **On Debian/Ubuntu:**
      ```bash
      sudo apt update
      sudo apt install nmap tshark dsniff graphviz
      ```

---

## USAGE

Both scripts should be run from the project's root directory.

### Deep Scanner

This script can be run with normal user privileges for basic scanning, but requires `sudo` for Nmap scans.

> ```bash
> # Activate your virtual environment if you haven't already
> source venv/bin/activate
> 
> # Run the script
> sudo python3 deep_scanner.py
> ```

### Enhanced Monitor

This script **requires superuser privileges** to perform ARP spoofing and to put the network card in promiscuous mode. **You must run it with the Python interpreter from the virtual environment**.

> ```bash
> # Make sure your virtual environment is activated
> 
> # Run the script with sudo and the venv's python
> sudo venv/bin/python3 enhanced_monitor.py
> ```

---

## ⚖️ Disclaimer

These tools are intended for educational purposes and for use in authorized security audits only. The author is not responsible for any misuse or damage that may be caused by these programs. **Use at your own risk and always with permission.**

---

## 👍 Show Your Support

If you find this project useful, you can show your support in the following ways:

- ⭐ **Star the repository on GitHub.**
- 🐛 **Report any issues or suggest improvements** by opening an issue.
