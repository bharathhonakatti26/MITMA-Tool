# MITMA - Man-in-the-Middle Attack Tool

MITMA is a Python-based tool designed for educational purposes to demonstrate how a Man-in-the-Middle (MITM) attack works. It uses ARP spoofing to intercept HTTP traffic on a local network and attempts to extract sensitive information like login credentials.

---

## **Features**
- Scans the local network to identify devices.
- Performs ARP spoofing to redirect traffic between a target device and the router.
- Sniffs HTTP traffic to capture potential credentials.
- Restores the network to its original state after the attack is stopped.

---

## **Requirements**
- **Operating System**: Linux (This tool is not compatible with Windows)
- Python 3.x
- Administrator/root privileges
- The following Python libraries:
  - `scapy`
  - `psutil`

---

## **Installation**
1. Clone this repository:
   ```bash
   git clone https://github.com/your-username/MITMA.git
   cd MITMA
   ```
2. Install the required Python libraries:
   ```bash
   pip install -r requirements.txt
   ```
3. Ensure IP forwarding is enabled on your Linux system:
   ```bash
   echo 1 > /proc/sys/net/ipv4/ip_forward
   ```

---

## **Usage**
1. Run the script with administrator/root privileges:
    ```bash
    sudo python3 main.py
    ```

2. Follow the on-screen instructions:
    Select the network interface to sniff on.
    Choose the target device and the router from the list of devices on the network.

3. The tool will start ARP spoofing and sniff HTTP traffic.

4. Press CTRL+C to stop the attack and restore the network.

---

## **Disclaimer**
This tool is intended for educational purposes only. Unauthorized use of this tool to intercept or manipulate network traffic is illegal and unethical. Use it only in a controlled environment with proper authorization.

## **Author**
Bharath Honakatti
GitHub: bharathhonakatti26