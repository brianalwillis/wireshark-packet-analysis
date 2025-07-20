<h1 = align=center>𝚆𝙸𝚁𝙴𝚂𝙷𝙰𝚁𝙺 𝙿𝙰𝙲𝙺𝙴𝚃 𝙰𝙽𝙰𝙻𝚈𝚂𝙸𝚂</h1>

<p = align=center>
<img width="1472" height="783" alt="Wireshark Final drawio" src="https://github.com/user-attachments/assets/be13648a-329a-46b7-b929-dc9503284816" />
</p>

## 🛠️ TECHNOLOGY & PLATFORMS UTILIZED

- `Wireshark:`</br>
  Core tool used for capturing and analyzing network traffic across various protocols.

- `VirtualBox:`</br>
  Hosted multiple isolated virtual machines for safely simulating real-world networking environments and security attacks.

- `Ubuntu VM 1:`</br>
  
  
- `Ubuntu VM 2:`</br>
  

## OBJECTIVE

This project involved the design and execution of a comprehensive series of network security simulations using `Wireshark` in a controlled virtual lab environment. Leveraging `VirtualBox` and multiple `Linux` virtual machines, I captured and analyzed network traffic across a variety of protocols to simulate both normal and malicious behavior. Key scenarios included `TCP handshakes`, `SYN scans`, `DNS tunneling`, `ARP spoofing`, `credential leakage` via HTTP and FTP, `Telnet/SSH` sessions, `TLS/SSL handshakes`, and `DoS/DDoS` indicators. Each simulation was crafted to mirror real-world attack patterns or defensive monitoring tasks, providing deep insights into packet-level behavior, protocol vulnerabilities, and network-based threat detection techniques. This project demonstrated hands-on proficiency in packet analysis, threat simulation, and network forensic workflows.

## 📜 TABLE OF CONTENTS

- [`TELNET TRAFFIC`](#telnet-traffic)
- [`SSH TRAFFIC`](ssh-traffic)
- [`TLS/SSL HANDSHAKE`](tlsssl-handshake)
- [`TCP 3-WAY HANDSHAKE`](tcp-3-way-handshake)
- [`DNS TUNNELING`](dns-tunneling)
- [`ARP SPOOFING & MAN-IN-THE-MIDDLE ATTACK`](arp-spoofing--man-in-the-middle-attack)
- [`CREDENTIAL LEAKAGE`](credential-leakage)
- [`DOS/DDOS ATTACK SIMULATION`](dosddos-attack-simulation)

## TELNET TRAFFIC

### Step 1: Set Up the `Telnet Server` (VM 2)

- ### Update package list:
```bash
sudo apt update
```
- ### Install Telnet server (telnetd):
```bash
sudo apt install telnetd
```
- ### Start the Telnet service:
```bash
sudo systemctl start inetd
```
- ### Confirm that Telnet is listening on port 23:
```bash
sudo netstat -tuln | grep :23
```

<img width="717" height="54" alt="image" src="https://github.com/user-attachments/assets/287643b2-218f-4888-9c4f-3327ef279151" />

### *Start `Wireshark` and begin capturing on `enp0s3`.*

---

### Step 2: Set up the `Telnet Client` (VM 1) 

- ### Install the Telnet Client:
```bash
sudo apt install telnet
```

- ### Connect to the Telnet server using its IP address:
```bash
telnet 10.10.10.50
```

<img width="617" height="415" alt="Lab 52" src="https://github.com/user-attachments/assets/b2c8d8fd-3857-4cfa-b41e-28386c5171eb" /></br>

- ### Once connected, run commands to generate traffic:
```bash
whoami
uname -a
ls -la
uptime
```

<img width="726" height="559" alt="Lab 59" src="https://github.com/user-attachments/assets/2652131c-4977-4180-9871-cc4b0463c7ff" />

---

### Step 3: Analyze Telnet Traffic in `Wireshark`

- ### Apply the display filter: `telnet` or `tcp.port == 23`

<img width="1425" height="646" alt="Lab 54 Crop" src="https://github.com/user-attachments/assets/30604382-6420-43aa-86ae-cbd85cc6697c" /></br>

The Telnet session captured in Wireshark demonstrates the inherent insecurity of the protocol, which transmits data entirely in plaintext over TCP port 23. During the session, we observed the full login exchange between the client and server, including the `Ubuntu login:` prompt followed by the username `test` and the password `9000`, all visible without encryption. Subsequent commands such as `whoami`, `uname -a`, `ls -la`, and `uptime` were also captured in clear text, along with their corresponding responses. This analysis clearly highlights how Telnet traffic can be easily intercepted and read by anyone with access to the network, reinforcing why Telnet is considered insecure and has been replaced in modern systems by encrypted alternatives like SSH.

<img width="863" height="489" alt="Lab 55" src="https://github.com/user-attachments/assets/a438edd4-b14d-4fc6-9353-d354d4e0c40f" />

---










