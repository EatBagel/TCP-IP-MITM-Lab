# TCP/IP Header-Based MITM Attack — VMware Lab

A controlled cybersecurity lab demonstrating packet capture and IPv4 header modification using three virtual machines.

> **Safety note:** Run this experiment only on your own isolated VMware lab network. Do not use these steps on a school, workplace, public, or other network without explicit authorization.

## 1. Lab Overview

The lab uses three VMs connected to the same isolated VMware virtual network.

| Machine | Operating system | IPv4 address | Interface | MAC address |
|---|---|---|---|---|
| Client | Ubuntu | `192.168.50.10/24` | `ens33` | `00:0c:29:5f:e2:6b` |
| Server | Ubuntu | `192.168.50.20/24` | `ens33` | `00:0c:29:92:c6:fe` |
| Attacker | Kali Linux | `192.168.50.30/24` | `eth0` | `00:0c:29:d5:1f:65` |

**Network:** `192.168.50.0/24`  
**Netmask:** `255.255.255.0`  
**VMware network:** Host-only (use the actual VMnet name/number configured on your computer)  
**Default gateway:** Not required for communication within this subnet.

<img width="1916" height="1018" alt="Screenshot 2026-10-27 161639" src="https://github.com/user-attachments/assets/0cdfff6e-eae6-4d39-95ae-57e870739ddf" />


## 2. Objective

The objective is to demonstrate that a packet's IPv4 header can be modified while traffic traverses a controlled man-in-the-middle (MITM) lab.

The bonus portion uses Python, Scapy, and NetfilterQueue to:

1. Select forwarded ICMP echo-request packets from the client to the server.
2. Change the IPv4 Time to Live (TTL) field to `42`.
3. Recalculate the IPv4 header checksum.
4. Allow the modified packet to continue to the destination.
5. Verify the TTL at the server using `tcpdump`.

Only claim a successful modification if the program output and receiving-side capture confirm it.

## 3. Tools

- VMware Workstation or another VMware product that supports an isolated virtual network
- Ubuntu client and server VMs
- Kali Linux attacker VM
- Python 3
- Scapy
- NetfilterQueue
- `iptables`
- `tcpdump`

## 4. Verify Lab Connectivity

On each VM, confirm the interface and IP address:

```bash
ip -br addr
```

Check that the client and server can communicate before starting the packet modifier.

On the client:

```bash
ping -c 4 192.168.50.20
```

On the server:

```bash
ping -c 4 192.168.50.10
```

For the packet modifier to process these packets, the client-to-server traffic must actually traverse Kali. The three VMs being on the same network and Kali capturing ordinary traffic does **not**, by itself, prove that traffic passes through the attacker. Confirm the authorized lab's MITM routing/ARP setup before continuing.

## 5. Install the Dependencies on Kali

Update package lists and install the required packages:

```bash
sudo apt update
sudo apt install python3-scapy python3-netfilterqueue iptables tcpdump
```

Test the Python imports:

```bash
python3 -c "from scapy.all import IP, ICMP; from netfilterqueue import NetfilterQueue; print('Libraries ready')"
```

Expected output:

```text
Libraries ready
```

If the imports fail, resolve the package or Python environment issue before continuing.

## 6. Create the TTL Modification Program

On Kali, create the Python file:

```bash
nano modify_ttl.py
```

Paste the following code:

```python
from netfilterqueue import NetfilterQueue
from scapy.all import IP, ICMP

CLIENT = "192.168.50.10"
SERVER = "192.168.50.20"
NEW_TTL = 42


def process_packet(packet):
    data = packet.get_payload()
    ip = IP(data)

    # Only modify ICMP echo requests from our lab client
    # to our lab server.
    if (
        IP in ip
        and ICMP in ip
        and ip.src == CLIENT
        and ip.dst == SERVER
        and ip[ICMP].type == 8
    ):
        old_ttl = ip.ttl
        ip.ttl = NEW_TTL

        # Recalculate the IPv4 header checksum.
        del ip.chksum

        packet.set_payload(bytes(ip))

        print(
            f"Modified {ip.src} -> {ip.dst}: "
            f"TTL {old_ttl} -> {NEW_TTL}",
            flush=True,
        )

    # Let the packet continue to its destination.
    packet.accept()


queue = NetfilterQueue()

try:
    queue.bind(1, process_packet)
    print("Listening for lab ICMP packets on queue 1...", flush=True)
    queue.run()
except KeyboardInterrupt:
    print("\nStopping packet modifier.")
finally:
    queue.unbind()
```

<img width="1916" height="1018" alt="Screenshot 2026-10-27 161639" src="https://github.com/user-attachments/assets/1081b262-6da3-4f05-ad23-76ff4ee70777" />


Save the file in nano:

1. Press `Ctrl+O`.
2. Press `Enter`.
3. Press `Ctrl+X`.

### What the program does

- NetfilterQueue receives packets selected by a Linux firewall rule.
- Scapy parses the IPv4 and ICMP headers.
- The program selects only echo requests from `192.168.50.10` to `192.168.50.20`.
- It sets the IPv4 TTL to `42` and recalculates the IPv4 header checksum.
- `packet.accept()` lets the packet continue.

This program does not intentionally modify ping replies or unrelated traffic.

## 7. Queue the Lab Packets

On Kali, add a narrowly scoped firewall rule to queue forwarded ICMP echo requests from the client to the server:

```bash
sudo iptables -I FORWARD 1 \
  -s 192.168.50.10 \
  -d 192.168.50.20 \
  -p icmp --icmp-type echo-request \
  -j NFQUEUE --queue-num 1
```

Check that the rule exists and inspect its packet counter:

```bash
sudo iptables -L FORWARD -n -v --line-numbers
```

The rule only processes packets that traverse Kali's `FORWARD` chain. It will not capture locally generated packets on Kali or packets that bypass Kali.

## 8. Run the Program

On Kali:

```bash
sudo python3 modify_ttl.py
```

Expected startup message:

```text
Listening for lab ICMP packets on queue 1...
```

Leave the program running.

From the Ubuntu client, send test pings:

```bash
ping -c 5 192.168.50.20
```

If the selected packets traverse Kali and reach the queue, the program should print messages similar to:

```text
Modified 192.168.50.10 -> 192.168.50.20: TTL 63 -> 42
```

<img width="1917" height="1022" alt="Screenshot 2026-10-27 170127" src="https://github.com/user-attachments/assets/326911d2-2988-416f-ba78-bdbabd087d17" />


The old TTL shown may vary depending on the packet's path and where the queue observes it. The important evidence is that the code logs the original value and sets the outgoing value to `42`.

If no modification messages appear, do not assume the program succeeded. Check whether the `iptables` rule counter increases, and verify that the client-to-server traffic is actually traversing Kali.

## 9. Verify the Result on the Server

On the Ubuntu server, capture incoming ICMP echo requests:

```bash
sudo tcpdump -ni ens33 -vv \
  'icmp and src host 192.168.50.10 and dst host 192.168.50.20'
```

From the client, run another ping:

```bash
ping -c 5 192.168.50.20
```

Inspect the server's capture for an incoming request that displays:

```text
ttl 42
```

<img width="1917" height="1023" alt="Screenshot 2026-10-27 170407" src="https://github.com/user-attachments/assets/7a94214c-6604-4672-aae7-bd1aa3653b1c" />


If the server receives a packet with TTL `42`, and the Python program logs changing that packet's TTL to `42`, this is evidence of the IPv4 header modification.

If the ping stops working, the server capture shows a different TTL, or the queue remains quiet, stop and troubleshoot before recording a successful result.

## 10. Evidence and Screenshots

Add your own screenshots to the report or repository. Recommended evidence:

- [ ] **Topology diagram** — client, server, attacker, their IP addresses, and the isolated VMware network.
- [ ] **VM configuration** — each VM's hostname, IP address, interface, and MAC address.
- [ ] **Baseline connectivity** — successful client-to-server and server-to-client pings.
- [ ] **Baseline capture** — ICMP packet and TTL before modification.
- [ ] **Program output** — Kali terminal showing `modify_ttl.py` and the TTL change log.
- [ ] **Firewall queue rule** — `iptables` output and its packet counter.
- [ ] **Modified packet** — server-side `tcpdump` output showing the observed TTL.
- [ ] **After-test connectivity** — ping results, if the traffic remained functional.

Use the actual values from your captures; do not present expected values as measured results.

## 11. Results

Fill in this table after running the experiment.

| Measurement | Observed result |
|---|---|
| Baseline TTL | `64` |
| TTL set by the program | `42` |
| TTL observed at server | `42` |
| Did the program log modified packets? | `Yes` |
| Did the server receive TTL 42? | `Yes` |
| Did ping succeed during the test? | `Yes` |

## 12. Explanation for the Report

> I implemented a Python packet-processing program using Scapy and NetfilterQueue. The program inspected forwarded ICMP echo requests from the client (`192.168.50.10`) to the server (`192.168.50.20`). For matching packets, it changed the IPv4 Time to Live (TTL) field to `42`, recalculated the IPv4 header checksum, and allowed the modified packet to continue to its destination. I checked the program's output and captured incoming ICMP requests on the server to verify the result. The observed original TTL was **64**, and the TTL recorded at the server was **42**. The ping test **successful**.

## 13. Clean Up

Stop the Python program with `Ctrl+C`.

Remove the specific queue rule:

```bash
sudo iptables -D FORWARD \
  -s 192.168.50.10 \
  -d 192.168.50.20 \
  -p icmp --icmp-type echo-request \
  -j NFQUEUE --queue-num 1
```

If you enabled IP forwarding solely for this experiment, disable it:

```bash
sudo sysctl -w net.ipv4.ip_forward=0
```

Stop any ARP-spoofing processes used in the lab. Restore normal neighbor entries on the client and server, then verify ordinary connectivity.

## 14. Limitations

- The program only modifies selected IPv4 ICMP echo requests.
- It requires the relevant packets to traverse Kali and enter the configured Netfilter queue.
- Capturing packets on Kali does not automatically mean Kali is in the communication path.
- TTL values may differ before the program processes a packet due to normal routing behavior.
- The result must be verified using the program's output and the receiving server's packet capture.
