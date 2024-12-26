# NÃO ESQUECER DE METER O SETUP!!!

## Task 1.1 - Sniffing Packets

In this task, we want to learn how to sniff packets, using the Scapy library from Python.

### Task 1.1A.

Along this task, we want to sniff packets transmitted to and from the hostA and hostB containers, from the seed-attacker container.

To start sniffing packets from the network, we first need to find our docker network interface (e.g., using `ifconfig`, which is, in our case, `br-87824c9e582a`), and then we can build the following script:

```py
#!/usr/bin/env python3

from scapy.all import *

def print_pkt(pkt):
    pkt.show()

pkt = sniff(iface='br-87824c9e582a', filter='icmp', prn=print_pkt)
```

This script will sniff all packets from the network interface `br-87824c9e582a` that are ICMP packets, and will print them to the console.

To see this script in action, we can start a shell inside the seed-attacker container (using `docksh <container-ID>`), give the script execution permissions (using `chmod a+x sniffer.py`) and run it (`sniffer.py`). From there, we can ping hostB from hostA (using `ping 10.9.0.6`) and, as we will see, the script will print the packets that are being transmitted, like the one presented below:

<p align="center" justify="center">
  <img src="./assets/LOGBOOK13/sniff.png">
</p>

This packet presents information of four different layers:

- Ethernet: Contains information needed for transmitting information in a network at a more physical level, like the source and destination MAC addresses.
- IP: Contains information needed for transmitting information in a network at a more logical level, like the source and destination IP addresses, for operations like logical addressing and routing.
- ICMP: Holds information characteristic of ICMP (Internet Control Message Protocol) packets, used network diagnostics and error reporting.
- Raw: Contains the raw data of the packet.

One thing to note is that the the Scapy library makes use of privileged operations. If we try to run the script as a normal user inside the container, it will fail due to permission errors.

<p align="center" justify="center">
  <img src="./assets/LOGBOOK13/failed-<p align="center" justify="center">
  <img src="./assets/LOGBOOK13/sniff.png">
</p>sniff.png">
</p>

### Task 1.1B.

This part of the task focuses on using BPF (Berkeley Packet Filter) filters to better filter sniffed packets, which is useful in real contexts.

To better use BPF filters, we can check their specification in the [IBM BPF manual](https://www.ibm.com/docs/en/qsip/7.4?topic=queries-berkeley-packet-filters). To test them, we also need to know how we can generate and send packets using Scapy, which can be done using the `send()` function (to send the packet) and the `/` operator (to concatenate layers, generated using object-oriented notation), as wee can see from the [Scapy documentation](https://scapy.readthedocs.io/en/latest/usage.html#sending-packets).

The usage of BPF filters is illustrated in the following script, adapted from the previous one and that can be used like `sniffer.py [ICMP|TCP|SUBNET]`:

```py
#!/usr/bin/env python3
from scapy.all import *
import sys

def print_pkt(pkt):
    pkt.show()

def capture_icmp(iface):
    pkt = sniff(iface=iface, filter='icmp', prn=print_pkt)

def capture_tcp(iface, ip):
    pkt = sniff(iface=iface, filter=f'tcp dst port 23 and src host {ip}', prn=print_pkt)

def capture_subnet(iface, subnet):
    pkt = sniff(iface=iface, filter=f'net {subnet}', prn=print_pkt)

def main():
    iface = 'br-87824c9e582a'

    if len(sys.argv) != 2:
        print("Usage: sniffer.py [ICMP|TCP|SUBNET]")
        exit(1)

    if sys.argv[1] == 'ICMP':
        capture_icmp(iface)
    elif sys.argv[1] == 'TCP':
        capture_tcp(iface, '10.9.0.5')
    elif sys.argv[1] == 'SUBNET':
        capture_subnet(iface, '10.9.0.0/24')
    else:
        print("Usage: sniffer.py [ICMP|TCP|SUBNET]")
        exit(1)

if __name__ == '__main__':
    main()
```

- The example originally presented already filters ICMP packets (using `icmp`), which is done if we run this script using the `ICMP` option. If we generate a packet using `send(IP(dst='10.9.0.6')/ICMP())`, it will be captured by the script. However, a TCP packet, for example (generated using `send(IP(dst='10.9.0.6')/TCP())`), will not be captured.

- To filter TCP packets that come from a particular IP (in our case, `10.9.0.6`) and with a destination port number 23, we can use the filter `tcp dst port 23 and src host 10.9.0.6`. We can see this working by generating a packet using `send(IP(dst='10.9.0.6')/TCP(dport=23))` (but not with `send(IP(dst='10.9.0.6')/TCP(dport=21))`, for example)

- To filter packets that come from or go to a particular subnet (we will be using `10.9.0.0/24`), we can use the filter `net 10.9.0.0/24`. If we generate packets from or to the subnetwork (like any un-spoofed packet generated from hostA), they will be captured by the script. A packet generated using `send(IP(src='10.9.1.5', dst='10.9.1.6')/ICMP())` will not appear in the console, however, since neither the destination nor the source are from the subnetwork.