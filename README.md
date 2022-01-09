# ICMP DDoS Mitigation with eBPF XDP

## Environment
```
$ uname -a
Linux thinkpad-t480 5.4.0-91-generic #102~18.04.1-Ubuntu SMP Thu Nov 11 14:46:36 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
```
```
$ lsb_release -a
No LSB modules are available.
Distributor ID: Ubuntu
Description:    Ubuntu 18.04.6 LTS
Release:        18.04
Codename:       bionic
```

## Prerequisites
Install toolchain and bpf related library on Ubuntu system
```
$ sudo apt install clang llvm libelf-dev libpcap-dev gcc-multilib build-essential
$ sudo apt install linux-tools-$(uname -r)
$ sudo apt install linux-headers-$(uname -r)
$ sudo apt install linux-tools-common linux-tools-generic
```

## eBPF XDP Packet Processing
![mechanism.png](http://i.imgur.com/ELy79Lu.png)

## ICMP DDoS Scenario
![scenario.png](http://i.imgur.com/gMcubNI.png)

## How to run
0. Create the experiment environment
```bash
$ sudo testenv/testenv.sh setup --name dos --legacy-ip
```
1. Compile the eBPF program
```bash
$ make
```
2. Load the eBPF program on the virtual interface (veth0)
```bash
$ sudo testenv/testenv.sh load
```
3. Visualize the eBPF map in userspace
```bash
$ sudo testenv/testenv.sh stats
```
4. Create normal ICMP flow (Terminal 1)
```bash
$ sudo ip netns exec dos /bin/bash
$ ping 10.11.1.1
```
5. Create ICMP flooding flow (Terminal 2)
```bash
$ sudo ip netns exec dos /bin/bash
$ hping3 -q -n -d 200 --icmp --flood 10.11.1.1
```
You should see that the icmp response in terminal 1 becomes unresponsive because ICMP DDoS mitigation.

6. Unload the eBPF program from the virtual interface (veth0)
```bash
$ sudo testenv/testenv.sh unload
```
