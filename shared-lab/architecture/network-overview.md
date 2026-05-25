## Global Overview

The SOC Lab requires 2 endpoints, Ubuntu and Windows, a monitoring machine and a machine hosting the SIEM.
The monitoring machine's main role is to capture the ongoing traffic on the internal network.

The endpoints and the monitoring machine are Virtual Machines, set using Virtual Box. The SIEM is hosted by the host machine, and receives the logs forwarded by the endpoints and the monitoring machine.
The attacks are simulated from a Kali Linux Virtual Machine.

Each VM is connected to 2 networks:
- Adapter 1: Network from the Bridged Adapter
- Adapter 2: Internal Network, only for the VMs

The goals of this architecture are:
- to create a SOC-like environment
- to separate internet traffic from internal traffic
- to centralize monitoring and log collection
- to simulate realistic attacks and logs

## Ubuntu Endpoint setup
- Open the network configuration file: 
`$ sudo vim /etc/netplan/01-network-manager-all.yaml`

- Configure both network interfaces:
```
network:
  version: 2
  renderer: NetworkManager

  ethernets:
    enp0s3:
      dhcp4: true

    enp0s8:
      dhcp4: false
      addresses:
        - 10.10.10.2/24
```

- Apply the changes and reboot if needed:
`$ sudo netplan apply`

## Windows Endpoint setup

The Ethernet interface does not require additional configuration.

For the Ethernet2 interface:
- Search for `npa.cpl` to open the network configuration
- Go to Ethernet 2 > Properties > Internet Protocol version 4 > - Use the following address: `10.10.10.3`
- Mask: `255.255.255.0`
- Default gateway: leave empty

## Set up Kali Attacker Machine
- Open the network interfaces configuration file:
`$ sudo vim /etc/network/interfaces`
- Configure both network interfaces:
```
auto lo
iface lo inet loopback

auto eth1
iface eth1 inet static
        address 10.10.10.1
        netmask 255.255.255.0

auto eth0
iface eth0 inet dhcp
```
- Apply the changes: `$ sudo systemctl restart networking`


## Monitoring Machine setup

- To allow the monitoring machine to listen on the internal network between the endpoints and the attacker machine, all VMs need the property `Promiscuous Mode` to be set to `Allow All`. This is required to allow packet capture on the internal network.
- The network configuration is the same as the Ubuntu Endpoint, with `10.10.10.4` for the internal network address


## Configuration checks:

- Each VM should have Internet access
- The command `ip route` gives the default interface, and the interface for the internal network
- Each VM is able to ping others through the bridged network, for example in order to ping the Ubuntu endpoint from Kali:
`$ ping 192.168.1.160`
- Each VM is able to ping others through the internal network, for example in order to ping the Ubuntu endpoint from Kali: `$ ping -I eth1 10.10.10.2`

To check that the Monitoring VM is able to see the traffic between other VMs:
- Start capturing traffic on the Monitoring machine: `$ sudo tcpdump -i enp0s8`
- Start the Ubuntu endpoint
- Ping the Ubuntu endpoint from the Windows endpoint on the local network: 
`$ ping 10.10.10.2 -S 10.10.10.3`
- The traffic captured by the monitoring machine should show the corresponding ICMP packets