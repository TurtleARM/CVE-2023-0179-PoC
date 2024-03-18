#!/bin/sh

# create the peer virtual device
ip link add eth0 type veth peer name host-enp3s0
ip link set host-enp3s0 up
ip link set eth0 up
ip addr add 192.168.137.137/24 dev host-enp3s0
# add two vlans on top of it
ip link add link host-enp3s0 name vlan.5 type vlan id 5
ip link add link vlan.5 name vlan.10 type vlan id 10
ip addr add 192.168.147.137/24 dev vlan.10
ip link set vlan.5 up
ip link set vlan.10 up
ip link set lo up