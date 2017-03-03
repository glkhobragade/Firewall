#!/bin/bash
## configure the firewall rules to prevent the network attacks:
## If possible, combine the rules which are similar.

IPTABLES="/sbin/iptables"

## Flush all the rule chain:
 $IPTABLES -F INPUT
 $IPTABLES -F OUTPUT
 $IPTABLES -F FORWARD
 $IPTABLES -F ICMP_INGRESS
 $IPTABLES -F ICMP_EGRESS
 $IPTABLES -F LOGGING

## Deleting the use defined chains:
 $IPTABLES -X ICMP_INGRESS
 $IPTABLES -X ICMP_EGRESS
 $IPTABLES -X LOGGING

## accept the localhost traffic ==
$IPTABLES -A INPUT -i lo -j ACCEPT
$IPTABLES -A OUTPUT -o lo -j ACCEPT

## drop policy for iptables chains
echo "Set default policy for chain to 'DROP'"

$IPTABLES -P INPUT   DROP
$IPTABLES -P FORWARD DROP
$IPTABLES -P OUTPUT  DROP

$IPTABLES -N ICMP_INGRESS
$IPTABLES -N ICMP_EGRESS

$IPTABLES -N LOGGING


## ICMP traffic redirecting to chain ==
$IPTABLES -A INPUT -p icmp -j ICMP_INGRESS
$IPTABLES -A OUTPUT -p icmp -j ICMP_EGRESS

## allow HTTP(S) traffic:
## As a server:==
iptables -A INPUT   -p tcp -m multiport --dports 80,443 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT  -p tcp -m multiport --sports 80,443 -m state --state NEW,ESTABLISHED -j ACCEPT

## As a client:==
iptables -A INPUT   -p tcp -m multiport --sports 80,443 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT  -p tcp -m multiport --dports 80,443 -m state --state NEW,ESTABLISHED -j ACCEPT

## SSH traffic: Do we have to allow this traffic, this may be dangerous.==
#so this rule should be very restrictive, we can add more tuples to make the rule more stringent.
# Serve==
$IPTABLES -A INPUT  -p tcp --dport 22 -j ACCEPT
$IPTABLES -A OUTPUT -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT


## Client ==
$IPTABLES -A INPUT  -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT
$IPTABLES -A OUTPUT -p tcp --dport 22 -j ACCEPT


# check if the DUT is able to make the SSH connection, means if it can acts as a client.

## TELNET Traffic==
$IPTABLES -A INPUT  -p tcp --dport 23 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPTABLES -A OUTPUT -p tcp --sport 23 -m state --state ESTABLISHED -j ACCEPT


## FTP
## DUT act as a server ==
#$IPTABLES -A INPUT  -p tcp --dport 21 -m state --state NEW,ESTABLISHED -j ACCEPT
#$IPTABLES -A INPUT  -p tcp --dport 1024: -m state --state RELATED,ESTABLISHED -j ACCEPT

#$IPTABLES -A OUTPUT -p tcp --sport 21 -m state --state ESTABLISHED -j ACCEPT
#$IPTABLES -A OUTPUT -p tcp --sport 1024: -m state --state RELATED,ESTABLISHED -j ACCEPT


## DUT as a client:==
#$IPTABLES -A INPUT  -p tcp --sport 21 -m state --state ESTABLISHED -j ACCEPT
#$IPTABLES -A INPUT  -p tcp --sport 1024: -m state --state RELATED,ESTABLISHED -j ACCEPT

#$IPTABLES -A OUTPUT -p tcp --dport 21 -m state --state NEW,ESTABLISHED -j ACCEPT
#$IPTABLES -A OUTPUT -p tcp --dport 1024: -m state --state NEW,ESTABLISHED -j ACCEPT

## Allowing DNS lookups (tcp, udp port 53) to server ip (DNS server IP if known)
## Server: ==
$IPTABLES -A OUTPUT -p udp --dport 53 -j ACCEPT
$IPTABLES -A OUTPUT -p tcp --dport 53 -j ACCEPT
$IPTABLES -A INPUT  -p udp --sport 53 -j ACCEPT
$IPTABLES -A INPUT  -p tcp --sport 53 -j ACCEPT

## client: ==
$IPTABLES -A OUTPUT -p udp --sport 53 -j ACCEPT
$IPTABLES -A OUTPUT -p tcp --sport 53 -j ACCEPT
$IPTABLES -A INPUT  -p udp --dport 53 -j ACCEPT
$IPTABLES -A INPUT  -p tcp --dport 53 -j ACCEPT


#DHCP traffic allowed:===
$IPTABLES -A INPUT -p udp --dport 67:68 --sport 67:68 -j ACCEPT
$IPTABLES -A OUTPUT -p udp --dport 67:68 --sport 67:68 -j ACCEPT


## Smurf attack:==
$IPTABLES -A ICMP_INGRESS -p icmp -m icmp --icmp-type 0 -m limit --limit 10/second  --limit-burst 10 -j ACCEPT
$IPTABLES -A ICMP_INGRESS -p icmp -m icmp --icmp-type 0 -j DROP
$IPTABLES -A ICMP_INGRESS -p icmp -m icmp --icmp-type 8 -m limit --limit 10/second  --limit-burst 10 -j ACCEPT
$IPTABLES -A ICMP_INGRESS -p icmp -m icmp --icmp-type 8 -j DROP
$IPTABLES -A ICMP_INGRESS -p icmp -m icmp --icmp-type 3 -m limit --limit 10/second --limit-burst 10 -j ACCEPT
$IPTABLES -A ICMP_INGRESS -p icmp -m icmp --icmp-type 3 -j DROP
$IPTABLES -A ICMP_INGRESS -p icmp -m icmp --icmp-type 11 -m limit --limit 10/second --limit-burst 10 -j ACCEPT
$IPTABLES -A ICMP_INGRESS -p icmp -m icmp --icmp-type 11 -j DROP
$IPTABLES -A ICMP_INGRESS -p icmp -m icmp --icmp-type 12 -m limit --limit 10/second --limit-burst 10 -j ACCEPT
$IPTABLES -A ICMP_INGRESS -p icmp -m icmp --icmp-type 12  -j DROP

$IPTABLES -A ICMP_EGRESS -p icmp -m icmp --icmp-type 0 -m limit --limit 10/second  --limit-burst 10 -j ACCEPT
$IPTABLES -A ICMP_EGRESS -p icmp -m icmp --icmp-type 0 -j DROP
$IPTABLES -A ICMP_EGRESS -p icmp -m icmp --icmp-type 8 -m limit --limit 10/second  --limit-burst 10 -j ACCEPT
$IPTABLES -A ICMP_EGRESS -p icmp -m icmp --icmp-type 8 -j DROP
$IPTABLES -A ICMP_EGRESS -p icmp -m icmp --icmp-type 3 -m limit --limit 10/second  --limit-burst 10 -j ACCEPT
$IPTABLES -A ICMP_EGRESS -p icmp -m icmp --icmp-type 3 -j DROP
$IPTABLES -A ICMP_EGRESS -p icmp -m icmp --icmp-type 11 -m limit --limit 10/second --limit-burst 10 -j ACCEPT
$IPTABLES -A ICMP_EGRESS -p icmp -m icmp --icmp-type 11 -j DROP
$IPTABLES -A ICMP_EGRESS -p icmp -m icmp --icmp-type 12 -m limit --limit 10/second --limit-burst 10 -j ACCEPT
$IPTABLES -A ICMP_EGRESS -p icmp -m icmp --icmp-type 12 -j DROP


## SYN Flood attack: we cant prevent this using the firewall filter  but we can limit those packets:
## limiting the packets in the new state.
$IPTABLES -A INPUT -p tcp -m state --state NEW -m limit --limit 10/second  --limit-burst 10 -j ACCEPT

## Fraggle Attack & Chargen attack:
#$IPTABLES -A INPUT -p udp –sport 7 -m limit --limit 10/second  --limit-burst 10 -j ACCEPT
$IPTABLES -A INPUT -p udp -m multiport --sports 7,19 -j DROP

## Allow IpSec Traffic:
iptables -A INPUT -p esp -j ACCEPT 
iptables -A INPUT -p ah -j ACCEPT

## Log the remaining packets:
iptables -A INPUT -j LOGGING
iptables -A OUTPUT -j LOGGING

## rules in the logging chain:
iptables -A LOGGING -m limit --limit 50/min -j LOG --log-prefix "Ghansham Dropped Packet:"
iptables -A LOGGING -j DROP

