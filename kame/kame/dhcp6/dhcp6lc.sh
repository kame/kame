#!/bin/sh

#
# Sample script to display the information via dhcpv6-lite handshake.
# To reflect these information to the actual configuration of the node,
# you have to customize this script.
#

echo "domain-name = ${new_domain_name}"
echo "domain-name-server = ${new_domain_name_servers}"
echo "ntp-server = ${new_ntp_servers}"
