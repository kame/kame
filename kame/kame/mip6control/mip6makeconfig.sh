#!/bin/sh
#
# $Id: mip6makeconfig.sh,v 1.1 2002/12/03 14:02:42 keiichi Exp $

cat=/bin/cat
basename=/usr/bin/basename

if [ -r /etc/defaults/rc.conf ]; then
	. /etc/defaults/rc.conf
	source_rc_confs
elif [ -r /etc/rc.conf ]; then
	. /etc/rc.conf
fi

if [ $# -ne 1 ]; then
	${cat} <<EOF
Usage: ${0} node_dir

	node_dir must be consist of 5 digits.  This value is used as a
	SPI number.  Because we need 2 SPIs for one bi-directional
	connection, the number 'node_dir + 1' is reserved for internal
	use.  If you have multiple node_dir, you must skip at least 1
	when creating a new node_dir.

	The default config directory is ${ipv6_mobile_config_dir}.
	This value can be changed by modifing ipv6_mobile_config_dir
	variable in /etc/rc.conf.
EOF
	exit 1
fi

ipv6_mobile_config_dir=${ipv6_mobile_config_dir:-/usr/local/v6/etc/mobileip6}

#
# source parameters
#
client=${ipv6_mobile_config_dir}/${1}
. ${client}/config

#
# determine SPIs
#
spi_mn=$((`${basename} ${client}`))
spi_ha=$((${spi_mn} + 1))

#
# write security association configuration files
#

#
# SA addition
#
${cat} << EOF > ${client}/add
add ${mobile_node} ${home_agent}
	esp ${spi_mn} -E ${algorithm} "${secret}";
add ${home_agent} ${mobile_node}
	esp ${spi_ha} -E ${algorithm} "${secret}";
EOF

#
# SA deletion
#
${cat} << EOF > ${client}/delete
delete ${mobile_node} ${home_agent}
	esp ${spi_mn};
delete ${home_agent} ${mobile_node}
	esp ${spi_ha};
EOF

#
# write security policy configuration files
#

#
# policy addition of a home agent
#
${cat} <<EOF > ${client}/spdadd_home_agent
spdadd ${home_agent} ${mobile_node}
	62 -P out ipsec
	esp/transport//require;
spdadd ${mobile_node} ${home_agent}
	62 -P in ipsec
	esp/transport//require;
EOF

#
# policy deletion of a home agent
#
${cat} <<EOF > ${client}/spddelete_home_agent
spddelete ${home_agent} ${mobile_node}
	62 -P out ipsec;
spddelete ${mobile_node} ${home_agent}
	62 -P in ipsec;
EOF

#
# tunnel policy addtion of a home agent
#
${cat} <<EOF >> ${client}/spdadd_home_agent
spdadd ::/0 ${mobile_node}
	62 -P out ipsec
	esp/tunnel/${home_agent}-${mobile_node}/require;
spdadd ${mobile_node} ::/0
	62 -P in ipsec
	esp/tunnel/${mobile_node}-${home_agent}/require;
EOF

#
# tunnel policy deletion of a home agent
#
${cat} <<EOF >> ${client}/spddelete_home_agent
spddelete ::/0 ${mobile_node}
	62 -P out ipsec;
spddelete ${mobile_node} ::/0
	62 -P in ipsec;
EOF

#
# policy addition of a mobile node
#
${cat} <<EOF > ${client}/spdadd_mobile_node
spdadd ${mobile_node} ${home_agent}
	62 -P out ipsec
	esp/transport//require;
spdadd ${home_agent} ${mobile_node}
	62 -P in ipsec
	esp/transport//require;
EOF

#
# policy deletion of a mobile node
#
${cat} <<EOF > ${client}/spddelete_mobile_node
spddelete ${mobile_node} ${home_agent}
	62 -P out ipsec;
spddelete ${home_agent} ${mobile_node}
	62 -P in ipsec;
EOF

#
# tunnel policy addition of a mobile node
#
${cat} <<EOF >> ${client}/spdadd_mobile_node
spdadd ${mobile_node} ::/0
	62 -P out ipsec
	esp/tunnel/${mobile_node}-${home_agent}/require;
spdadd ::/0 ${mobile_node}
	62 -P in ipsec
	esp/tunnel/${home_agent}-${mobile_node}/use;
EOF

#
# tunnel policy deletion of a mobile node
#
${cat} <<EOF >> ${client}/spddelete_mobile_node
spddelete ${mobile_node} ::/0
	62 -P out ipsec;
spddelete ::/0 ${mobile_node}
	62 -P in ipsec;
EOF
