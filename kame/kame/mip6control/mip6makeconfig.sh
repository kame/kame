#!/bin/sh
#
# $Id: mip6makeconfig.sh,v 1.2 2002/12/04 05:39:05 keiichi Exp $

cat=/bin/cat
basename=/usr/bin/basename

if [ -r /etc/defaults/rc.conf ]; then
	. /etc/defaults/rc.conf
fi
if [ -r /etc/rc.conf ]; then
	. /etc/rc.conf
fi

if [ $# -ne 1 ]; then
	${cat} <<EOF
Usage: ${0} node_dir

	The default config directory is ${ipv6_mobile_config_dir}.
	each node_dir must reside in this directory.  This value can
	be changed by modifing ipv6_mobile_config_dir variable in
	/etc/rc.conf.
EOF
	exit 1
fi

ipv6_mobile_config_dir=${ipv6_mobile_config_dir:-/usr/local/v6/etc/mobileip6}

#
# check node_dir
#
if [ ! -d ${ipv6_mobile_config_dir}/${1} ]; then
	cat << EOF
No configuration directory for the node ${1}.
EOF
	exit 1
fi
node_dir=${ipv6_mobile_config_dir}/${1}

#
# source parameters
#
. ${node_dir}/config

#
# write security association configuration files
#

#
# SA addition
#
${cat} << EOF > ${node_dir}/add
add ${mobile_node} ${home_agent}
	esp ${spi_mn_to_ha} -E ${algorithm} "${secret}";
add ${home_agent} ${mobile_node}
	esp ${spi_ha_to_mn} -E ${algorithm} "${secret}";
EOF

#
# SA deletion
#
${cat} << EOF > ${node_dir}/delete
delete ${mobile_node} ${home_agent}
	esp ${spi_mn_to_ha};
delete ${home_agent} ${mobile_node}
	esp ${spi_ha_to_mn};
EOF

#
# write security policy configuration files
#

#
# policy addition of a home agent
#
${cat} <<EOF > ${node_dir}/spdadd_home_agent
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
${cat} <<EOF > ${node_dir}/spddelete_home_agent
spddelete ${home_agent} ${mobile_node}
	62 -P out ipsec;
spddelete ${mobile_node} ${home_agent}
	62 -P in ipsec;
EOF

#
# tunnel policy addtion of a home agent
#
${cat} <<EOF >> ${node_dir}/spdadd_home_agent
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
${cat} <<EOF >> ${node_dir}/spddelete_home_agent
spddelete ::/0 ${mobile_node}
	62 -P out ipsec;
spddelete ${mobile_node} ::/0
	62 -P in ipsec;
EOF

#
# policy addition of a mobile node
#
${cat} <<EOF > ${node_dir}/spdadd_mobile_node
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
${cat} <<EOF > ${node_dir}/spddelete_mobile_node
spddelete ${mobile_node} ${home_agent}
	62 -P out ipsec;
spddelete ${home_agent} ${mobile_node}
	62 -P in ipsec;
EOF

#
# tunnel policy addition of a mobile node
#
${cat} <<EOF >> ${node_dir}/spdadd_mobile_node
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
${cat} <<EOF >> ${node_dir}/spddelete_mobile_node
spddelete ${mobile_node} ::/0
	62 -P out ipsec;
spddelete ::/0 ${mobile_node}
	62 -P in ipsec;
EOF
