#!/bin/sh
#
# $Id: mip6makeconfig.sh,v 1.4 2003/09/30 12:37:16 keiichi Exp $

cat=/bin/cat
basename=/usr/bin/basename

if [ -r /etc/defaults/rc.conf ]; then
	. /etc/defaults/rc.conf
fi
if [ -r /etc/rc.conf ]; then
	. /etc/rc.conf
fi

ipv6_mobile_config_dir=${ipv6_mobile_config_dir:-/usr/local/v6/etc/mobileip6}

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
# set other auto configurable parameters
#
if [ "X${transport_protocol}" = 'Xah' ]; then
	transport_esparg=''
	transport_esp_algorithm=''
	transport_esp_secret=''
else
	transport_esparg='-E'
	transport_esp_secret=\"${transport_esp_secret}\"
fi
transport_auth_secret=\"${transport_auth_secret}\"
tunnel_auth_secret=\"${tunnel_auth_secret}\"
tunnel_esp_secret=\"${tunnel_esp_secret}\"

#
# write security association configuration files
#

#
# SA addition
#
${cat} << EOF > ${node_dir}/add
add ${mobile_node} ${home_agent}
	${transport_protocol} ${transport_spi_mn_to_ha}
	-m transport
	${transport_esparg} ${transport_esp_algorithm} ${transport_esp_secret}
	-A ${transport_auth_algorithm} ${transport_auth_secret};
add ${home_agent} ${mobile_node}
	${transport_protocol} ${transport_spi_ha_to_mn}
	-m transport
	${transport_esparg} ${transport_esp_algorithm} ${transport_esp_secret}
	-A ${transport_auth_algorithm} ${transport_auth_secret};
add ${mobile_node} ${home_agent}
	esp ${tunnel_spi_mn_to_ha}
	-m tunnel
	-u  ${tunnel_uid_mn_to_ha}
	-E ${tunnel_esp_algorithm} ${tunnel_esp_secret}
	-A ${tunnel_auth_algorithm} ${tunnel_auth_secret};
add ${home_agent} ${mobile_node}
	esp ${tunnel_spi_ha_to_mn}
	-m tunnel
	-u ${tunnel_uid_ha_to_mn}
	-E ${tunnel_esp_algorithm} ${tunnel_esp_secret}
	-A ${tunnel_auth_algorithm} ${tunnel_auth_secret};
EOF

#
# SA deletion
#
${cat} << EOF > ${node_dir}/delete
delete ${mobile_node} ${home_agent}
	${transport_protocol} ${transport_spi_mn_to_ha};
delete ${home_agent} ${mobile_node}
	${transport_protocol} ${transport_spi_ha_to_mn};
delete ${mobile_node} ${home_agent}
	esp ${tunnel_spi_mn_to_ha};
delete ${home_agent} ${mobile_node}
	esp ${tunnel_spi_ha_to_mn};
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
	${transport_protocol}/transport//require;
spdadd ${mobile_node} ${home_agent}
	62 -P in ipsec
	${transport_protocol}/transport//require;
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
	esp/tunnel/${home_agent}-${mobile_node}/unique:${tunnel_uid_ha_to_mn};
spdadd ${mobile_node} ::/0
	62 -P in ipsec
	esp/tunnel/${mobile_node}-${home_agent}/unique:${tunnel_uid_mn_to_ha};
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
	${transport_protocol}/transport//require;
spdadd ${home_agent} ${mobile_node}
	62 -P in ipsec
	${transport_protocol}/transport//require;
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
	esp/tunnel/${mobile_node}-${home_agent}/unique:${tunnel_uid_mn_to_ha};
spdadd ::/0 ${mobile_node}
	62 -P in ipsec
	esp/tunnel/${home_agent}-${mobile_node}/unique:${tunnel_uid_ha_to_mn};
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
