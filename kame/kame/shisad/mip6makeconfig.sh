#!/bin/sh
#
# $KAME: mip6makeconfig.sh,v 1.1 2004/12/09 02:18:42 t-momose Exp $

cat=/bin/cat
basename=/usr/bin/basename

if [ -r /etc/defaults/rc.conf ]; then
	. /etc/defaults/rc.conf
fi
if [ -r /etc/rc.conf ]; then
	. /etc/rc.conf
fi

ipv6_mobile_config_dir=${ipv6_mobile_config_dir:-/usr/local/v6/etc/mobileip6}

args=`getopt l $*`
if [ $? -ne 0 ]; then
	${cat} <<EOF
Usage: ${0} [-l] node_dir

	The default config directory is ${ipv6_mobile_config_dir}.
	each node_dir must reside in this directory.  This value can
	be changed by modifing ipv6_mobile_config_dir variable in
	/etc/rc.conf.

	-l	This option should be used when you use a mobile node 
		that is a recent USAGI derived Mobile IPv6 implementation.
EOF
	exit 1
fi

tunnel_upperspec='135'

set -- $args
for i do
	case "$i"
	in
		-l)
			tunnel_upperspec='any'
			shift;;
		--)
			shift;
			break;;
	esac
done

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
	transport_protocol='ah'
	transport_autharg='-A'
	transport_esparg=''
	transport_esp_algorithm=''
	transport_esp_secret=''
else
	transport_protocol='esp'
	transport_esparg='-E'
	if [ "X${transport_auth_algorithm}" = 'X' ]; then
		transport_autharg=''
		transport_auth_secret=''
	else
		transport_autharg='-A'
	fi
fi

if [ "X${tunnel_protocol}" = 'Xah' ]; then
	tunnel_protocol='ah'
	tunnel_autharg='-A'
	tunnel_esparg=''
	tunnel_esp_algorithm=''
	tunnel_esp_secret=''
else
	tunnel_protocol='esp'
	tunnel_esparg='-E'
	if [ "X${tunnel_auth_algorithm}" = 'X' ]; then
		tunnel_autharg=''
		tunnel_auth_secret=''
	else
		tunnel_autharg='-A'
	fi
fi

#
# write security association configuration files
#

#
# SA addition
#
${cat} << EOF | sed '/^[[:space:]]*$/d' > ${node_dir}/add
add ${mobile_node} ${home_agent}
	${transport_protocol} ${transport_spi_mn_to_ha}
	-m transport
	${transport_esparg} ${transport_esp_algorithm} ${transport_esp_secret}
	${transport_autharg} ${transport_auth_algorithm} ${transport_auth_secret};
add ${home_agent} ${mobile_node}
	${transport_protocol} ${transport_spi_ha_to_mn}
	-m transport
	${transport_esparg} ${transport_esp_algorithm} ${transport_esp_secret}
	${transport_autharg}  ${transport_auth_algorithm} ${transport_auth_secret};
add ${mobile_node} ${home_agent}
	${tunnel_protocol} ${tunnel_spi_mn_to_ha}
	-m tunnel
	-u  ${tunnel_uid_mn_to_ha}
	${tunnel_esparg} ${tunnel_esp_algorithm} ${tunnel_esp_secret}
	${tunnel_autharg} ${tunnel_auth_algorithm} ${tunnel_auth_secret};
add ${home_agent} ${mobile_node}
	${tunnel_protocol} ${tunnel_spi_ha_to_mn}
	-m tunnel
	-u ${tunnel_uid_ha_to_mn}
	${tunnel_esparg} ${tunnel_esp_algorithm} ${tunnel_esp_secret}
	${tunnel_autharg} ${tunnel_auth_algorithm} ${tunnel_auth_secret};
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
	${tunnel_protocol} ${tunnel_spi_mn_to_ha};
delete ${home_agent} ${mobile_node}
	${tunnel_protocol} ${tunnel_spi_ha_to_mn};
EOF

#
# write security policy configuration files
#

#
# policy addition of a home agent
#
${cat} <<EOF > ${node_dir}/spdadd_home_agent
spdadd ${home_agent} ${mobile_node}
	135 -P out ipsec
	${transport_protocol}/transport//require;
spdadd ${mobile_node} ${home_agent}
	135 -P in ipsec
	${transport_protocol}/transport//require;
EOF

#
# policy deletion of a home agent
#
${cat} <<EOF > ${node_dir}/spddelete_home_agent
spddelete ${home_agent} ${mobile_node}
	135 -P out;
spddelete ${mobile_node} ${home_agent}
	135 -P in;
EOF

#
# tunnel policy addtion of a home agent
#
${cat} <<EOF >> ${node_dir}/spdadd_home_agent
spdadd ::/0 ${mobile_node}
	${tunnel_upperspec} -P out ipsec
	esp/tunnel/${home_agent}-${mobile_node}/unique:${tunnel_uid_ha_to_mn};
spdadd ${mobile_node} ::/0
	${tunnel_upperspec} -P in ipsec
	esp/tunnel/${mobile_node}-${home_agent}/unique:${tunnel_uid_mn_to_ha};
EOF

#
# tunnel policy deletion of a home agent
#
${cat} <<EOF >> ${node_dir}/spddelete_home_agent
spddelete ::/0 ${mobile_node}
	${tunnel_upperspec} -P out;
spddelete ${mobile_node} ::/0
	${tunnel_upperspec} -P in;
EOF

#
# policy addition of a mobile node
#
${cat} <<EOF > ${node_dir}/spdadd_mobile_node
spdadd ${mobile_node} ${home_agent}
	135 -P out ipsec
	${transport_protocol}/transport//require;
spdadd ${home_agent} ${mobile_node}
	135 -P in ipsec
	${transport_protocol}/transport//require;
EOF

#
# policy deletion of a mobile node
#
${cat} <<EOF > ${node_dir}/spddelete_mobile_node
spddelete ${mobile_node} ${home_agent}
	135 -P out;
spddelete ${home_agent} ${mobile_node}
	135 -P in;
EOF

#
# tunnel policy addition of a mobile node
#
${cat} <<EOF >> ${node_dir}/spdadd_mobile_node
spdadd ${mobile_node} ::/0
	135 -P out ipsec
	esp/tunnel/${mobile_node}-${home_agent}/unique:${tunnel_uid_mn_to_ha};
spdadd ::/0 ${mobile_node}
	135 -P in ipsec
	esp/tunnel/${home_agent}-${mobile_node}/unique:${tunnel_uid_ha_to_mn};
EOF

#
# tunnel policy deletion of a mobile node
#
${cat} <<EOF >> ${node_dir}/spddelete_mobile_node
spddelete ${mobile_node} ::/0
	135 -P out;
spddelete ::/0 ${mobile_node}
	135 -P in;
EOF
