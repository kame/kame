#!/bin/sh
#
# $KAME: mip6makeconfig.sh,v 1.2 2005/01/19 09:57:54 t-momose Exp $

cat=/bin/cat
basename=/usr/bin/basename
rm=/bin/rm

#
# write security association configuration files
#

remove_sa_conffiles()
{
	${rm} ${node_dir}/add 2> /dev/null
	${rm} ${node_dir}/delete 2> /dev/null
	${rm} ${node_dir}/spdadd_home_agent 2> /dev/null
	${rm} ${node_dir}/spddelete_home_agent 2> /dev/null
	${rm} ${node_dir}/spdadd_mobile_node 2> /dev/null
	${rm} ${node_dir}/spddelete_mobile_node 2> /dev/null
}

setconfvar()
{
	if eval [ "\"X\${$1}"\" != 'X' ]; then
		eval t_$1=\${$1}
	fi
	if eval [ "\"X\${$1_$2}"\" != 'X' ]; then
		eval t_$1=\${$1_$2}
		j=1
	fi
}

#
# SA addition
#
write_sa_conffiles()
{
if [ "${t_transport_protocol}" != "none" ]; then
${cat} << EOF | sed '/^[[:space:]]*$/d' >> ${node_dir}/add
add ${mobile_node} ${home_agent}
	${t_transport_protocol} ${t_transport_spi_mn_to_ha}
	-m transport
	${t_transport_esparg} ${t_transport_esp_algorithm} ${t_transport_esp_secret}
	${t_transport_autharg} ${t_transport_auth_algorithm} ${t_transport_auth_secret};
add ${home_agent} ${mobile_node}
	${t_transport_protocol} ${t_transport_spi_ha_to_mn}
	-m transport
	${t_transport_esparg} ${t_transport_esp_algorithm} ${t_transport_esp_secret}
	${t_transport_autharg}  ${t_transport_auth_algorithm} ${t_transport_auth_secret};
add ${mobile_node} ${home_agent}
	${t_tunnel_protocol} ${t_tunnel_spi_mn_to_ha}
	-m tunnel
	-u  ${t_tunnel_uid_mn_to_ha}
	${t_tunnel_esparg} ${t_tunnel_esp_algorithm} ${t_tunnel_esp_secret}
	${t_tunnel_autharg} ${t_tunnel_auth_algorithm} ${t_tunnel_auth_secret};
add ${home_agent} ${mobile_node}
	${t_tunnel_protocol} ${t_tunnel_spi_ha_to_mn}
	-m tunnel
	-u ${t_tunnel_uid_ha_to_mn}
	${t_tunnel_esparg} ${t_tunnel_esp_algorithm} ${t_tunnel_esp_secret}
	${t_tunnel_autharg} ${t_tunnel_auth_algorithm} ${t_tunnel_auth_secret};
EOF
fi

#
# SA deletion
#
if [ "${t_transport_protocol}" != "none" ]; then
${cat} << EOF >> ${node_dir}/delete
delete ${mobile_node} ${home_agent}
	${t_transport_protocol} ${t_transport_spi_mn_to_ha};
delete ${home_agent} ${mobile_node}
	${t_transport_protocol} ${t_transport_spi_ha_to_mn};
delete ${mobile_node} ${home_agent}
	${t_tunnel_protocol} ${t_tunnel_spi_mn_to_ha};
delete ${home_agent} ${mobile_node}
	${t_tunnel_protocol} ${t_tunnel_spi_ha_to_mn};
EOF
fi

#
# write security policy configuration files
#

#
# policy addition of a home agent
#
if [ "${t_transport_protocol}" = "none" ]; then
${cat} <<EOF >> ${node_dir}/spdadd_home_agent
spdadd ${home_agent} ${mobile_node}
	${t_transport_upperspec} -P out none;
spdadd ${mobile_node} ${home_agent}
	${t_transport_upperspec} -P in none;
EOF
else
${cat} <<EOF >> ${node_dir}/spdadd_home_agent
spdadd ${home_agent} ${mobile_node}
	${t_transport_upperspec} -P out ipsec
	${t_transport_protocol}/transport//require;
spdadd ${mobile_node} ${home_agent}
	${t_transport_upperspec} -P in ipsec
	${t_transport_protocol}/transport//require;
EOF
fi

#
# policy deletion of a home agent
#
${cat} <<EOF >> ${node_dir}/spddelete_home_agent
spddelete ${home_agent} ${mobile_node}
	${t_transport_upperspec} -P out;
spddelete ${mobile_node} ${home_agent}
	${t_transport_upperspec} -P in;
EOF

#
# tunnel policy addtion of a home agent
#
if [ "${t_tunnel_protocol}" != "none" ]; then
${cat} <<EOF >> ${node_dir}/spdadd_home_agent
spdadd ::/0 ${mobile_node}
	${t_tunnel_upperspec} -P out ipsec
	esp/tunnel/${home_agent}-${mobile_node}/unique:${t_tunnel_uid_ha_to_mn};
spdadd ${mobile_node} ::/0
	${t_tunnel_upperspec} -P in ipsec
	esp/tunnel/${mobile_node}-${home_agent}/unique:${t_tunnel_uid_mn_to_ha};
EOF
else
${cat} <<EOF >> ${node_dir}/spdadd_home_agent
spdadd ::/0 ${mobile_node}
	${t_tunnel_upperspec} -P out none;
spdadd ${mobile_node} ::/0
	${t_tunnel_upperspec} -P in none;
EOF
fi

#
# tunnel policy deletion of a home agent
#
${cat} <<EOF >> ${node_dir}/spddelete_home_agent
spddelete ::/0 ${mobile_node}
	${t_tunnel_upperspec} -P out;
spddelete ${mobile_node} ::/0
	${t_tunnel_upperspec} -P in;
EOF

#
# policy addition of a mobile node
#
if [ "${t_transport_protocol}" = "none" ]; then
${cat} <<EOF >> ${node_dir}/spdadd_mobile_node
spdadd ${mobile_node} ${home_agent}
	${t_transport_upperspec} -P out none;
spdadd ${home_agent} ${mobile_node}
	${t_transport_upperspec} -P in none;
EOF
else
${cat} <<EOF >> ${node_dir}/spdadd_mobile_node
spdadd ${mobile_node} ${home_agent}
	${t_transport_upperspec} -P out ipsec
	${t_transport_protocol}/transport//require;
spdadd ${home_agent} ${mobile_node}
	${t_transport_upperspec} -P in ipsec
	${t_transport_protocol}/transport//require;
EOF
fi

#
# policy deletion of a mobile node
#
${cat} <<EOF >> ${node_dir}/spddelete_mobile_node
spddelete ${mobile_node} ${home_agent}
	${t_transport_upperspec} -P out;
spddelete ${home_agent} ${mobile_node}
	${t_transport_upperspec} -P in;
EOF

#
# tunnel policy addition of a mobile node
#
if [ "${t_tunnel_protocol}" != "none" ]; then
${cat} <<EOF >> ${node_dir}/spdadd_mobile_node
spdadd ${mobile_node} ::/0
	${t_tunnel_upperspec} -P out ipsec
	esp/tunnel/${mobile_node}-${home_agent}/unique:${t_tunnel_uid_mn_to_ha};
spdadd ::/0 ${mobile_node}
	${t_tunnel_upperspec} -P in ipsec
	esp/tunnel/${home_agent}-${mobile_node}/unique:${t_tunnel_uid_ha_to_mn};
EOF
fi

#
# tunnel policy deletion of a mobile node
#
${cat} <<EOF >> ${node_dir}/spddelete_mobile_node
spddelete ${mobile_node} ::/0
	${t_tunnel_upperspec} -P out;
spddelete ::/0 ${mobile_node}
	${t_tunnel_upperspec} -P in;
EOF
}

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
transport_upperspec='135'

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
	${cat} << EOF
No configuration directory for the node ${1}.
EOF
	exit 1
fi
node_dir=${ipv6_mobile_config_dir}/${1}

#
# source parameters
#
. ${node_dir}/config

remove_sa_conffiles

i=1
while true; do
	j=0
	setconfvar transport_protocol $i
	setconfvar transport_upperspec $i
	setconfvar transport_spi_mn_to_ha $i
	setconfvar transport_spi_ha_to_mn $i
	setconfvar transport_esparg $i
	setconfvar transport_esp_algorithm $i
	setconfvar transport_esp_secret $i
	setconfvar transport_autharg $i
	setconfvar transport_auth_algorithm $i
	setconfvar transport_auth_secret $i
    
	setconfvar tunnel_protocol $i
	setconfvar tunnel_upperspec $i
	setconfvar tunnel_spi_mn_to_ha $i
	setconfvar tunnel_spi_ha_to_mn $i
	setconfvar tunnel_uid_mn_to_ha $i
	setconfvar tunnel_uid_ha_to_mn $i
	setconfvar tunnel_esparg $i
	setconfvar tunnel_esp_algorithm $i
	setconfvar tunnel_esp_secret $i
	setconfvar tunnel_autharg $i
	setconfvar tunnel_auth_algorithm $i
	setconfvar tunnel_auth_secret $i
    
#
# set other auto configurable parameters
#
	if [ "X${t_transport_protocol}" = 'Xah' ]; then
		t_transport_protocol='ah'
		t_transport_autharg='-A'
		t_transport_esparg=''
		t_transport_esp_algorithm=''
		t_transport_esp_secret=''
	elif [ "X${t_transport_protocol}" != 'Xnone' ]; then
		t_transport_protocol='esp'
		t_transport_esparg='-E'
		if [ "X${t_transport_auth_algorithm}" = 'X' ]; then
			t_transport_autharg=''
			t_transport_auth_secret=''
		else
			t_transport_autharg='-A'
		fi
	fi

	if [ "X${t_tunnel_protocol}" = 'Xah' ]; then
		t_tunnel_protocol='ah'
		t_tunnel_autharg='-A'
		t_tunnel_esparg=''
		t_tunnel_esp_algorithm=''
		t_tunnel_esp_secret=''
	elif [ "X${t_tunnel_protocol}" != 'Xnone' ]; then
		t_tunnel_protocol='esp'
		t_tunnel_esparg='-E'
		if [ "X${t_tunnel_auth_algorithm}" = 'X' ]; then
			t_tunnel_autharg=''
			t_tunnel_auth_secret=''
		else
			t_tunnel_autharg='-A'
		fi
	fi

	if [ $j -eq 0 -a $i -gt 1 ]; then
		break
	fi

	write_sa_conffiles

	if [ $j -eq 0 -a $i -eq 1 ]; then
		break
	fi
	i=`expr $i + 1`
done
