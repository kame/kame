                      DELIVERY NOTES FOR MOBILE IPv6
                      ==============================


1.0     INTRODUCTION

        The Mobile IPv6 implementation has been developed for the FreeBSD
        platform. It will be able to run the code on other platforms (NetBSD,
        OpenBSD and BSDi) in the future, but for the moment it's only possible
        to run the code on the FreeBSD platform (although the changes that
        have to be made to get the code running for the other platformes are
        small).

        The code is implemented as part of the kernel. In addition to this
        two applications for configuration of Mobile IPv6 and extracting
        statistics have been developed (mip6config and mip6stat). These
        applications resides in user space.

        The implementation follows draft-ietf-mobileip-ipv6-09.txt with
        some minor exceptions (see below for further information). The
        implementation includes the Correspondent Node part (mandatory for
        an IPv6 implementation that claims to be IPv6 compliant), the Home
        Agent node part and the Mobile Node part.

        Changes has been made to the ``tcpdump'' and the ``rtadvd''
        applications.



2.0     ORGANIZATION OF THE CODE

        The Mobile IPv6 code is located in different directories and files
        throughout the KAME file tree.

2.1     Kernel files

        At directory /usr/kame/kame/sys/netinet6 the following files have
        been added:
        
        - mip6.c         (Used when MIP6 option is activated)
        - mip6_io.c      (Used when MIP6 option is activated)
        - mip6_hooks.c   (Used when MIP6 option is activated)
        - mip6.h         (Used when MIP6 option is activated)
        - mip6_common.h  (Used when MIP6 option is activated)
        - mip6_mn.c      (Used when MIP6_MN option is activated)
        - mip6_md.c      (Used when MIP6_MN option is activated)
        - mip6_ha.c      (Used when MIP6_HA option is activated)
        
2.2     New and Modified Applications

        We have introduced two new applications for configuring of Mobile
        IPv6 and for retrieving statistical information.

        Please note that the Home Agent and Mobile Node code must be sepa-
        rately activated. They are not activated during the boot sequence.
        However, the Correspondent Node part of the Mobile IPv6 code is
        activated during the boot-up sequence.

2.2.1   Configuration of Mobile IPv6

        There are a number of configuration parameters that can be used for
        configuring the behaviour of Mobile IPv6. The ``mip6config'' 
        application holds all possible configuration options.

        The code has been placed in /usr/kame/kame/kame/mip6config.

        By typing ``mip6config -h'' all the available options are shown. At
        the moment only some of them are implemented (see below).

        A configuration example file exist at
        /usr/local/v6/etc/mip6.conf.sample

2.2.2   Statistical information from Mobile IPv6

        To view and clear internal lists that are created by Mobile IPv6 the
        ``mip6stat'' command is used. Different lists are used in different
        parts (Correspondent Node, Mobile Node and Home Agent) of the code
        and therefor some commands will be enabled or disabled respectively.

2.2.3   Changes to router advertisement deamon

        The router advertisement code (/usr/kame/kame/kame/rtadvd) has been
        changed according to the requirements for Mobile IPv6.

        Mobile IPv6 modifies the format of the Router Advertisement message
        by the addition of a single flag bit for use in the dynamic home
        agent address discovery. The Home Agent H-bit is set in a Router
        advertisement to indicate that the router sending this Router
        Advertisement is also functioning as a Mobile IP Home Agent.

        Mobile IPv6 requires knowledge of the router's global address and it
        therefor extends the Prefix Information option by the addition of a
        single flag bit. The Router Address (R-bit) indicates that the prefix
        field, in addition to advertising the indicated prefix, contains a
        complete IPv6 address assigned to the sending router.

        A new Advertisement Interval option, used in Router Advertisement
        messages to advertise the interval at which the sending router
        sends unsolicited multicast Router Advertisements, has been defined.

        A new Home Agent Information option, used in Router Advertisement
        sent by a Home Agent to advertise information specific to a routers
        functionality as a Home Agent, has been defined.

2.2.4   Changes to tcpdump

        The Mobile IPv6 destination options and the new options/flags in 
        Router Advertisements has been added. Sub-options in IPv6 was not
        implemented previously. The new features are only shown in verbose 
        (-v) mode.



3.0     PREPARATIONS BEFORE RUNNING MOBILE IPv6

3.1     Configuration of the kernel

        There exist five options in the kernel configuration file that are
        used for Mobile IPv6.

        options MIP6          Correspondent Node part is activated. This
                              must be enabled if Mobile IPv6 shall be used. 
        options MIP6_DEBUG    Add this if debugging shall be enabled later
                              using the ``mip6config'' command.
        options MIP6_MODULES  Enable this if the Mobile Node or Home Agent
                              code will be loaded as modules. Note that the
                              modules are not compiled by enabling this; only
                              support for later loading is enabled.
        options MIP6_HA       Enables Home Agent functionality statically in
                              the kernel.
        options MIP6_MN       Enables Mobile Node functionality statically in
                              the kernel.

        The following combinations of the options are possible.

                         Static Compilation              As Module
                      Mobile Node   Home Agent   Mobile Node   Home Agent
        MIP6                X           X              X           X
        MIP6_DEBUG          X           X              X           X
        MIP6_MODULES                                   X           X
        MIP6_HA                         X                          X
        MIP6_MN             X                          X

        It is not possible to have the Mobile Node and Home Agent code
        active at the same time.

        We recommend that the option MIP6_DEBUG is always included. This
        makes it easy to turn the debug printout on/off during execution.
        The printout is enabled/disabled by using the ``mip6config -d 1/0''
        command.

        We currently suggest that you disable ``options IPSEC'' in the 
        kernel, see below.

3.2     Setting up the Home Agent

        The Home Agent must enable routing functionality, i.e. set forwarding
        of IPv6 packets. In addition to this the Router Advertisements sent by
         the router daemon must be modified. This is done by changing the
         variables in the /usr/local/v6/etc/rtadvd.conf file.
        
        The following parameters should be added:
        hatime#100    # Home Agent lifetime
        hapref#10     # Home Agent preference

        The following parameters should be changed:
        raflags#<raflags | 0x20>        #Add H-bit to Router Advertisement
        pinfoflags#<pinfoflags | 0x20>  #Add R-bit to Prefix Information
        maxinterval#2          # Advertisement Interval option will be derived
                               # from Max Router Advertisement Interval used 
                               # in the daemon.
        addr="<prefix:id>"     # Routers Global unicast address

        Note:   ``MaxInterval'' option can be set lower than Neighbor 
                Discovery's default minimum value, according to the Mobile
                IPv6 specifications. A lower value will give a faster handoff 
                and consequently a higher value will give a slower handoff.

        The Home Agent code can be activated by: 
            ``mip6config -g''
        or
            ``mip6config -f <file>''
              with the line ``enable_ha'' specified in <file>.


3.3     Setting up the Mobile Node

        If the Mobile Node has been included in the kernel it may be started
        in different ways depending on how the home address is assigned to
        the Mobile node.

        The following possibilities are present:
            ``mip6config -a''
        or
             `mip6config -H <Home addr>/<plen>@<interface>%<Home Agent addr>''
        or
            ``mip6config -f <file>

              with either line specified in <file>:
                  ``autoconfig''
              or
                  ``homeaddr <Home addr>/<plen>@<interface>%<Home Agent addr>''

        At the moment we recommend the manual (-H) alternative and that this
        is written in a configuration file. See example file
        /usr/local/v6/etc/mip6.conf.sample.

        

4.0     OUTSTANDING ISSUES

4.1     Draft compliance

        The implementation follows draft-ietf-mobileip-ipv6-09.txt with the
        following exceptions:

        - Section 9.7 "Renumbering the Home subnet" has not been implemented.

        - Support for multihoming and multiple arbitrary home addresses is
          not implemented.

        - Support for IPSec has been implemented but not tested. It might be
          the case that there is more work to do. We have to look into this.

4.2     Missing functionality

        Although the basic functionality has been implemented there are some
        features that are missing or has not been tested properly.

        - Modules are not supported.

        - We have only verified the code for FreeBSD. The code has been
          prepared for the other platforms (OpenBSD, NetBSD and BSDi) but
          not compiled.

        - In the ``mip6stat'' command the following options are not supported:
           * -M  (Clear home address)

        - In the ``mip6config'' command the following options are not
          supported:
           * -F  (Set default foreign IP Address)
           * -E  (Remove default foreign address from list)
           * -w  (Set time when CN should send Binding request)
           * -u  (Enable forwarding of Site local Unicast dest addresses)
           * -m  (Enable forwarding of Site local Multicast dest addresses)
           * -p  (Enable link layer promiscuous mode)
           * -r  (Enable sending BU to CN, i.e. Route optimisation on/off)
           * -t  (Enable tunneling of packets from MN to CN via HA)
           * -q  (Enable sending BR to the MN)
           * -a  (Allow autoconfiguration of Home address)
