"`#include <linux/rtnetlink.h>`"
import pyroute2.netlink.rtnl as rtnl
import enum

__all__ = [
    "RTMGRP",
]

class RTMGRP(enum.IntFlag):
    NONE = rtnl.RTMGRP_NONE
    LINK = rtnl.RTMGRP_LINK
    NOTIFY = rtnl.RTMGRP_NOTIFY
    NEIGH = rtnl.RTMGRP_NEIGH
    TC = rtnl.RTMGRP_TC
    IPV4_IFADDR = rtnl.RTMGRP_IPV4_IFADDR
    IPV4_MROUTE = rtnl.RTMGRP_IPV4_MROUTE
    IPV4_ROUTE = rtnl.RTMGRP_IPV4_ROUTE
    IPV4_RULE = rtnl.RTMGRP_IPV4_RULE
    IPV6_IFADDR = rtnl.RTMGRP_IPV6_IFADDR
    IPV6_MROUTE = rtnl.RTMGRP_IPV6_MROUTE
    IPV6_ROUTE = rtnl.RTMGRP_IPV6_ROUTE
    IPV6_IFINFO = rtnl.RTMGRP_IPV6_IFINFO
    DECnet_IFADDR = rtnl.RTMGRP_DECnet_IFADDR
    NOP2 = rtnl.RTMGRP_NOP2
    DECnet_ROUTE = rtnl.RTMGRP_DECnet_ROUTE
    DECnet_RULE = rtnl.RTMGRP_DECnet_RULE
    NOP4 = rtnl.RTMGRP_NOP4
    IPV6_PREFIX = rtnl.RTMGRP_IPV6_PREFIX
    IPV6_RULE = rtnl.RTMGRP_IPV6_RULE
    MPLS_ROUTE = rtnl.RTMGRP_MPLS_ROUTE

