#ifndef _LINUX_NETFILTER_XT_MPTCP_H
#define _LINUX_NETFILTER_XT_MPTCP_H

enum {
	XT_MPTCP_PRESENT     = 1 << 0,
	XT_MPCAPABLE_PRESENT = 1 << 1,
	XT_MPJOIN_PRESENT	 = 1 << 2,
	XT_DSS_FLAGS		 = 1 << 3
};

struct xt_mptcp_mtinfo {
	__u8 subtypes;
	__u8 dss_flg_mask;
	__u8 dss_flg_cmp;
	__u8 invflags;
};

#endif /* _LINUX_NETFILTER_XT_MPTCP_H */
