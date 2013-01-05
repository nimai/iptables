#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_mptcp.h>
#include <stdbool.h>
#include <string.h>
#include <xtables.h>
#include <getopt.h>


static const struct option mptcp_mt_opts[] = {
	{.name = "capable", .has_arg = false, .val = '1'},
	{.name = "join", .has_arg = false, .val = '2'},
	{.name = "dss", .has_arg = true, .val = '3'},
	{NULL},
};

struct dss_flag_names {
	const char *name;
	unsigned int flag;
};

static const struct dss_flag_names dss_flag_names[]
= { { "ACK", 0x01 },
    { "MAP", 0x04 },
    { "FIN", 0x10 },
    { "ALL", 0x15 },
};

static unsigned int
parse_dss_flag(const char *flags)
{
	unsigned int ret = 0;
	char *ptr;
	char *buffer;

	buffer = strdup(flags);

	for (ptr = strtok(buffer, ","); ptr; ptr = strtok(NULL, ",")) {
		unsigned int i;
		for (i = 0; i < ARRAY_SIZE(dss_flag_names); ++i)
			if (strcasecmp(dss_flag_names[i].name, ptr) == 0) {
				ret |= dss_flag_names[i].flag;
				break;
			}
		if (i == ARRAY_SIZE(dss_flag_names))
			xtables_error(PARAMETER_PROBLEM,
				   "Unknown DSS flag `%s'", ptr);
	}

	free(buffer);
	return ret;
}

static void
parse_dss_flags(struct xt_mptcp_mtinfo *info,
		const char *mask,
		const char *cmp,
		int invert)
{
	info->dss_flg_mask = parse_dss_flag(mask);
	info->dss_flg_cmp = parse_dss_flag(cmp);

	if (invert)
		info->invflags |= XT_DSS_FLAGS;
}


static int mptcp_mt_parse(int c, char **argv, int invert, 
        unsigned int *flags, const void *entry, struct xt_entry_match **match)
{
    struct xt_mptcp_mtinfo *info = (void *)(*match)->data;

	switch (c) {
	case '1': /* match mpcapable */
		if (*flags & XT_MPCAPABLE_PRESENT)
			xtables_error(PARAMETER_PROBLEM, "xt_mptcp: "
					"Only use \"--capable\" once!");
		*flags |= XT_MPCAPABLE_PRESENT;
		info->suptypes |= XT_MPCAPABLE_PRESENT;
		if (invert)
			info->invflags |= XT_MPCAPABLE_PRESENT;
		return true;

	case '2': /* match mpjoin */
		if (*flags & XT_MPJOIN_PRESENT)
			xtables_error(PARAMETER_PROBLEM, "xt_mptcp: "
					"Only use \"--capable\" once!");
		*flags |= XT_MPJOIN_PRESENT;
		info->subtypes |= XT_MPJOIN_PRESENT;
		if (invert)
			info->invflags |= XT_MPJOIN_PRESENT;
		return true;

	case '3': /* match dss flags */
		if (*flags & DSS_FLAGS)
			xtables_error(PARAMETER_PROBLEM,
					"xt_mptcp: Only use \"--dss\" once!");
		/* 2nd arg handling */
		if (!argv[optind]
				|| argv[optind][0] == '-' || argv[optind][0] == '!')
			xtables_error(PARAMETER_PROBLEM,
					"xt_mptcp: \"--dss\" requires two args.");

		parse_dss_flags(info, optarg, argv[optind], invert);
		*flags |= XT_DSS_FLAGS;
		return true;
	}
	return false;

}

static void mptcp_mt_init(struct xt_entry_match *match)
{
    struct xt_mptcp_mtinfo *info = (void *)match->data;
	/* whenever the match is used, it matches only MPTCP packets, even without
	 * parameter */
	info->flags = XT_MPTCP_PRESENT;
}
    
static void mptcp_mt_help(void)
{
    printf(
            "no mptcp match options for now.\n"
          );
}


static struct xtables_match mptcp_mt4_reg = {
    .version    = XTABLES_VERSION,
    .name           = "mptcp",
    .revision       = 0,
    .family         = NFPROTO_IPV4,
    .size           = XT_ALIGN(sizeof(struct xt_mptcp_mtinfo)),
    .userspacesize  = XT_ALIGN(sizeof(struct xt_mptcp_mtinfo)),
    /* Functions */
    .help           = mptcp_mt_help,
    .init           = mptcp_mt_init,
    .parse          = mptcp_mt_parse,
	/* TODO implement missing functions */
/*    .final_check    = mptcp_mt_check,*/
/*    .print          = mptcp_mt4_print,*/
/*    .save           = mptcp_mt4_save,*/
/*    .extra_opts     = mptcp_mt_opts,*/
};
static struct xtables_match mptcp_mt6_reg = {
    .version    = XTABLES_VERSION,
    .name           = "mptcp",
    .revision       = 0,
    .family         = NFPROTO_IPV6,
    .size           = XT_ALIGN(sizeof(struct xt_mptcp_mtinfo)),
    .userspacesize  = XT_ALIGN(sizeof(struct xt_mptcp_mtinfo)),
    /* Functions */
    .help           = mptcp_mt_help,
    .init           = mptcp_mt_init,
    .parse          = mptcp_mt_parse,
/*    .final_check    = mptcp_mt_check,*/
/*    .print          = mptcp_mt4_print,*/
/*    .save           = mptcp_mt4_save,*/
/*    .extra_opts     = mptcp_mt_opts,*/
};


void _init(void)
{
    xtables_register_match(&mptcp_mt4_reg);
    xtables_register_match(&mptcp_mt6_reg);
}
