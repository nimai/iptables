#include <stdio.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_mptcp.h>
#include <xtables.h>


/*
 * dump -- not necessary right now 
static void mptcp_mt4_save(const void *entry, const struct xt_entry_match *match)
{
    const struct xt_mptcp_info *info = (const void*) match->data;
}
*/

static int mptcp_mt_parse(int c, char **argv, int invert, 
        unsigned int *flags, const void *entry, struct xt_entry_match **match)
{
    struct xt_mptcp_mtinfo *info = (void *)(*match)->data;
    /* for future use. for now, purpose is only to detect if mptcp present */
    *flags = XT_MPTCP_PRESENT;
    info->flags = XT_MPTCP_PRESENT;
    return true;
}

static void mptcp_mt_init(struct xt_entry_match *match)
{
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
