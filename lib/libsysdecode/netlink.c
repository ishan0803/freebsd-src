/*
 * Copyright (c) 2026 Ishan Agrawal
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netlink/netlink.h>
#include <netlink/netlink_generic.h>
#include <netlink/netlink_snl.h>
#include <netpfil/pf/pf_nl.h>
#include <netphil/pf/pf.h>

#include <stdio.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "sysdecode.h"
#include "support.h"

/*
 * Decodes a buffer as a Netlink message stream.
 *
 * Returns true if the data was successfully decoded as Netlink.
 * Returns false if the data is malformed, allowing the caller
 * to fallback to a standard hex/string dump.
 */

static struct name_table *family_table = NULL;
static size_t num_family = 0;

typedef void decode_attr_f(FILE *fp, const struct nlattr *attr,
    const char *attr_name, const void *args);
struct nlattr_decoder {
	uint16_t	type;		/* Attribute type */
	const char	*attr_name;	/* Attribute name*/
	decode_attr_f	*cb;		/* decoder function to call */
	const void	*args;		/* nested decoder */
};

struct nlattr_decoder_set {
	const struct nlattr_decoder	*decoders;	/* PFNL CMD Decoders */
	size_t				count;		/*Attribute Count*/
};

#define	NL_DECLARE_ATTR_DECODER(_name, _np)			\
static const struct nlattr_decoder_set _name = {			\
	.decoders = &((_np)[0]),					\
	.count = nitems(_np),						\
}

static void nl_decode_attrs_raw(FILE *fp, const struct nlattr *nla_head,
    size_t len, const struct nlattr_decoder *ps, size_t pslen);

static void
nlattr_decode_pfaddr(FILE *fp, const struct nlattr *attr,
    const char *attr_name, const void *args __unused)
{
	struct pf_addr target;

	fprintf(fp, "%s=", attr_name);
	if (NLA_DATA_LEN(attr) < (int)sizeof(target))
		return;

	memcpy(&target, NLA_DATA_CONST(attr), sizeof(struct pf_addr));

	char buf[INET_ADDRSTRLEN];

	if (inet_ntop(AF_INET, &target.v4, buf, sizeof(buf)) != NULL)
		fprintf(fp, "%s", buf);
}

static void
nlattr_decode_in6_addr(FILE *fp, const struct nlattr *attr,
    const char *attr_name, const void *args)
{
	(void)args;

	struct in6_addr target;

	fprintf(fp, "%s=", attr_name);
	if (NLA_DATA_LEN(attr) < (int)sizeof(target))
		return;

	memcpy(&target, NLA_DATA_CONST(attr), sizeof(struct in6_addr));

	char buf[INET6_ADDRSTRLEN];

	if (inet_ntop(AF_INET6, &target, buf, sizeof(buf)) != NULL)
		fprintf(fp, "%s", buf);
}

static void
nlattr_decode_int32(FILE *fp, const struct nlattr *attr, const char *attr_name,
    const void *args __unused)
{
	int32_t target;

	fprintf(fp, "%s=", attr_name);
	if (NLA_DATA_LEN(attr) < (int)sizeof(target))
		return;

	memcpy(&target, NLA_DATA_CONST(attr), sizeof(int32_t));

	fprintf(fp, "%u", target);
}

static void
nlattr_decode_uint64(FILE *fp, const struct nlattr *attr, const char *attr_name,
    const void *args)
{
	(void)args;

	uint64_t target;

	fprintf(fp, "%s=", attr_name);
	if (NLA_DATA_LEN(attr) < (int)sizeof(target))
		return;

	memcpy(&target, NLA_DATA_CONST(attr), sizeof(uint64_t));

	fprintf(fp, "%lu", target);
}

static void
nlattr_decode_uint32(FILE *fp, const struct nlattr *attr, const char *attr_name,
    const void *args)
{
	(void)args;

	uint32_t target;

	fprintf(fp, "%s=", attr_name);
	if (NLA_DATA_LEN(attr) < (int)sizeof(target))
		return;

	memcpy(&target, NLA_DATA_CONST(attr), sizeof(uint32_t));

	fprintf(fp, "%u", target);
}

static void
nlattr_decode_uint16(FILE *fp, const struct nlattr *attr, const char *attr_name,
    const void *args)
{
	(void)args;

	uint16_t target;

	fprintf(fp, "%s=", attr_name);
	if (NLA_DATA_LEN(attr) < (int)sizeof(target))
		return;

	memcpy(&target, NLA_DATA_CONST(attr), sizeof(uint16_t));

	fprintf(fp, "%u", target);
}

static void
nlattr_decode_uint8(FILE *fp, const struct nlattr *attr, const char *attr_name,
    const void *args)
{
	(void)args;

	uint8_t target;

	fprintf(fp, "%s=", attr_name);
	if (NLA_DATA_LEN(attr) < (int)sizeof(target))
		return;

	memcpy(&target, NLA_DATA_CONST(attr), sizeof(uint8_t));

	fprintf(fp, "%u", target);
}

static void
nlattr_decode_bool(FILE *fp, const struct nlattr *attr, const char *attr_name,
    const void *args)
{
	(void)args;

	bool target;

	fprintf(fp, "%s=", attr_name);
	if (NLA_DATA_LEN(attr) < (int)sizeof(target))
		return;

	memcpy(&target, NLA_DATA_CONST(attr), sizeof(bool));

	if (target)
		fprintf(fp, "TRUE");
	else
		fprintf(fp, "FALSE");
}

static void
nlattr_decode_string(FILE *fp, const struct nlattr *attr, const char *attr_name,
    const void *args)
{
	(void)args;

	fprintf(fp, "%s=", attr_name);
	if (NLA_DATA_LEN(attr) == 0)
		return;

	const char *target = (const char *)NLA_DATA_CONST(attr);

	fprintf(fp, "%s", target);
}

static void
nlattr_decode_nested(FILE *fp, const struct nlattr *attr, const char *attr_name,
    const void *args)
{
	const struct nlattr_decoder_set *set = args;

	fprintf(fp, "%s=", attr_name);
	if (set == NULL)
		return;

	nl_decode_attrs_raw(fp, NLA_DATA_CONST(attr), NLA_DATA_LEN(attr),
	    set->decoders, set->count);
}

static const struct nlattr_decoder *
search_decoders(const struct nlattr_decoder *ps, size_t pslen, int key)
{
	size_t left_i = 0, right_i = pslen - 1;

	if (pslen == 0)
		return (NULL);

	if (key < ps[0].type || key > ps[pslen - 1].type)
		return (NULL);

	while (left_i + 1 < right_i) {
		size_t mid_i = (left_i + right_i) / 2;
		if (key < ps[mid_i].type)
			right_i = mid_i;
		else if (key > ps[mid_i].type)
			left_i = mid_i + 1;
		else
			return (&ps[mid_i]);
	}
	if (ps[left_i].type == key)
		return (&ps[left_i]);
	else if (ps[right_i].type == key)
		return (&ps[right_i]);
	return (NULL);
}

static void
nl_decode_attrs_raw(FILE *fp, const struct nlattr *nla_head, size_t len,
    const struct nlattr_decoder *ps, size_t pslen)
{
	const struct nlattr_decoder *s;
	const struct nlattr *nla;
	bool first = true;

	fprintf(fp, "{");

	NLA_FOREACH_CONST(nla, nla_head, len) {
		if (!first)
			fprintf(fp, ",");

		s = search_decoders(ps, pslen, nla->nla_type & NLA_TYPE_MASK);
		if (s != NULL && s->cb != NULL)
			s->cb(fp, nla, s->attr_name, s->args);

		first = false;
	}

	fprintf(fp, "}");
}

static const struct nlattr_decoder nla_d_addr_wrap[] = {
	{ .type = PF_AT_ADDR, .attr_name = "addr", .cb = nlattr_decode_in6_addr },
	{ .type = PF_AT_MASK, .attr_name = "mask", .cb = nlattr_decode_in6_addr },
	{ .type = PF_AT_IFNAME, .attr_name = "ifname", .cb = nlattr_decode_string },
	{ .type = PF_AT_TABLENAME, .attr_name = "tablename", .cb = nlattr_decode_string },
	{ .type = PF_AT_TYPE, .attr_name = "type", .cb = nlattr_decode_uint8 },
	{ .type = PF_AT_IFLAGS, .attr_name = "iflags", .cb = nlattr_decode_uint8 },
};
NL_DECLARE_ATTR_DECODER(addr_wrap_decoder, nla_d_addr_wrap);

static const struct nlattr_decoder nla_d_pool_addr[] = {
	{ .type = PF_PA_ADDR, .attr_name = "addr", .cb = nlattr_decode_nested, .args = &addr_wrap_decoder},
	{ .type = PF_PA_IFNAME, .attr_name = "ifname", .cb = nlattr_decode_string },
};
NL_DECLARE_ATTR_DECODER(pool_addr_decoder, nla_d_pool_addr);

static const struct nlattr_decoder nla_d_add_addr[] = {
	{ .type = PF_AA_ACTION, .attr_name = "action", .cb = nlattr_decode_uint32 },
	{ .type = PF_AA_TICKET, .attr_name = "ticket", .cb = nlattr_decode_uint32 },
	{ .type = PF_AA_NR, .attr_name = "nr", .cb = nlattr_decode_uint32 },
	{ .type = PF_AA_R_NUM, .attr_name = "r_num", .cb = nlattr_decode_uint32 },
	{ .type = PF_AA_R_ACTION, .attr_name = "r_action", .cb = nlattr_decode_uint8 },
	{ .type = PF_AA_R_LAST, .attr_name = "r_last", .cb = nlattr_decode_uint8 },
	{ .type = PF_AA_AF, .attr_name = "af", .cb = nlattr_decode_uint8 },
	{ .type = PF_AA_ANCHOR, .attr_name = "anchor", .cb = nlattr_decode_string },
	{ .type = PF_AA_ADDR, .attr_name = "addr", .cb = nlattr_decode_nested , .args = &pool_addr_decoder},
	{ .type = PF_AA_WHICH, .attr_name = "which", .cb = nlattr_decode_uint32 },
};
NL_DECLARE_ATTR_DECODER(addr_decoder, nla_d_add_addr);

static const struct nlattr_decoder nla_d_ruleaddr[] = {
	{ .type = PF_RAT_ADDR, .attr_name = "addr", .cb = nlattr_decode_nested, .args = &addr_wrap_decoder },
	{ .type = PF_RAT_SRC_PORT, .attr_name = "src_port", .cb = nlattr_decode_uint16 },
	{ .type = PF_RAT_DST_PORT, .attr_name = "dst_port", .cb = nlattr_decode_uint16 },
	{ .type = PF_RAT_NEG, .attr_name = "neg", .cb = nlattr_decode_uint8 },
	{ .type = PF_RAT_OP, .attr_name = "op", .cb = nlattr_decode_uint8 },
};
NL_DECLARE_ATTR_DECODER(rule_addr_decoder, nla_d_ruleaddr);

static const struct nlattr_decoder nla_d_clear_states[] = {
	{ .type = PF_CS_CMP_ID, .attr_name = "cmp_id", .cb = nlattr_decode_uint64 },
	{ .type = PF_CS_CMP_CREATORID, .attr_name = "cmp_creatorid", .cb = nlattr_decode_uint32 },
	{ .type = PF_CS_CMP_DIR, .attr_name = "cmp_dir", .cb = nlattr_decode_uint8 },
	{ .type = PF_CS_AF, .attr_name = "af", .cb = nlattr_decode_uint8 },
	{ .type = PF_CS_PROTO, .attr_name = "proto", .cb = nlattr_decode_uint8 },
	{ .type = PF_CS_SRC, .attr_name = "src", .cb = nlattr_decode_nested, .args = &rule_addr_decoder },
	{ .type = PF_CS_DST, .attr_name = "dst", .cb = nlattr_decode_nested, .args = &rule_addr_decoder },
	{ .type = PF_CS_RT_ADDR, .attr_name = "rt_addr", .cb = nlattr_decode_nested, .args = &rule_addr_decoder },
	{ .type = PF_CS_IFNAME, .attr_name = "ifname", .cb = nlattr_decode_string },
	{ .type = PF_CS_LABEL, .attr_name = "label", .cb = nlattr_decode_string },
	{ .type = PF_CS_KILL_MATCH, .attr_name = "kill_match", .cb = nlattr_decode_bool },
	{ .type = PF_CS_NAT, .attr_name = "nat", .cb = nlattr_decode_bool },
};
NL_DECLARE_ATTR_DECODER(killclear_states_decoder, nla_d_clear_states);

static const struct nlattr_decoder nla_d_skey[] = {
	{ .type = PF_STK_ADDR0, .attr_name = "addr0", .cb = nlattr_decode_pfaddr },
	{ .type = PF_STK_ADDR1, .attr_name = "addr1", .cb = nlattr_decode_pfaddr },
	{ .type = PF_STK_PORT0, .attr_name = "port0", .cb = nlattr_decode_uint16 },
	{ .type = PF_STK_PORT1, .attr_name = "port1", .cb = nlattr_decode_uint16 },
	{ .type = PF_STK_AF, .attr_name = "af", .cb = nlattr_decode_uint8 },
	{ .type = PF_STK_PROTO, .attr_name = "proto", .cb = nlattr_decode_uint16 },
};
NL_DECLARE_ATTR_DECODER(pfstate_key_decoder, nla_d_skey);

static const struct nlattr_decoder nla_d_speer[] = {
	{ .type = PF_STP_PFSS_FLAGS, .attr_name = "pfss_flags", .cb = nlattr_decode_uint16 },
	{ .type = PF_STP_PFSS_TTL, .attr_name = "pfss_ttl", .cb = nlattr_decode_uint8 },
	{ .type = PF_STP_SCRUB_FLAG, .attr_name = "scrub_flag", .cb = nlattr_decode_uint8 },
	{ .type = PF_STP_PFSS_TS_MOD, .attr_name = "pfss_ts_mod", .cb = nlattr_decode_uint32 },
	{ .type = PF_STP_SEQLO, .attr_name = "seqlo", .cb = nlattr_decode_uint32 },
	{ .type = PF_STP_SEQHI, .attr_name = "seqhi", .cb = nlattr_decode_uint32 },
	{ .type = PF_STP_SEQDIFF, .attr_name = "seqdiff", .cb = nlattr_decode_uint32 },
	{ .type = PF_STP_MAX_WIN, .attr_name = "max_win", .cb = nlattr_decode_uint16 },
	{ .type = PF_STP_MSS, .attr_name = "mss", .cb = nlattr_decode_uint16 },
	{ .type = PF_STP_STATE, .attr_name = "state", .cb = nlattr_decode_uint8 },
	{ .type = PF_STP_WSCALE, .attr_name = "wscale", .cb = nlattr_decode_uint8 },
};
NL_DECLARE_ATTR_DECODER(pfstate_peer_decoder, nla_d_speer);

static const struct nlattr_decoder nla_d_state[] = {
	{ .type = PF_ST_ID, .attr_name = "id", .cb = nlattr_decode_uint32 },
	{ .type = PF_ST_CREATORID, .attr_name = "creatorid", .cb = nlattr_decode_uint32 },
	{ .type = PF_ST_IFNAME, .attr_name = "ifname", .cb = nlattr_decode_string },
	{ .type = PF_ST_ORIG_IFNAME, .attr_name = "orig_ifname", .cb = nlattr_decode_string },
	{ .type = PF_ST_KEY_WIRE, .attr_name = "key_wire", .cb = nlattr_decode_nested, .args = &pfstate_key_decoder },
	{ .type = PF_ST_KEY_STACK, .attr_name = "key_stack", .cb = nlattr_decode_nested, .args = &pfstate_key_decoder },
	{ .type = PF_ST_PEER_SRC, .attr_name = "peer_src", .cb = nlattr_decode_nested, .args = &pfstate_peer_decoder },
	{ .type = PF_ST_PEER_DST, .attr_name = "peer_dst", .cb = nlattr_decode_nested, .args = &pfstate_peer_decoder },
	{ .type = PF_ST_RT_ADDR, .attr_name = "rt_addr", .cb = nlattr_decode_pfaddr },
	{ .type = PF_ST_RULE, .attr_name = "rule", .cb = nlattr_decode_uint32 },
	{ .type = PF_ST_ANCHOR, .attr_name = "anchor", .cb = nlattr_decode_uint32 },
	{ .type = PF_ST_NAT_RULE, .attr_name = "nat_rule", .cb = nlattr_decode_uint32 },
	{ .type = PF_ST_CREATION, .attr_name = "creation", .cb = nlattr_decode_uint32 },
	{ .type = PF_ST_EXPIRE, .attr_name = "expire", .cb = nlattr_decode_uint32 },
	{ .type = PF_ST_PACKETS0, .attr_name = "packets0", .cb = nlattr_decode_uint64 },
	{ .type = PF_ST_PACKETS1, .attr_name = "packets1", .cb = nlattr_decode_uint64 },
	{ .type = PF_ST_BYTES0, .attr_name = "bytes0", .cb = nlattr_decode_uint64 },
	{ .type = PF_ST_BYTES1, .attr_name = "bytes1", .cb = nlattr_decode_uint64 },
	{ .type = PF_ST_AF, .attr_name = "af", .cb = nlattr_decode_uint8 },
	{ .type = PF_ST_PROTO, .attr_name = "proto", .cb = nlattr_decode_uint8 },
	{ .type = PF_ST_DIRECTION, .attr_name = "direction", .cb = nlattr_decode_uint8 },
	{ .type = PF_ST_LOG, .attr_name = "log", .cb = nlattr_decode_uint8 },
	{ .type = PF_ST_TIMEOUT, .attr_name = "timeout", .cb = nlattr_decode_uint8 },
	{ .type = PF_ST_STATE_FLAGS, .attr_name = "state_flags", .cb = nlattr_decode_uint8 },
	{ .type = PF_ST_SYNC_FLAGS, .attr_name = "sync_flags", .cb = nlattr_decode_uint8 },
	{ .type = PF_ST_UPDATES, .attr_name = "updates", .cb = nlattr_decode_uint8 },
	{ .type = PF_ST_VERSION, .attr_name = "version", .cb = nlattr_decode_uint64 },
	{ .type = PF_ST_FILTER_ADDR, .attr_name = "filter_addr", .cb = nlattr_decode_pfaddr },
	{ .type = PF_ST_FILTER_MASK, .attr_name = "filter_mask", .cb = nlattr_decode_pfaddr },
	{ .type = PF_ST_RTABLEID, .attr_name = "rtableid", .cb = nlattr_decode_int32 },
	{ .type = PF_ST_MIN_TTL, .attr_name = "min_ttl", .cb = nlattr_decode_uint8 },
	{ .type = PF_ST_MAX_MSS, .attr_name = "max_mss", .cb = nlattr_decode_uint16 },
	{ .type = PF_ST_DNPIPE, .attr_name = "dnpipe", .cb = nlattr_decode_uint16 },
	{ .type = PF_ST_DNRPIPE, .attr_name = "dnrpipe", .cb = nlattr_decode_uint16 },
	{ .type = PF_ST_RT, .attr_name = "rt", .cb = nlattr_decode_uint8 },
	{ .type = PF_ST_RT_IFNAME, .attr_name = "rt_ifname", .cb = nlattr_decode_string },
	{ .type = PF_ST_SRC_NODE_FLAGS, .attr_name = "src_node_flags", .cb = nlattr_decode_uint8 },
	{ .type = PF_ST_RT_AF, .attr_name = "rt_af", .cb = nlattr_decode_uint8 },
	{ .type = PF_ST_INCLUDE_RULE, .attr_name = "include_rule", .cb = nlattr_decode_bool },
	{ .type = PF_ST_CREATED_BY_RULE, .attr_name = "created_by_rule", .cb = nlattr_decode_nested, .args = &pf_rule_decoder },
};
NL_DECLARE_ATTR_DECODER(state_decoder, nla_d_state);

static void
sysdecode_netlink_pf(FILE *fp, const struct genlmsghdr *genl, size_t nlm_len)
{
	uint8_t cmd = genl->cmd;
	const char *cmd_name = sysdecode_pfnl_cmd(cmd);

	if (cmd_name != NULL)
		fprintf(fp, "cmd=%s", cmd_name);
	else
		fprintf(fp, "cmd=%u", cmd);

	const struct nlattr *nla = (const struct nlattr *)(const void *)
	    ((const char *)genl + sizeof(struct genlmsghdr));

	switch (cmd) {
	case PFNL_CMD_GETSTATES:
			nl_decode_attrs_raw(fp, nla, nlm_len,
			    state_decoder.decoders, state_decoder.count);
		break;
	case PFNL_CMD_GET_ADDR:
			nl_decode_attrs_raw(fp, nla, nlm_len,
			    addr_decoder.decoders, addr_decoder.count);
		break;
	case PFNL_CMD_GET_ADDRS:
			nl_decode_attrs_raw(fp, nla, nlm_len,
			    addr_decoder.decoders, addr_decoder.count);
		break;
	case PFNL_CMD_KILLSTATES:
			nl_decode_attrs_raw(fp, nla, nlm_len,
			    killclear_states_decoder.decoders,
			    killclear_states_decoder.count);
		break;
	default:
		break;
	}
}

bool
sysdecode_netlink(FILE *fp, const void *buf, size_t len, int protocol)
{
	const struct nlmsghdr *nl = buf;
	size_t remaining = len;
	bool first = true;

	/* Basic sanity check: Buffer must be at least one header size. */
	if (remaining < sizeof(struct nlmsghdr))
		return (false);

	/* * Protocol Sanity Check:
	 * The first message length must be valid (>= header) and fit
	 * inside the provided buffer snapshot.
	 */
	if (nl->nlmsg_len < sizeof(struct nlmsghdr) || nl->nlmsg_len > remaining)
		return (false);

	if (family_table == NULL) {
		family_table = malloc((num_family + 1) *
		    sizeof(struct name_table));
		family_table[num_family] = (struct name_table){0, NULL};
	}

	fprintf(fp, "netlink{");

	while (remaining >= sizeof(struct nlmsghdr)) {
		if (!first)
			fprintf(fp, ",");

		/* Safety check for current message. */
		if (nl->nlmsg_len < sizeof(struct nlmsghdr) ||
		    nl->nlmsg_len > remaining) {
			fprintf(fp, "<truncated>");
			break;
		}

		fprintf(fp, "flags=");
		sysdecode_nlm_flag(fp, nl->nlmsg_flags);

		fprintf(fp, ",seq=%u,pid=%u", nl->nlmsg_seq, nl->nlmsg_pid);

		fprintf(fp, ",len=%u,type=", nl->nlmsg_len);

		/* Decode Standard Message Types. */
		switch (nl->nlmsg_type) {
		case NLMSG_NOOP:
			fprintf(fp, "NLMSG_NOOP");
			break;
		case NLMSG_ERROR:
			fprintf(fp, "NLMSG_ERROR");
			break;
		case NLMSG_DONE:
			fprintf(fp, "NLMSG_DONE");
			break;
		case NLMSG_OVERRUN:
			fprintf(fp, "NLMSG_OVERRUN");
			break;
		case GENL_ID_CTRL:
			if (protocol != NETLINK_GENERIC)
				break;

			fprintf(fp, "GENL_ID_CTRL");

			const struct genlmsghdr *genl =
			    (const struct genlmsghdr *)(const void *)
			    ((const char *)nl + sizeof(struct nlmsghdr));

			uint16_t family_id = 0;
			const char *family_name = NULL;

			fprintf(fp,
			    ",genl={cmd=%u,"
			    "ver=%u,reserve=%u",
			    genl->cmd,
			    genl->version, genl->reserved);

			size_t cur_len = (sizeof(struct nlmsghdr)
			    + sizeof(struct genlmsghdr));
			size_t nla_len = nl->nlmsg_len - cur_len;

			const struct nlattr *nla;
			const struct nlattr *nla_head = (const struct nlattr *)
			    (const void *)((const char *)nl + cur_len);

			NLA_FOREACH_CONST(nla, nla_head, nla_len) {
				switch (nla->nla_type) {
				case CTRL_ATTR_FAMILY_ID:
					memcpy(&family_id, NLA_DATA_CONST(nla),
					    sizeof(family_id));
					fprintf(fp, ",family_id=%u", family_id);
					break;
				case CTRL_ATTR_FAMILY_NAME:
					family_name =
					    ((const char *)NLA_DATA_CONST(nla));
					fprintf(fp, ",family_name=%s",
					    family_name);
					break;
				default:
					break;
				}
			}

			if (family_name && family_id &&
			    !lookup_value(family_table, family_id)) {
				num_family++;

				family_table = realloc(family_table,
				    (num_family + 1) *
				    sizeof(struct name_table));
				family_table[num_family - 1].val =
				    family_id;
				family_table[num_family - 1].str =
				    strdup(family_name);

				family_table[num_family] =
				    (struct name_table){0, NULL};
			}
			fprintf(fp, "}");
			break;
		default:
			fprintf(fp, "%u", nl->nlmsg_type);
			break;
		}

		const char *family = lookup_value(family_table, nl->nlmsg_type);

		if (family != NULL && protocol == NETLINK_GENERIC) {
			fprintf(fp, ",%s={", family);

			if (strcmp(family, "pfctl") == 0) {
				const struct genlmsghdr *genl =
				    (const struct genlmsghdr *)(const void *)
				    ((const char *)nl +
				    sizeof(struct nlmsghdr));
				const size_t nlm_len = nl->nlmsg_len -
				    (sizeof(struct nlmsghdr) +
				    sizeof(struct genlmsghdr));

				sysdecode_netlink_pf(fp, genl, nlm_len);
			}

			fprintf(fp, "}");
		}

		/* Handle Alignment (Netlink messages are 4-byte aligned). */
		size_t aligned_len = NLMSG_ALIGN(nl->nlmsg_len);
		if (aligned_len > remaining)
			remaining = 0;
		else
			remaining -= aligned_len;

		nl = (const struct nlmsghdr *)(const void *)((const char *)nl + aligned_len);
		first = false;
	}

	fprintf(fp, "}");
	return (true);
}
