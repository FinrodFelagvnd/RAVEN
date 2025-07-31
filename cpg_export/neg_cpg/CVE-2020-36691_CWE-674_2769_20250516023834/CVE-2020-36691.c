int __nla_parse(struct nlattr **tb, int maxtype,
		const struct nlattr *head, int len,
		const struct nla_policy *policy, unsigned int validate,
		struct netlink_ext_ack *extack)
{
	return __nla_validate_parse(head, len, maxtype, policy, validate,
				    extack, tb);
}