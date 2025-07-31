int __nla_validate(const struct nlattr *head, int len, int maxtype,
		   const struct nla_policy *policy, unsigned int validate,
		   struct netlink_ext_ack *extack)
{
	return __nla_validate_parse(head, len, maxtype, policy, validate,
				    extack, NULL);
}