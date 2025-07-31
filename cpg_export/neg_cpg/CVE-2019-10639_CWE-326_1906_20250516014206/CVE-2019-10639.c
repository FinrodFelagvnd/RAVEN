static inline u32 net_hash_mix(const struct net *net)
{
#ifdef CONFIG_NET_NS
	return (u32)(((unsigned long)net) >> ilog2(sizeof(*net)));
#else
	return 0;
#endif
}