static unsigned int sfq_hash(const struct sfq_sched_data *q,
			     const struct sk_buff *skb)
{
	return skb_get_hash_perturb(skb, q->perturbation) & (q->divisor - 1);
}