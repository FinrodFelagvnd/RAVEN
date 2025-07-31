static int tcp_validate_incoming(struct sock *sk, struct sk_buff *skb,
			      const struct tcphdr *th, int syn_inerr)
{
	const u8 *hash_location;
	struct tcp_sock *tp = tcp_sk(sk);

	/* RFC1323: H1. Apply PAWS check first. */
	if (tcp_fast_parse_options(skb, th, tp, &hash_location) &&
	    tp->rx_opt.saw_tstamp &&
	    tcp_paws_discard(sk, skb)) {
		if (!th->rst) {
			NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_PAWSESTABREJECTED);
			tcp_send_dupack(sk, skb);
			goto discard;
		}
		/* Reset is accepted even if it did not pass PAWS. */
	}

	/* Step 1: check sequence number */
	if (!tcp_sequence(tp, TCP_SKB_CB(skb)->seq, TCP_SKB_CB(skb)->end_seq)) {
		/* RFC793, page 37: "In all states except SYN-SENT, all reset
		 * (RST) segments are validated by checking their SEQ-fields."
		 * And page 69: "If an incoming segment is not acceptable,
		 * an acknowledgment should be sent in reply (unless the RST
		 * bit is set, if so drop the segment and return)".
		 */
		if (!th->rst)
			tcp_send_dupack(sk, skb);
		goto discard;
	}

	/* Step 2: check RST bit */
	if (th->rst) {
		tcp_reset(sk);
		goto discard;
	}

	/* ts_recent update must be made after we are sure that the packet
	 * is in window.
	 */
	tcp_replace_ts_recent(tp, TCP_SKB_CB(skb)->seq);

	/* step 3: check security and precedence [ignored] */

	/* step 4: Check for a SYN in window. */
	if (th->syn && !before(TCP_SKB_CB(skb)->seq, tp->rcv_nxt)) {
		if (syn_inerr)
			TCP_INC_STATS_BH(sock_net(sk), TCP_MIB_INERRS);
		NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPABORTONSYN);
		tcp_reset(sk);
		return -1;
	}

	return 1;

discard:
	__kfree_skb(skb);
	return 0;
}