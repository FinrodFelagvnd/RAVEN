static int prb_calc_retire_blk_tmo(struct packet_sock *po,
				int blk_size_in_bytes)
{
	struct net_device *dev;
	unsigned int mbits = 0, msec = 0, div = 0, tmo = 0;
	struct ethtool_link_ksettings ecmd;
	int err;

	rtnl_lock();
	dev = __dev_get_by_index(sock_net(&po->sk), po->ifindex);
	if (unlikely(!dev)) {
		rtnl_unlock();
		return DEFAULT_PRB_RETIRE_TOV;
	}
	err = __ethtool_get_link_ksettings(dev, &ecmd);
	rtnl_unlock();
	if (!err) {
		/*
		 * If the link speed is so slow you don't really
		 * need to worry about perf anyways
		 */
		if (ecmd.base.speed < SPEED_1000 ||
		    ecmd.base.speed == SPEED_UNKNOWN) {
			return DEFAULT_PRB_RETIRE_TOV;
		} else {
			msec = 1;
			div = ecmd.base.speed / 1000;
		}
	}

	mbits = (blk_size_in_bytes * 8) / (1024 * 1024);

	if (div)
		mbits /= div;

	tmo = mbits * msec;

	if (div)
		return tmo+1;
	return tmo;
}