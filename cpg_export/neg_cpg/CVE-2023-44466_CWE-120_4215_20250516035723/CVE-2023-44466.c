static int head_onwire_len(int ctrl_len, bool secure)
{
	int head_len;
	int rem_len;

	if (secure) {
		head_len = CEPH_PREAMBLE_SECURE_LEN;
		if (ctrl_len > CEPH_PREAMBLE_INLINE_LEN) {
			rem_len = ctrl_len - CEPH_PREAMBLE_INLINE_LEN;
			head_len += padded_len(rem_len) + CEPH_GCM_TAG_LEN;
		}
	} else {
		head_len = CEPH_PREAMBLE_PLAIN_LEN;
		if (ctrl_len)
			head_len += ctrl_len + CEPH_CRC_LEN;
	}
	return head_len;
}