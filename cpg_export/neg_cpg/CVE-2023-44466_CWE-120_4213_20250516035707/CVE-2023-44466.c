static int __tail_onwire_len(int front_len, int middle_len, int data_len,
			     bool secure)
{
	if (!front_len && !middle_len && !data_len)
		return 0;

	if (!secure)
		return front_len + middle_len + data_len +
		       CEPH_EPILOGUE_PLAIN_LEN;

	return padded_len(front_len) + padded_len(middle_len) +
	       padded_len(data_len) + CEPH_EPILOGUE_SECURE_LEN;
}