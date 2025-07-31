static int retrieve_ptr_limit(const struct bpf_reg_state *ptr_reg,
			      u32 *ptr_limit, u8 opcode, bool off_is_neg)
{
	bool mask_to_left = (opcode == BPF_ADD &&  off_is_neg) ||
			    (opcode == BPF_SUB && !off_is_neg);
	u32 off;

	switch (ptr_reg->type) {
	case PTR_TO_STACK:
		/* Indirect variable offset stack access is prohibited in
		 * unprivileged mode so it's not handled here.
		 */
		off = ptr_reg->off + ptr_reg->var_off.value;
		if (mask_to_left)
			*ptr_limit = MAX_BPF_STACK + off;
		else
			*ptr_limit = -off;
		return 0;
	case PTR_TO_MAP_VALUE:
		if (mask_to_left) {
			*ptr_limit = ptr_reg->umax_value + ptr_reg->off;
		} else {
			off = ptr_reg->smin_value + ptr_reg->off;
			*ptr_limit = ptr_reg->map_ptr->value_size - off;
		}
		return 0;
	default:
		return -EINVAL;
	}
}