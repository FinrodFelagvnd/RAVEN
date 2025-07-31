static bool signed_sub32_overflows(s32 a, s32 b)
{
	/* Do the sub in u64, where overflow is well-defined */
	s32 res = (s32)((u32)a - (u32)b);

	if (b < 0)
		return res < a;
	return res > a;
}