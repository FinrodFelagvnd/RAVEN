static inline bool spectre_v2_in_ibrs_mode(enum spectre_v2_mitigation mode)
{
	return mode == SPECTRE_V2_IBRS ||
	       mode == SPECTRE_V2_EIBRS ||
	       mode == SPECTRE_V2_EIBRS_RETPOLINE ||
	       mode == SPECTRE_V2_EIBRS_LFENCE;
}