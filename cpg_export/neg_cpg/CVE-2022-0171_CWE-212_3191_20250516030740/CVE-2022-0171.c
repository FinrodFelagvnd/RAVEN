static __always_inline int kvm_handle_hva_range(struct mmu_notifier *mn,
						unsigned long start,
						unsigned long end,
						pte_t pte,
						hva_handler_t handler)
{
	struct kvm *kvm = mmu_notifier_to_kvm(mn);
	const struct kvm_hva_range range = {
		.start		= start,
		.end		= end,
		.pte		= pte,
		.handler	= handler,
		.on_lock	= (void *)kvm_null_fn,
		.flush_on_ret	= true,
		.may_block	= false,
	};

	return __kvm_handle_hva_range(kvm, &range);
}