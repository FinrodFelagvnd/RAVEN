static long kvm_s390_guest_sida_op(struct kvm_vcpu *vcpu,
				   struct kvm_s390_mem_op *mop)
{
	void __user *uaddr = (void __user *)mop->buf;
	int r = 0;

	if (mop->flags || !mop->size)
		return -EINVAL;
	if (mop->size + mop->sida_offset < mop->size)
		return -EINVAL;
	if (mop->size + mop->sida_offset > sida_size(vcpu->arch.sie_block))
		return -E2BIG;

	switch (mop->op) {
	case KVM_S390_MEMOP_SIDA_READ:
		if (copy_to_user(uaddr, (void *)(sida_origin(vcpu->arch.sie_block) +
				 mop->sida_offset), mop->size))
			r = -EFAULT;

		break;
	case KVM_S390_MEMOP_SIDA_WRITE:
		if (copy_from_user((void *)(sida_origin(vcpu->arch.sie_block) +
				   mop->sida_offset), uaddr, mop->size))
			r = -EFAULT;
		break;
	}
	return r;
}