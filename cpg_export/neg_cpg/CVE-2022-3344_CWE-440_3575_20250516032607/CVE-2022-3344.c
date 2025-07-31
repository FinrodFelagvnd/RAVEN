void svm_free_nested(struct vcpu_svm *svm)
{
	if (!svm->nested.initialized)
		return;

	svm_vcpu_free_msrpm(svm->nested.msrpm);
	svm->nested.msrpm = NULL;

	__free_page(virt_to_page(svm->nested.vmcb02.ptr));
	svm->nested.vmcb02.ptr = NULL;

	/*
	 * When last_vmcb12_gpa matches the current vmcb12 gpa,
	 * some vmcb12 fields are not loaded if they are marked clean
	 * in the vmcb12, since in this case they are up to date already.
	 *
	 * When the vmcb02 is freed, this optimization becomes invalid.
	 */
	svm->nested.last_vmcb12_gpa = INVALID_GPA;

	svm->nested.initialized = false;
}