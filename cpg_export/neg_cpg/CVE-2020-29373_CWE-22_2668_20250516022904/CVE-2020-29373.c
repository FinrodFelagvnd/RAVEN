static inline void io_req_work_grab_env(struct io_kiocb *req,
					const struct io_op_def *def)
{
	if (!req->work.mm && def->needs_mm) {
		mmgrab(current->mm);
		req->work.mm = current->mm;
	}
	if (!req->work.creds)
		req->work.creds = get_current_cred();
}