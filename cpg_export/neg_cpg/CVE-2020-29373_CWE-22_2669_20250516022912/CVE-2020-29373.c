static inline void io_req_work_drop_env(struct io_kiocb *req)
{
	if (req->work.mm) {
		mmdrop(req->work.mm);
		req->work.mm = NULL;
	}
	if (req->work.creds) {
		put_cred(req->work.creds);
		req->work.creds = NULL;
	}
}