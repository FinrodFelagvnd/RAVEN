static const char *fuse_get_link(struct dentry *dentry, struct inode *inode,
				 struct delayed_call *callback)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct page *page;
	int err;

	err = -EIO;
	if (is_bad_inode(inode))
		goto out_err;

	if (fc->cache_symlinks)
		return page_get_link(dentry, inode, callback);

	err = -ECHILD;
	if (!dentry)
		goto out_err;

	page = alloc_page(GFP_KERNEL);
	err = -ENOMEM;
	if (!page)
		goto out_err;

	err = fuse_readlink_page(inode, page);
	if (err) {
		__free_page(page);
		goto out_err;
	}

	set_delayed_call(callback, page_put_link, page);

	return page_address(page);

out_err:
	return ERR_PTR(err);
}