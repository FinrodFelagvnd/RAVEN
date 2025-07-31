void hci_conn_hash_flush(struct hci_dev *hdev)
{
	struct hci_conn_hash *h = &hdev->conn_hash;
	struct hci_conn *c, *n;

	BT_DBG("hdev %s", hdev->name);

	list_for_each_entry_safe(c, n, &h->list, list) {
		c->state = BT_CLOSED;

		hci_disconn_cfm(c, HCI_ERROR_LOCAL_HOST_TERM);
		hci_conn_del(c);
	}
}