import os
import imaplib
import email
import re
import requests
from typing import List


class EmailPoller:
    def __init__(self, ingest_url: str = None):
        self.imap_user = os.environ.get("IMAP_USER")
        self.imap_app_password = os.environ.get("IMAP_APP_PASSWORD")
        # default to local ingest endpoint used by the demo backend
        self.ingest_url = ingest_url or os.environ.get("INGEST_URL", "http://localhost:8000/ingest/email")

    def _extract_links(self, text: str) -> List[str]:
        if not text:
            return []
        links = re.findall(r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+", text)
        return links

    def poll_inbox(self):
        if not self.imap_user or not self.imap_app_password:
            return
        try:
            imap = imaplib.IMAP4_SSL("imap.gmail.com")
            imap.login(self.imap_user, self.imap_app_password)
            imap.select("INBOX")
            status, data = imap.search(None, "UNSEEN")
            if status != "OK":
                return
            # data[0] is space-separated bytes of message ids
            msg_nums = data[0].split()
            for num in msg_nums:
                status, msg_data = imap.fetch(num, "(RFC822)")
                if status != "OK":
                    continue
                raw_email = msg_data[0][1]
                email_message = email.message_from_bytes(raw_email)
                subject = email_message.get("Subject", "")
                links = self._extract_links(subject)
                # also check body
                body_text = ""
                if email_message.is_multipart():
                    for part in email_message.walk():
                        if part.get_content_type() == "text/plain":
                            try:
                                body_text += part.get_payload(decode=True).decode(errors="ignore")
                            except Exception:
                                pass
                else:
                    try:
                        body_text = email_message.get_payload(decode=True).decode(errors="ignore")
                    except Exception:
                        body_text = ""
                links += self._extract_links(body_text)
                if links:
                    # send to ingest endpoint
                    payload = {"description": f"Email with links: {links}", "confidence": 0.6, "title_hint": subject}
                    try:
                        requests.post(self.ingest_url, json=payload, timeout=5)
                    except Exception:
                        # best-effort, ignore failures
                        pass
            imap.logout()
        except Exception:
            # best-effort poller: swallow errors
            return
