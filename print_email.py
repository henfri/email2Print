import imapclient
import email
import os
import logging
import tempfile
import subprocess
import smtplib
import time
import re
from email.message import EmailMessage
from email.header import decode_header
import io

# Logging setup
log_formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger()
logger.setLevel(logging.INFO)

console_handler = logging.StreamHandler()
console_handler.setFormatter(log_formatter)
logger.addHandler(console_handler)

file_handler = logging.FileHandler("email2print.log")
file_handler.setFormatter(log_formatter)
logger.addHandler(file_handler)

def get_env_var(name, required=False, default=None):
    val = os.getenv(name)
    if val is None or val == "":
        if required:
            logger.error(f"Missing required environment variable: {name}")
            raise ValueError(f"Missing required environment variable: {name}")
        return default
    return val

# --- Configuration ---
EMAIL_ACCOUNT = get_env_var("EMAIL_ACCOUNT", required=True)
EMAIL_PASSWORD = get_env_var("EMAIL_PASSWORD", required=True)

SMTP_USERNAME = get_env_var("SMTP_USERNAME", default=EMAIL_ACCOUNT)
SMTP_PASSWORD = get_env_var("SMTP_PASSWORD", default=EMAIL_PASSWORD)
FROM_ADDRESS   = get_env_var("FROM_ADDRESS", default=EMAIL_ACCOUNT)

SMTP_SERVER = get_env_var("SMTP_SERVER", required=True)
SMTP_PORT = int(get_env_var("SMTP_PORT", required=True))

PRINTER_NAME = get_env_var("PRINTER_NAME", required=True)
SLEEP_TIME = int(get_env_var("SLEEP_TIME", default=60))

CONFIRM_SUBJECT = get_env_var("CONFIRM_SUBJECT", default="Your Print Job Confirmation")
ALLOWED_ATTACHMENT_TYPES = [ext.strip().lower() for ext in get_env_var("ALLOWED_ATTACHMENT_TYPES", default="").split(",") if ext]
ALLOWED_RECIPIENTS = [addr.strip().lower() for addr in get_env_var("ALLOWED_RECIPIENTS", default="").split(",") if addr]

DETAILED_CONFIRMATION = get_env_var("DETAILED_CONFIRMATION", default="false").lower() == "true"
DELETE_AFTER_PRINT = get_env_var("DELETE_AFTER_PRINT", default="false").lower() == "true"
PRINT_ONLY_ATTACHMENTS = get_env_var("PRINT_ONLY_ATTACHMENTS", default="false").lower() == "true"

# --- NEUE VARIABLE ---
ONLY_ALLOW_SAME_DOMAIN = get_env_var("ONLY_ALLOW_SAME_DOMAIN", default="true").lower() == "true"
# ---------------------

def decode_mime_words(s):
    if not s: return ""
    return ''.join(part.decode(enc or 'utf-8') if isinstance(part, bytes) else part for part, enc in decode_header(s))

def is_mostly_html_blank(html):
    return re.sub(r"<[^>]+>", "", html or "").strip() == ""

def print_file(file_path):
    try:
        subprocess.run(["lp", "-d", PRINTER_NAME, file_path], check=True)
        logger.info(f"Sent to printer: {PRINTER_NAME} - File: {file_path}")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Printing failed for {file_path}: {e}")
        return False

def send_confirmation_email(to_email, log_text, printed_files):
    msg = EmailMessage()
    msg["Subject"] = CONFIRM_SUBJECT
    msg["From"] = FROM_ADDRESS
    msg["To"] = to_email
    
    if DETAILED_CONFIRMATION:
        msg.set_content(f"Your print job was processed:\n\n{log_text}")
    else:
        lines = [f"Printed: {fname}" for fname in printed_files]
        msg.set_content("\n".join(lines) if lines else "No printable content found (or filtered by rules).")

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=20) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(msg)
    except Exception as e:
        logger.error(f"Error sending confirmation: {e}")

def process_email(msg):
    from_addr = email.utils.parseaddr(msg.get("From"))
