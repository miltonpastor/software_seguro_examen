import threading
from datetime import datetime

LOG_FILE = "custom_logs.txt"
log_lock = threading.Lock()

def write_custom_log(log_type, remote_ip, username, action, http_code):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    log_entry = f"{now} | {log_type} | {remote_ip} | {username} | {action} | {http_code}\n"
    with log_lock:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(log_entry)
