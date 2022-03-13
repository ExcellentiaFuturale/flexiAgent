#! /usr/bin/python3

import os
from datetime import datetime

log_file = "__VPN_SCRIPTS_LOG_FILE__"

def logger(str):
    date = datetime.today().strftime('%b %d %H:%M:%S')
    os.system(f'echo "{date}: {str}" >> {log_file}')
