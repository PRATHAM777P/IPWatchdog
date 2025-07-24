import re
import sys
import os
import logging

# Setup logging
logging.basicConfig(filename='ipwatchdog.log', level=logging.INFO, format='%(asctime)s %(levelname)s:%(message)s')

# Allow log file as argument
log_file = 'access_log.txt'
if len(sys.argv) > 1:
    log_file = sys.argv[1]

if not os.path.exists(log_file):
    logging.error(f'Log file {log_file} does not exist.')
    print(f'Error: Log file {log_file} does not exist.')
    sys.exit(1)

ip = []
try:
    with open(log_file, 'r') as file1:
        p = re.compile(r'^(\d{1,3}(?:\.\d{1,3}){3})')
        z = re.compile(r"\[([^\]]+)\]")
        u = re.compile(r'"([A-Z]+ [^ ]+ HTTP/[0-9.]+)"')
        for line in file1:
            c = p.findall(line)
            da = z.findall(line)
            ur = u.findall(line)
            if len(c) == 0 or len(da) == 0 or len(ur) == 0:
                logging.warning(f'Malformed line skipped: {line.strip()}')
                continue
            c.append(da[0])
            c.append(ur[0])
            ip.append(c)
except Exception as e:
    logging.error(f'Error reading log file: {e}')
    print(f'Error reading log file: {e}')
    sys.exit(1)

import pandas as pd

df = pd.DataFrame(ip, columns=['IP', 'DATE', 'URL'])
try:
    df.to_csv('ip_set.csv', index=False)
    logging.info(f'Successfully wrote ip_set.csv with {len(df)} records.')
except Exception as e:
    logging.error(f'Error writing ip_set.csv: {e}')
    print(f'Error writing ip_set.csv: {e}')
    sys.exit(1)
