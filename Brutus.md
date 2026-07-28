## `wtmp` Quick Definition

`wtmp` is a **binary Linux log file** that stores the **history of user logins, logouts, system boots, and shutdowns**. It is mainly used for **system administration, auditing, and digital forensics**.

Default location:

```bash
/var/log/wtmp
```

---

## Common Commands

| Command                  | Description                                                                    |
| ------------------------ | ------------------------------------------------------------------------------ |
| `last`                   | Display the login/logout history stored in `wtmp`.                             |
| `last <username>`        | Show the login history of a specific user.                                     |
| `last reboot`            | List all system reboot events.                                                 |
| `last shutdown`          | List all recorded shutdown events.                                             |
| `last -n <N>`            | Show only the last **N** entries.                                              |
| `last -f /path/to/wtmp`  | Read a specific `wtmp` file (e.g., an archived log).                           |
| `last -x`                | Include system events such as reboots, shutdowns, and runlevel changes.        |
| `lastb`                  | Display failed login attempts from `/var/log/btmp` (not `wtmp`).               |
| `who`                    | Show users currently logged in (reads `utmp`, not `wtmp`).                     |
| `w`                      | Display currently logged-in users and what they are doing (reads `utmp`).      |
| `utmpdump /var/log/wtmp` | Convert the binary `wtmp` file into a human-readable text format for analysis. |
| `ls -lh /var/log/wtmp*`  | List the current and archived `wtmp` log files.                                |

---

## Related Log Files

| File                                | Purpose                 | Command              |
| ----------------------------------- | ----------------------- | -------------------- |
| `/var/log/wtmp`                     | Login history           | `last`               |
| `/var/log/btmp`                     | Failed login attempts   | `lastb`              |
| `/var/run/utmp`                     | Current logged-in users | `who`, `w`           |
| `/var/log/auth.log` (Debian/Ubuntu) | Authentication events   | `grep`, `journalctl` |
| `/var/log/secure` (RHEL/CentOS)     | Authentication events   | `grep`, `journalctl` |

<img width="1016" height="258" alt="image" src="https://github.com/user-attachments/assets/2a1a7d32-9529-4e20-b21d-53863960aee8" />

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-

# simple utmp parser
# Reference
# http://man7.org/linux/man-pages/man5/utmp.5.html

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os, time, datetime, sys, csv, argparse, struct, io, ipaddress

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

parser = argparse.ArgumentParser(description="utmp parser")
parser.add_argument("input", help="specified input utmp file")
parser.add_argument("-o", "--output", help="specified output file name")
args = parser.parse_args()

input_file = args.input
output_file = args.output

row = ["type", "pid", "line", "id", "user", "host", "term", "exit", "session", "sec", "usec", "addr"]

def parseutmp(utmp_filesize, utmp_file, tsv):

  STATUS = {
    0: 'EMPTY',
    1: 'RUN_LVL',
    2: 'BOOT_TIME',
    3: 'NEW_TIME',
    4: 'OLD_TIME',
    5: 'INIT',
    6: 'LOGIN',
    7: 'USER',
    8: 'DEAD',
    9: 'ACCOUNTING'}
        
  record_field = []

  offset = 0
  while offset < utmp_filesize:
    utmp_file.seek(offset)
    type = struct.unpack("<L", utmp_file.read(4))[0]
    for k, v in STATUS.items():
      if type == k:
        type = v
    pid = struct.unpack("<L", utmp_file.read(4))[0]
    line = utmp_file.read(32).decode("utf-8", "replace").split('\0', 1)[0]
    id = utmp_file.read(4).decode("utf-8", "replace").split('\0', 1)[0]
    user = utmp_file.read(32).decode("utf-8", "replace").split('\0', 1)[0]
    host = utmp_file.read(256).decode("utf-8", "replace").split('\0', 1)[0]
    term = struct.unpack("<H", utmp_file.read(2))[0]
    exit = struct.unpack("<H", utmp_file.read(2))[0]
    session = struct.unpack("<L", utmp_file.read(4))[0]
    sec = struct.unpack("<L", utmp_file.read(4))[0]
    sec = time.strftime("%Y/%m/%d %H:%M:%S", time.localtime(float(sec)))
    usec = struct.unpack("<L", utmp_file.read(4))[0]
    addr = ipaddress.IPv4Address(struct.unpack(">L", utmp_file.read(4))[0])
    record_field.extend([type, pid, line, id, user, host, term, exit, session, sec, usec, addr])        
    csv.writer(tsv, delimiter="\t", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow(record_field)
    record_field = []
    offset += 384
  utmp_file.close()

if __name__ == '__main__':
  if os.path.exists(input_file):
    with open(input_file, "rb") as utmp_file:
      utmp_filesize = os.path.getsize(input_file)
      if output_file:
          tsv = open(output_file, "w", encoding='UTF-8')
      else:
          tsv = sys.stdout
      csv.writer(tsv, delimiter="\t", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow(row)
      parseutmp(utmp_filesize, utmp_file, tsv)
  else:
    print("No input file found")
  sys.exit(1)

```

<img width="451" height="115" alt="image" src="https://github.com/user-attachments/assets/ca87f850-d443-4b99-aed6-d061295df1ab" />

<img width="1165" height="82" alt="image" src="https://github.com/user-attachments/assets/7eeabc6b-a5de-43e6-a842-f8f48a58b6c2" />

<img width="1181" height="114" alt="image" src="https://github.com/user-attachments/assets/4296cc45-5517-4625-aa64-45d1c9b83c37" />

<img width="886" height="94" alt="image" src="https://github.com/user-attachments/assets/897f7f22-1342-404e-b346-d6cd3b658ca6" />

<img width="1762" height="766" alt="image" src="https://github.com/user-attachments/assets/8720424e-8d38-4f15-b576-02ce6d9d514c" />


<img width="864" height="108" alt="image" src="https://github.com/user-attachments/assets/1576954f-bbde-41b8-9583-d228bb9271fa" />

<img width="1544" height="125" alt="image" src="https://github.com/user-attachments/assets/eda59676-1d58-45d6-b93c-56eaec3129b9" />

