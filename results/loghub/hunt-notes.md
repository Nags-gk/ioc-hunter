# Hunt notes: real OpenSSH server log (Loghub)

Source: Loghub OpenSSH dataset (https://zenodo.org/records/8196385/files/SSH.tar.gz, sha256 `296610a35773f58b...`). 655,147 lines over 28 days. The log has no year; dates below use a placeholder year.

## Scale

- 367,393 failed authentication events from **1,011 sources**; 316,601 of them (86%) targeted `root`.
- 182 successful logins to 9 accounts from 42 sources.
- Sigma: `ssh_bruteforce` fired 2,066 times (source x 10-minute window); `ssh_root_login` 0, `linux_uid0_account` 0, `sudo_download_execute` 0 (this log has no sudo or useradd lines).

## Hypothesis 1: a brute-forcing source got in. Not supported.

No source with 20 or more failures ever logged in. Of 42 sources with a successful login, 8 had any failures at all (at most 13):

| Source | Logged in as | Failures | Usernames that failed |
|---|---|---:|---|
| 218.17.80.182 | zachary | 13 | zachary |
| 111.222.107.90 | hxu | 11 | hxu |
| 123.255.103.142 | curi | 7 | curi |
| 113.99.127.215 | suyuxin | 2 | suyuxin |
| 183.62.156.108 | fztu, suyuxin, jmzhu | 2 | root |
| 61.187.54.9 | curi | 2 | curi |
| 137.189.204.253 | hxu | 1 | hxu |
| 137.189.204.138 | hxu | 1 | hxu |

Most are a handful of failures on the same account that then succeeds, the pattern of a mistyped password. The exception is noted under hypothesis 2.

## Hypothesis 2: credentials are shared or stolen. Two leads.

- 183.62.156.108 logged in successfully to 3 accounts (fztu, jmzhu, suyuxin); check for shared NAT before treating as compromise
- 137.189.88.215 logged in successfully to 3 accounts (curi, suyuxin, yuewang); check for shared NAT before treating as compromise
  - Same /16 as 183.62.156.108: 183.62.140.253 (22,115 failed attempts on 51 usernames); 183.62.232.144 (128 failed attempts on 1 usernames)
  - Same /16 as 137.189.88.215: 137.189.204.138 (1 failed attempts on 1 usernames); 137.189.204.253 (1 failed attempts on 1 usernames)

Both are consistent with a shared campus or lab gateway. Next step: ask the account owners, and compare these sources with each account's usual login locations.

## Hypothesis 3: the noise is a few operators, not a thousand. Supported.

8 groups of sources replayed identical username dictionaries, often with identical attempt counts, which points to shared tooling or one operator rotating IPs:

- 3 sources replayed the same 16-username list (0, 0101, 1234, admin, default, ftp...); attempts per source: 846, 1058, 1191; active 12-10 to 01-07
- 2 sources replayed the same 51-username list (123, 123456, Test, apache, apache1, apache2...); attempts per source: 21704; active 12-10 to 12-30
- 2 sources replayed the same 52-username list (CentOS, PlcmSpIp, admin, apache, cron, debian...); attempts per source: 809, 918; active 12-31 to 01-02
- 8 sources replayed the same 18-username list (admin, alarm, cirros, debian, ethos, guest...); attempts per source: 122; active 12-12 to 01-04
- 2 sources replayed the same 13-username list (admin, baku, debian, guest, oracle, pi...); attempts per source: 101; active 01-04 to 01-04
- 3 sources replayed the same 25-username list (admin, cashier, dspace, git, gpadmin, hadoop...); attempts per source: 126; active 12-11 to 12-19
- 2 sources replayed the same 7-username list (admin, root, support, telnet, test, ubnt...); attempts per source: 158, 402; active 12-11 to 01-02
- 2 sources replayed the same 37-username list (alex, anna, desktop, ftpuser, gast, git...); attempts per source: 884; active 12-13 to 01-02

## Recommendations for this server

1. Disable password authentication for SSH (`PasswordAuthentication no`) and root login (`PermitRootLogin no`); 86% of guessing targets root.
2. Rate-limit new SSH connections per source (fail2ban or nftables meters) to cut log volume and guessing speed.
3. Alert on the sequence rule (failures then success from one source); it found nothing here, which is the expected baseline.
4. Feed the dictionary fingerprints into blocklists by tool signature rather than by single IP.
