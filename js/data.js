const SVC={
  20:'FTP-Data',21:'FTP',22:'SSH',23:'Telnet',25:'SMTP',53:'DNS',
  67:'DHCP',69:'TFTP',80:'HTTP',110:'POP3',111:'RPC',119:'NNTP',
  123:'NTP',135:'MS-RPC',137:'NetBIOS-NS',138:'NetBIOS-DGM',
  139:'NetBIOS-SSN',143:'IMAP',161:'SNMP',162:'SNMP-Trap',179:'BGP',
  194:'IRC',389:'LDAP',443:'HTTPS',445:'SMB',465:'SMTPS',514:'Syslog',
  515:'LPD',548:'AFP',587:'SMTP-Sub',631:'IPP',636:'LDAPS',
  873:'rsync',993:'IMAPS',995:'POP3S',1080:'SOCKS5',1194:'OpenVPN',
  1433:'MSSQL',1521:'Oracle-DB',1723:'PPTP',2049:'NFS',
  2082:'cPanel',2083:'cPanel-SSL',2121:'FTP-Alt',2375:'Docker',
  2376:'Docker-TLS',3000:'Grafana/Dev',3306:'MySQL',3389:'RDP',
  3690:'SVN',4369:'RabbitMQ-EPM',4444:'Metasploit',5000:'Flask/Dev',
  5432:'PostgreSQL',5672:'AMQP',5900:'VNC',5901:'VNC-2',
  5985:'WinRM-HTTP',5986:'WinRM-HTTPS',6379:'Redis',
  6667:'IRC',7001:'WebLogic',8000:'HTTP-Dev',8080:'HTTP-Alt',
  8443:'HTTPS-Alt',8888:'Jupyter',9000:'PHP-FPM',9200:'Elasticsearch',
  9300:'Elasticsearch-T',11211:'Memcached',15672:'RabbitMQ-Mgmt',
  27017:'MongoDB',27018:'MongoDB-S',28017:'MongoDB-Web',50000:'IBM-DB2'
};

const BANNERS={
  22:'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1',
  80:'Apache/2.4.54 (Ubuntu) PHP/8.1.12',
  443:'nginx/1.23.1',
  21:'220 vsftpd 3.0.5',
  25:'220 mail.target.local ESMTP Postfix (Ubuntu)',
  3306:'5.7.39-MySQL Community Server',
  5432:'PostgreSQL 14.5 on x86_64-pc-linux-gnu',
  3389:'NTLM: Protocol 10.0.19041 — Windows 10/Server 2019',
  6379:'Redis 7.0.5 (no auth)',
  9200:'Elasticsearch 8.5.0 cluster: my-cluster',
  27017:'MongoDB 6.0.2 — unauthorized',
  5900:'RFB 003.008 — VNC (no auth)',
  8080:'Apache-Coyote/1.1 — Tomcat/9.0.68',
  5985:'Microsoft-HTTPAPI/2.0 — WinRM',
  23:'Linux telnetd — Kernel 5.4.0',
  7001:'WebLogic Server 12.2.1.4.0',
  11211:'Memcached 1.6.17',
  2375:'Docker daemon API 1.41'
};

const VULNS_DB={
  21:{sev:'high',title:'FTP Anonymous Login / vsftpd Backdoor',cve:'CVE-2011-2523',desc:'vsftpd 2.3.4 contains a backdoor on port 6200. Anonymous FTP login may expose file system contents. Recommend disabling anonymous access.'},
  22:{sev:'medium',title:'SSH Weak Cipher Suite / Deprecated Algorithms',cve:'CVE-2023-38408',desc:'Deprecated key exchange algorithms detected: diffie-hellman-group1-sha1. Weak ciphers: arcfour, 3des-cbc. Brute-force attacks possible if rate limiting not configured.'},
  23:{sev:'critical',title:'Telnet — Plaintext Credential Transmission',cve:'CWE-319',desc:'Telnet transmits all data including credentials in cleartext. Trivially intercepted with passive sniffing. Replace with SSH immediately.'},
  80:{sev:'medium',title:'HTTP TRACE Enabled — Cross-Site Tracing (XST)',cve:'CVE-2004-2320',desc:'HTTP TRACE method is enabled which can be used to steal credentials via XST attacks. Disable TRACE in web server configuration.'},
  443:{sev:'low',title:'Deprecated TLS Versions Supported',cve:'CVE-2011-3389',desc:'Server accepts TLS 1.0 and TLS 1.1 which are deprecated. BEAST and POODLE attacks possible. Upgrade to TLS 1.2/1.3 minimum.'},
  445:{sev:'critical',title:'SMB EternalBlue / SMBGhost',cve:'CVE-2017-0144',desc:'SMB exposed on network. EternalBlue (MS17-010) enables remote code execution without authentication. SMBGhost (CVE-2020-0796) also applicable. Patch immediately.'},
  3389:{sev:'critical',title:'BlueKeep — Remote Desktop RCE',cve:'CVE-2019-0708',desc:'BlueKeep vulnerability allows unauthenticated remote code execution via RDP. Pre-authentication, no user interaction needed. CVSS 9.8. Apply MS19-0708 patch immediately.'},
  5432:{sev:'medium',title:'PostgreSQL Default Configuration Exposed',cve:'CVE-2019-10164',desc:'PostgreSQL accessible on network interface. Check pg_hba.conf for trust authentication. Default postgres user may have no password set.'},
  6379:{sev:'critical',title:'Redis Exposed Without Authentication',cve:'CVE-2022-0543',desc:'Redis is accessible without authentication. Attackers can read/write arbitrary data, achieve RCE via SLAVEOF command or Lua sandbox escape. Bind to localhost or require auth.'},
  8080:{sev:'medium',title:'Tomcat Manager / Default Credentials',cve:'CVE-2020-1938',desc:'Apache Tomcat manager interface exposed. Default credentials admin:admin or tomcat:tomcat may work. Ghostcat (CVE-2020-1938) AJP file inclusion if AJP port open.'},
  9200:{sev:'critical',title:'Elasticsearch Open — Unauthenticated Data Access',cve:'CVE-2021-22145',desc:'Elasticsearch exposed without authentication. All indices including sensitive data accessible to anyone. Enable X-Pack security or bind to localhost.'},
  27017:{sev:'critical',title:'MongoDB — No Authentication Required',cve:'CVE-2017-2612',desc:'MongoDB accepting connections without credentials. All databases and collections readable and writable. Enable --auth flag and create admin user immediately.'},
  11211:{sev:'high',title:'Memcached DDoS Amplification Vector',cve:'CVE-2018-1000115',desc:'Memcached UDP exposed. Can be used for amplification DDoS attacks (amplification factor up to 51,000x). Disable UDP or firewall port 11211.'},
  2375:{sev:'critical',title:'Docker Daemon API Exposed — Container Escape',cve:'CVE-2019-5736',desc:'Docker API accessible without TLS. Attackers can list containers, exec commands, mount host filesystem, escape to root on host. Bind only to unix socket or use TLS client certs.'},
  7001:{sev:'critical',title:'WebLogic Deserialization RCE',cve:'CVE-2023-21839',desc:'Oracle WebLogic Server IIOP/T3 deserialization vulnerability. Unauthenticated remote code execution. Multiple CVEs: 2019-2729, 2020-14882, 2023-21839. Patch to latest.'},
  5900:{sev:'high',title:'VNC — No Authentication',cve:'CVE-2006-2369',desc:'VNC server accessible without password. Full graphical desktop control exposed. Enable VNC password and consider SSH tunneling.'},
};

const OS_PROFILES=[
  {os:'Ubuntu 22.04 LTS (Jammy Jellyfish)',kernel:'5.15.0-76-generic',arch:'x86_64',ttl:64,prob:87,vendor:'Canonical'},
  {os:'Ubuntu 20.04.6 LTS (Focal Fossa)',kernel:'5.4.0-155-generic',arch:'x86_64',ttl:64,prob:8,vendor:'Canonical'},
  {os:'Debian 11 (Bullseye)',kernel:'5.10.0-26-amd64',arch:'x86_64',ttl:64,prob:4,vendor:'Debian'},
  {os:'Linux 4.15–5.x (generic)',kernel:'unknown',arch:'x86_64',ttl:64,prob:1,vendor:'Open Source'},
  {os:'Windows Server 2019/2022',kernel:'10.0',arch:'x86_64',ttl:128,prob:75,vendor:'Microsoft'},
  {os:'Windows 10/11 Pro',kernel:'10.0',arch:'x86_64',ttl:128,prob:20,vendor:'Microsoft'},
  {os:'macOS 13 Ventura',kernel:'22.x',arch:'arm64',ttl:64,prob:15,vendor:'Apple'}
];

const DEEP_DETAILS = {
  21: {
    mitre: "T1046: Network Service Discovery\nMitigation: Disable anonymous login, enforce FTPS/SFTP over TLS 1.2+, implement strict IP allowlisting.",
    hex: "0000   32 32 30 20 28 76 73 66 74 70 64 20 33 2e 30 2e   220 (vsftpd 3.0.\n0010   33 29 0d 0a                                       3).."
  },
  22: {
    mitre: "T1110: Brute Force\nMitigation: Disable root login, enforce key-based authentication, use fail2ban to rate-limit connections.",
    hex: "0000   53 53 48 2d 32 2e 30 2d 4f 70 65 6e 53 53 48 5f   SSH-2.0-OpenSSH_\n0010   38 2e 39 70 31 20 55 62 75 6e 74 75 0d 0a         8.9p1 Ubuntu.."
  },
  23: {
    mitre: "T1040: Network Sniffing\nMitigation: Deprecate Telnet immediately. Replace with SSH. Block port 23 at the network perimeter.",
    hex: "0000   ff fd 18 ff fd 20 ff fd 23 ff fd 27               ..... ..#..'"
  },
  80: {
    mitre: "T1190: Exploit Public-Facing Application\nMitigation: Deploy Web Application Firewall (WAF), enforce HTTPS (HSTS), patch web server software.",
    hex: "0000   48 54 54 50 2f 31 2e 31 20 32 30 30 20 4f 4b 0d   HTTP/1.1 200 OK.\n0010   0a 53 65 72 76 65 72 3a 20 41 70 61 63 68 65 0d   .Server: Apache."
  },
  443: {
    mitre: "T1190: Exploit Public-Facing Application\nMitigation: Use strong Cipher Suites, enforce TLS 1.2/1.3, rotate certificates regularly.",
    hex: "0000   16 03 03 00 5a 02 00 00 56 03 03 64 59 18 2a 12   ....Z...V..dY.*.\n0010   34 56 78 90 12 34 56 78 90 12 34 56 78 90 12 34   4Vx..4Vx..4Vx..4"
  },
  445: {
    mitre: "T1210: Exploitation of Remote Services (EternalBlue)\nMitigation: Disable SMBv1, require SMB signing, segment network to isolate endpoints.",
    hex: "0000   00 00 00 85 ff 53 4d 42 72 00 00 00 00 18 53 c0   .....SMBr.....S.\n0010   00 00 00 00 00 00 00 00 00 00 00 00 00 00 ff fe   ................"
  },
  3389: {
    mitre: "T1133: External Remote Services\nMitigation: Place RDP behind a VPN/Gateway, enforce MFA, enable Network Level Authentication (NLA).",
    hex: "0000   03 00 00 13 0e e0 00 00 00 00 00 01 00 08 00 03   ................\n0010   00 00 00                                          ..."
  },
  3306: {
    mitre: "T1190: Exploit Public-Facing Application (SQLi)\nMitigation: Do not expose databases to public internet. Bind to localhost or private VPC subnet.",
    hex: "0000   4a 00 00 00 0a 35 2e 37 2e 33 39 00 08 00 00 00   J....5.7.39.....\n0010   45 56 67 43 21 34 56 78 00 ff ff 08 02 00 ff c1   EVgC!4Vx........"
  },
  5432: {
    mitre: "T1046: Network Service Discovery\nMitigation: Secure pg_hba.conf, enforce SCRAM-SHA-256 passwords, use TLS connections.",
    hex: "0000   52 00 00 00 08 00 00 00 00                        R........"
  },
  6379: {
    mitre: "T1059.006: Python (Lua Sandbox Escape)\nMitigation: Set 'requirepass' in redis.conf, use 'rename-command' to disable dangerous commands.",
    hex: "0000   2d 4e 4f 41 55 54 48 20 41 75 74 68 65 6e 74 69   -NOAUTH Authenti\n0010   63 61 74 69 6f 6e 20 72 65 71 75 69 72 65 64 2e   cation required."
  },
  27017: {
    mitre: "T1046: Network Service Discovery\nMitigation: Enable role-based access control (RBAC), enable internal authentication, disable bind_ip_all.",
    hex: "0000   3b 00 00 00 01 00 00 00 00 00 00 00 d4 07 00 00   ;...............\n0010   00 00 00 00 00 00 00 00                           ........"
  }
};

// Exporting to global scope for our separated files
window.SVC = SVC;
window.BANNERS = BANNERS;
window.VULNS_DB = VULNS_DB;
window.OS_PROFILES = OS_PROFILES;
window.DEEP_DETAILS = DEEP_DETAILS;
