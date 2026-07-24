# grep — Write-up

## Objective

Welcome to the OSINT challenge, part of TryHackMe's Red Teaming Path. In this task, the goal is to act as an ethical hacker targeting a newly developed web application.

SuperSecure Corp, a fast-paced startup, is building a blogging platform and has invited security professionals to assess it. The challenge combines OSINT techniques — gathering information from publicly accessible sources — with exploiting vulnerabilities in the web application itself.

> **Note:** No local privilege escalation is necessary to answer the questions.

**Questions to answer:**

- What is the API key that allows a user to register on the website?
- What is the first flag?
- What is the email of the "admin" user?
- What is the host name of the web application that allows a user to check an email for a possible password leak?
- What is the password of the "admin" user?

---

## Initial Recon

```bash
nmap -sS -sV -sC -p- 10.81.178.72
```

```
PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http     Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
443/tcp   open  ssl/http Apache httpd 2.4.41
| ssl-cert: Subject: commonName=grep.thm/organizationName=SearchME/...
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
| http-title: Welcome
|_Requested resource was /public/html/
51337/tcp open  http     Apache httpd 2.4.41
|_http-title: 400 Bad Request
```

From this scan the first page was found: `10.81.178.72:443/public/html/`.

```bash
gobuster dir -w raft-medium-words.txt -u https://grep.thm/public/html -x php,txt,html,js -k --exclude-length 274
```

```
/admin.php            (Status: 403) [Size: 0]
/login.php            (Status: 200) [Size: 1981]
/index.php            (Status: 200) [Size: 1471]
/register.php         (Status: 200) [Size: 2346]
/logout.php           (Status: 200) [Size: 154]
/upload.php           (Status: 403) [Size: 0]
/.                    (Status: 200) [Size: 1471]
/dashboard.php        (Status: 403) [Size: 0]
```

---

## Finding the API Key (OSINT)

I'm going to work on the first question before going any deeper! I found an API key in `https://grep.thm/public/js/register.js`, but using that doesn't work.

I understand this is an OSINT challenge, so I tried to Google dork the API key using:

```
site:github.com SearchME API
```

I found a GitHub project with languages listed as "HACK." I assumed this was the correct repository. Going into `api/register.php` I found `X-THM-API-Key`, which confirmed my suspicion of this being the correct repository.

The API key wasn't directly visible, so I looked at the past updates and bam! Found the original API key!

```
ffe60ecaa8b#######b15b8f39
```

Using Burp to change the header to the new API key, I found I logged in and found the first flag!

**Flag:** `THM{4ec98######ccebb}`

---

## Bypassing the Upload Filter

There's no other clues or directions to go besides the previous Gobuster scan for `upload.php`. I tried uploading a reverse shell but I got the message:

```json
{"error":"Invalid file type. Only JPG, JPEG, PNG, and BMP files are allowed."}
```

I checked the repository and noticed there's a hex code checker in the API. I changed the hex code in the reverse shell using a hex editor, adding my own line before the PHP shell and changing the first hex line to `89504e47`. This let me successfully upload the shell.

After visiting `https://grep.thm/api/uploads/` and clicking the uploaded PHP file, I could create a reverse shell!

---

## Post-Exploitation

Going into the original website file path, `cd /var/www`, I found a backup folder containing an SQL user database, and from that I received the admin email:

```
admin@searchme2023cms.grep.thm
```

Inside I noticed another web application in the directory. I added a subdomain to my `/etc/hosts`:

```
leakchecker.grep.thm
```

and used the leftover port from the previous Nmap scan. Putting in the admin email from earlier, I got the admin password:

```
admin_tryhackme!
```

---

## Summary

- **Recon:** Nmap uncovered SSH, HTTP/HTTPS (with a `/public/html/` blog app), and a third HTTP service on an unusual port (`51337`). Gobuster mapped out the blog's login, registration, and admin/upload/dashboard endpoints (the latter three returning 403).
- **OSINT-driven key recovery:** A leaked API key in client-side JS didn't work as-is, but Google-dorking led to the app's GitHub repository, whose commit history contained the original, working API key — first flag.
- **Upload filter bypass:** `upload.php` validated files by checking magic bytes rather than trusting file extensions. Prepending the PNG signature (`89504E47`) to a PHP reverse shell was enough to pass validation while keeping the payload intact.
- **RCE → credential harvesting:** The uploaded shell gave code execution, leading to a backup SQL database (admin email) and a second, previously-unknown internal web app (`leakchecker.grep.thm`) reachable via the odd port from recon — which, given the admin email, handed back the admin password.

**Key takeaways:**

- API keys and secrets shouldn't live in client-side JavaScript, and rotating a leaked key is pointless if its full history is still sitting in a public (or dork-able) Git repository.
- Signature/magic-byte checks on file uploads are trivial to satisfy without giving up the malicious payload — validate content type *and* restrict what an uploaded file is allowed to do (e.g., no script execution in the upload directory).
- Non-standard ports found during recon are worth revisiting after gaining a foothold — they can point to entirely separate internal applications that don't show up in the main app's attack surface.
- Backup files and internal databases left reachable from a web shell can leak credentials for other, unrelated services.
