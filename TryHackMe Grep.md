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

An API key was found in `https://grep.thm/public/js/register.js`, but it didn't work when used directly.

Since this is an OSINT challenge, I Google-dorked the key:

```
site:github.com SearchME API
```

This turned up a GitHub project tagged with the language "HACK." Digging into `api/register.php` in the repo revealed an `X-THM-API-Key` header, confirming this was the correct repository.

The current key in the repo wasn't valid on its own, so I checked the commit history — and found the *original* API key from a past update:

```
ffe60ecaa8b#######b15b8f39
```

Using Burp to swap in this key as the `X-THM-API-Key` header successfully logged me in, revealing the first flag.

**Flag:** `THM{4ec98######ccebb}`

---

## Bypassing the Upload Filter

With no further leads besides `upload.php` from the earlier Gobuster scan, I tried uploading a reverse shell directly:

```json
{"error":"Invalid file type. Only JPG, JPEG, PNG, and BMP files are allowed."}
```

Checking the repository showed the upload validation was based on a **hex signature check** rather than the file extension. Using a hex editor, I prepended the PNG magic bytes (`89504E47`) to the top of the reverse shell file, ahead of the actual PHP payload.

This satisfied the hex check and let the shell upload successfully. Visiting:

```
https://grep.thm/api/uploads/
```

and clicking the uploaded PHP file triggered the shell, giving remote code execution.

---

## Post-Exploitation

From the shell, I navigated to the site's original file path:

```bash
cd /var/www
```

This contained a `backup` folder with a SQL user database, from which I recovered the admin email:

```
admin@searchme2023cms.grep.thm
```

Inside the same directory I noticed **another** web application. I added a subdomain entry to `/etc/hosts`:

```
leakchecker.grep.thm
```

and combined it with the leftover port (`51337`) found during the initial Nmap scan. Submitting the admin email into that leak-checker application returned the admin password:

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
- Backup files and internal databases left reachable from a web shell can leak credentials for other, unrelated services.uploaded file is allowed to do (e.g., no script execution in the upload directory).
- Non-standard ports found during recon are worth revisiting after gaining a foothold — they can point to entirely separate internal applications that don't show up in the main app's attack surface.
- Backup files and internal databases left reachable from a web shell can leak credentials for other, unrelated services.
