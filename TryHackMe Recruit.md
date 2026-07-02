# Recruit
Recruit has just launched its new recruitment portal, allowing HR staff to manage candidate applications and administrators to oversee hiring decisions. While the platform appears functional, management suspects that security may have been overlooked during development. Your task is to assess the application like a real attacker, mapping its structure, abusing exposed functionality, and exploiting vulnerabilities.

Can you gain an initial foothold, escalate your access, and ultimately log in as the administrator?
Answer the questions below

What is the flag value after logging in as a normal user?

What is the flag value after logging in as admin?

Let's start with some basic reconnisance to discover some secrets!

---

nmap -sS 10.81.182.40
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
gobuster dir -w raft-medium-directories.txt -u http://10.81.182.40 -x html, php, txt, js
```
assets               (Status: 301) [Size: 313] [--> http://10.81.182.40/assets/]
mail                 (Status: 301) [Size: 311] [--> http://10.81.182.40/mail/]
javascript           (Status: 301) [Size: 317] [--> http://10.81.182.40/javascript/]
phpmyadmin           (Status: 301) [Size: 317] [--> http://10.81.182.40/phpmyadmin/]
server-status        (Status: 403) [Size: 277]
Progress: 89997 / 89997 (100.00%)
```
