# Cat Pictures 2 — Write-up

## Objective

Now with more Cat Pictures!

**Questions to answer:**

- What is Flag 1?
- What is Flag 2?
- What is Flag 3?

---

## Initial Recon

```bash
nmap -sS 10.81.128.169
```

```
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
222/tcp  open  rsh-spx
3000/tcp open  ppp
8080/tcp open  http-proxy
```

```bash
gobuster dir -w raft-medium-words.txt -u http://10.81.128.169 -x php,html,png,jpg,txt
```

```
/plugins              (Status: 301) [Size: 193] [--> http://10.81.128.169/plugins/]
/index.html           (Status: 200) [Size: 60906]
/LICENSE              (Status: 200) [Size: 1105]
/data                 (Status: 301) [Size: 193] [--> http://10.81.128.169/data/]
/uploads              (Status: 301) [Size: 193] [--> http://10.81.128.169/uploads/]
/docs                 (Status: 301) [Size: 193] [--> http://10.81.128.169/docs/]
/view.php             (Status: 200) [Size: 58172]
/php                  (Status: 301) [Size: 193] [--> http://10.81.128.169/php/]
/.                    (Status: 301) [Size: 193] [--> http://10.81.128.169/./]
/.htaccess            (Status: 200) [Size: 630]
/robots.txt           (Status: 200) [Size: 136]
/src                  (Status: 301) [Size: 193] [--> http://10.81.128.169/src/]
/dist                 (Status: 301) [Size: 193] [--> http://10.81.128.169/dist/]
/.git                 (Status: 301) [Size: 193] [--> http://10.81.128.169/.git/]
/.gitignore           (Status: 200) [Size: 274]
```

---

## Finding Flag 1 (Leaked Metadata)

On the main page there's a selection of cat photos. On the first image, it has a unique description: "note to self: strip metadata." After downloading the image and using exiftool on it, there's a piece of metadata that doesn't belong:

```
Title                           : :8080/764efa883dda1e11db47671c4a3bbd9e.txt
```

Visiting this link gives me:

```
note to self:

I setup an internal gitea instance to start using IaC for this server. It's at a quite basic state, but I'm putting the password here because I will definitely forget.
This file isn't easy to find anyway unless you have the correct url...

gitea: port 3000
user: samarium
password: TUmhyZ37CLZrhP

ansible runner (olivetin): port 1337
```

Going onto port 3000 and logging in with these details gave me the first flag.

**Flag 1:** `10d916##################be36b59538146bb5`

---

## Finding Flag 2 (Ansible Playbook RCE)

The hint for the second flag is "ansible," which is a huge hint. Sending a Burp request with **Run Ansible Playbook** responds with a `whoami` command in the log entry (`bismuth`).

Changing the command on the Gitea instance inside `playbook.yaml` to `cat flag2.txt` gave me the second flag.

**Flag 2:** `5e2cafbbf1#################2651c020`

---

## Getting a Shell

I managed to get the private RSA key through `cat .ssh/rsa_key` and used that key to log in via SSH.

---

## Finding Flag 3 (CVE-2021-3156 / Baron Samedit)

I couldn't find any obvious exploits, so I did some research and came across `linpeas.sh`. I downloaded it onto my own laptop, then set up a Python server and used `wget` on the victim machine to grab it, then ran it!

Linpeas found a possible exploit for Sudo version 1.8.21p2. After some research I found **CVE-2021-3156**.

Using a Git repo, `https://github.com/blasty/CVE-2021-3156`, I managed to get root privileges through this script. Finally, `cat /root/flag3.txt` gave me the last flag.

**Flag 3:** `6d2a9f8##########d565087a28a971`

---

## Summary

- **Recon:** Nmap showed SSH, HTTP, an odd `rsh-spx` on 222, a Gitea-flavored service on 3000, and an HTTP proxy on 8080. Gobuster mapped out the main site's structure, including an exposed `.git` directory.
- **Flag 1 — Metadata leak:** A cat photo's EXIF metadata contained a "hidden" URL that led to a note-to-self file with plaintext Gitea credentials and a mention of an internal Ansible runner (OliveTin) on port 1337.
- **Flag 2 — Ansible playbook abuse:** With Gitea access, editing the `playbook.yaml` used by the "Run Ansible Playbook" action allowed arbitrary command execution as the `bismuth` user, used to read `flag2.txt`.
- **Foothold:** An exposed private RSA key (`.ssh/rsa_key`) gave a stable SSH shell.
- **Flag 3 — Local privilege escalation:** `linpeas.sh` flagged a vulnerable Sudo version (1.8.21p2), which corresponds to **CVE-2021-3156** ("Baron Samedit") — a heap-based buffer overflow in `sudo`. A public exploit was used to gain root and read `flag3.txt`.

**Key takeaways:**

- Strip metadata from images before publishing them — EXIF fields (titles, GPS, comments) are an easy, often-overlooked way to leak URLs, paths, or notes.
- Storing plaintext credentials in a "hidden" file reachable by URL is still a leak, even if the file isn't linked anywhere — obscurity isn't access control.
- Automation tooling (Ansible/OliveTin runners, CI pipelines, etc.) that lets a user edit and execute a playbook is effectively remote code execution if reachable and under-authenticated.
- Keep infrastructure patched: CVE-2021-3156 affected a huge range of `sudo` versions and gave trivial local root: outdated `sudo` binaries are a near-guaranteed privesc path once a foothold is gained.
