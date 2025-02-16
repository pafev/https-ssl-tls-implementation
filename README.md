# self HTTPS-SSL-TLS protocol

## HTTPS protocol

HTTPS is basically a protocol that acts over HTTP, but with TLS/SSL certificates.

These certificates guarantee security in a communication between a server and a
client, while using HTTPS. Essentially, TLS and SSL are protocols that offer
encryption for packets that travelling on the internet (SSL is an older
version of TLS).

## TLS/SSL protocol

SSL is an older version of TLS, but the names can sometimes be confused and we can
speak of the same protocol as SSL or TLS or SSL/TLS

Basically, this protocol guarantees an extra layer of security over HTTP, establishing
encrypted message exchange over HTTP messages.

The protocol steps consist of a handshake to exchange keys, using asymmetric cryptography.
Once the shared keys has been exchanged, symmetric encryption now takes
place, using this key to encrypt the HTTP messages.

## How to run software

1 - Setup env

```bash
cd src/
python3 -m venv venv
source venv/bin/activate
```

2 - Install dependencies

```bash
pip install -e .
```

3 - Run server

```bash
python3 server/main.py
```

4 - Run client in another bash (open another bash and repeat step 1)

```bash
python3 client/main.py
```

Note: To get out of the env

```bash
deactivate
```
