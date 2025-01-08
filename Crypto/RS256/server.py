import abc
import base64
import datetime
import hashlib
import json
import os
import sys
from urllib.parse import parse_qs, urlencode

from Crypto.Random.random import randrange
from Crypto.Util.number import bytes_to_long, getPrime, inverse, isPrime, long_to_bytes, size

from secret import FLAG


class RsaKey:
    def __init__(self):
        p = self.get_forward_prime()
        q = self.get_backward_prime()
        self.n = p * q * (q + 2)
        self.e = 0x10001
        self.d = inverse(self.e, (p - 1) * (q ** 2 - 1))

    @staticmethod
    def get_forward_prime() -> int:
        while True:
            p = 2
            while size(p) < 527:
                p *= getPrime(randrange(4, 17))
            if isPrime(p + 1):
                return p + 1

    @staticmethod
    def get_backward_prime() -> int:
        while True:
            p = getPrime(240)
            if isPrime(p) and isPrime(p + 2):
                return p

    @property
    def public_key(self) -> str:
        return json.dumps({"e": self.e, "n": self.n})

    @property
    def private_key(self) -> str:
        return json.dumps({"d": self.d, "n": self.n})

    def sign(self, message: bytes) -> bytes:
        return long_to_bytes(pow(bytes_to_long(message), self.d, self.n))

    def verify(self, message: bytes, signature: bytes) -> bool:
        return message == long_to_bytes(pow(bytes_to_long(signature), self.e, self.n))


class JWT256(abc.ABC):
    def __init__(self, secret: bytes):
        self.secret = secret

    @property
    def alg(self) -> bytes:
        return self.__class__.__name__.encode()

    @property
    def exp(self) -> datetime.timedelta:
        return datetime.timedelta(minutes=1)

    @property
    def typ(self) -> bytes:
        return b"JWT256"

    @classmethod
    def base64encode(cls, data: bytes) -> str:
        data = base64.b64encode(data).decode()
        data = data.replace("+", "-").replace("/", "_")
        return data.rstrip("=")

    @classmethod
    def base64decode(cls, data: str) -> bytes:
        data = data.replace("-", "+").replace("_", "/")
        data = data + "=" * (-len(data) % 4)
        return base64.b64decode(data.encode())

    def encode(self, payload: dict[bytes, bytes]) -> str:
        header = self.generate_header()
        body = self.generate_body(payload)
        signature = self.generate_signature(header + b"." + body)
        return ".".join(self.base64encode(payload) for payload in (header, body, signature))

    def decode(self, token: str) -> dict[bytes, list[bytes]]:
        header, body, signature = tuple(self.base64decode(payload) for payload in token.split("."))
        self.verify_header(header)
        self.verify_body(body)
        self.verify_signature(header + b"." + body, signature)
        return parse_qs(body)

    def generate_body(self, payload: dict[bytes, bytes]) -> bytes:
        payload[b"iat"] = f"{int(datetime.datetime.now().timestamp())}".encode()
        return urlencode(payload).encode()

    def generate_header(self) -> bytes:
        payload = {b"alg": self.alg, b"typ": self.typ}
        return urlencode(payload).encode()

    def generate_signature(self, message: bytes) -> bytes:
        return hashlib.sha256(self.secret + message).digest()

    def verify_body(self, body: bytes):
        issued_at = int(parse_qs(body)[b"iat"][-1].decode())
        if datetime.datetime.fromtimestamp(issued_at) + self.exp < datetime.datetime.now():
            raise ValueError("Verify body failed.")

    def verify_header(self, header: bytes):
        payload = parse_qs(header)
        if self.alg not in payload[b"alg"] or self.typ not in payload[b"typ"]:
            raise ValueError("Verify header failed.")

    def verify_signature(self, message: bytes, signature: bytes):
        if self.generate_signature(message) != signature:
            raise ValueError("Verify signature failed.")


class RS256(JWT256):
    def __init__(self, secret: bytes, key: RsaKey):
        super().__init__(secret)
        self.key = key

    def generate_signature(self, message: bytes) -> str:
        return self.key.sign(super().generate_signature(message))

    def verify_signature(self, message: bytes, signature: bytes):
        if not self.key.verify(super().generate_signature(message), signature):
            raise ValueError("Verify signature failed.")


def read_server():
    with open("./server.py", "r", encoding="utf-8") as file:
        print(file.read())


def main():
    provider = RS256(os.urandom(randrange(37, 43)), RsaKey())
    print(f"public_key: {provider.key.public_key}")
    while True:
        print("> register")
        print("> login")
        print("> server.py")
        print("> exit")
        cmd = input("> Command: ")
        if cmd == "exit":
            sys.exit()
        elif cmd == "register":
            username = input("> Input username: ").strip()
            token = provider.encode({b"username": username.encode(), b"admin": b"N"})
            print(f"Hi {username}, your token is: {token}")
        elif cmd == "login":
            data = provider.decode(input("> Input token: ").strip())
            username = b" ".join(data[b"username"]).decode()
            print(f"Hi {username}.")
            if b"Y" in data[b"admin"]:
                print(f"Administrator can read the flag: {FLAG}")
        elif cmd == "server.py":
            read_server()
        else:
            print("Bad hacker")


if __name__ == "__main__":
    try:
        main()
    except ValueError:
        print("Login failed.")
    except EOFError:
        sys.exit(1)
