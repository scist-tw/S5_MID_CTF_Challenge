import itertools
import json
import sys
import typing

from Crypto.Random.random import randrange
from Crypto.Util.number import bytes_to_long, getPrime, isPrime, long_to_bytes

from secret import FLAG


class ElGamal:
    def __init__(self, nbit: int = 1024):
        self.nbyte = nbit // 8
        self.p = getPrime(nbit)
        self.g = self.gen_generator()
        self.x = randrange(2, self.p - 2)
        self.y = pow(self.g, self.x, self.p)

    def gen_generator(self) -> int:
        for g in self.gen_prime():
            if pow(g, (self.p - 1) // 2, self.p) == self.p - 1:
                return g

        raise ValueError("It's impossible to get here.")

    @staticmethod
    def gen_prime() -> typing.Generator[int, None, None]:
        yield from (2, 3)
        for k in itertools.count(5, 6):
            if isPrime(k):
                yield k
            if isPrime(k + 2):
                yield k + 2

    @property
    def public_key(self) -> str:
        return json.dumps({"g": self.g, "y": self.y, "p": self.p})

    def encrypt(self, plaintext: bytes) -> bytes:
        m = bytes_to_long(plaintext)
        assert 0 < m < self.p
        k = randrange(2, self.p - 2)
        c1 = pow(self.g, k, self.p)
        c2 = m * pow(self.y, k, self.p) % self.p
        return b"".join(
            c.to_bytes(self.nbyte, byteorder="big")
            for c in (c1, c2)
        )

    def decrypt(self, ciphertext: bytes) -> bytes:
        assert len(ciphertext) == 2 * self.nbyte
        c1, c2 = tuple(
            int.from_bytes(ciphertext[idx:idx+self.nbyte], byteorder="big")
            for idx in range(0, len(ciphertext), self.nbyte)
        )
        m = pow(c1, -self.x, self.p) * c2 % self.p
        return long_to_bytes(m)


def read_server():
    with open("./server.py", "r", encoding="utf-8") as file:
        print(file.read())


def main():
    cipher = ElGamal()
    print(f"public_key: {cipher.public_key}")
    print(f"flag: {cipher.encrypt(FLAG.encode()).hex()}")
    for _ in range(cipher.nbyte):
        print("> decrypt")
        print("> server.py")
        print("> exit")
        cmd = input("> Command: ")
        if cmd == "exit":
            sys.exit()
        elif cmd == "decrypt":
            ciphertext = bytes.fromhex(input("> Enter ciphertext: "))
            print(f"plaintext last byte: {cipher.decrypt(ciphertext)[-1]}")
        elif cmd == "server.py":
            read_server()
        else:
            print("Bad hacker")


if __name__ == "__main__":
    try:
        main()
    except EOFError:
        sys.exit(1)
