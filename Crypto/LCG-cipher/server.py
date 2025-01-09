import abc
import copy
import sys
import typing

from Crypto.Util.number import getPrime

from secret import FLAG


class PRNG(abc.ABC):
    pass


class LCG(PRNG):
    def __init__(self, nbit: int = 128):
        self.nbyte = nbit // 8

        self.a = getPrime(nbit // 2)
        self.c = getPrime(nbit // 2)
        self.m = getPrime(nbit)
        self.seed = getPrime(nbit // 2)

    def next(self) -> typing.Generator[int, None, None]:
        while True:
            self.seed = (self.a * self.seed + self.c) % self.m
            yield from self.seed.to_bytes(self.nbyte, byteorder="big")


class Cipher:
    def __init__(self, rpng: PRNG):
        self.rpng = copy.copy(rpng)

    def encrypt(self, plaintext: bytes) -> bytes:
        return bytes(pt ^ key for pt, key in zip(plaintext, self.rpng.next()))


def read_server():
    with open("./server.py", "r", encoding="utf-8") as file:
        print(file.read())


def main():
    lcg = LCG()
    print(f"flag: {Cipher(lcg).encrypt(FLAG.encode()).hex()}")
    while True:
        print("> encrypt")
        print("> server.py")
        print("> exit")
        cmd = input("> Command: ")
        if cmd == "exit":
            sys.exit()
        elif cmd == "encrypt":
            plaintext = input("> Enter plaintext: ")
            print(f"enc: {Cipher(lcg).encrypt(plaintext.encode()).hex()}")
        elif cmd == "server.py":
            read_server()
        else:
            print("Bad hacker")


if __name__ == "__main__":
    try:
        main()
    except EOFError:
        sys.exit(1)
