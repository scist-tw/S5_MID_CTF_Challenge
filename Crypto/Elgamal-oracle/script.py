import json

from Crypto.Util.number import long_to_bytes
from pwn import remote

conn = remote("0.0.0.0", "10315")

def decrypt(c1: int, c2: int) -> int:
    ciphertext = b"".join(c.to_bytes(128, byteorder="big") for c in (c1, c2))
    conn.sendlineafter(b": ", b"decrypt")
    conn.sendlineafter(b": ", ciphertext.hex().encode())
    conn.recvuntil(b": ")
    return int(conn.recvuntil(b"\n").decode())


def main():
    conn.recvuntil(b": ")
    p = json.loads(conn.recvuntil(b"\n"))["p"]
    p_reverse_mapping = {-k * p % 256: k for k in range(256)}

    conn.recvuntil(b": ")
    ciphertext = bytes.fromhex(conn.recvuntil(b"\n").decode())
    c1, c2 = tuple(
        int.from_bytes(ciphertext[idx:idx+128], byteorder="big")
        for idx in range(0, len(ciphertext), 128)
    )

    l, r = 0, p
    while r - l > 255:
        c2 = 256 * c2 % p
        k = p_reverse_mapping[decrypt(c1, c2)]
        l, r = l + k * (r - l) // 256, l + (k + 1) * (r - l) // 256
        print(r - l)

    print(long_to_bytes(l))
    print(long_to_bytes(r))


if __name__ == "__main__":
    main()
