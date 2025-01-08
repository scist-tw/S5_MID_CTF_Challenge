import json

import gmpy2
from Crypto.Util.number import GCD, bytes_to_long, inverse, long_to_bytes
from pwn import remote

from server import JWT256

conn = remote("0.0.0.0", "10317")


def pollard(n: int) -> int:
    a, b = 2, 2
    while True:
        a = pow(a, b, n)
        p = GCD(a - 1, n)
        if 1 < p < n:
            return p
        b += 1


def fermat(n: int) -> tuple[int, int]:
    a = gmpy2.isqrt(n) + 1
    b = a ** 2 - n
    while not gmpy2.iroot(b, 2)[1]:
        a += 1
        b = a ** 2 - n
    b = gmpy2.iroot(b, 2)[0]
    return int(a + b), int(a - b)


# initialize table of round constants
k = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]


# copy from lambda function of source code
def right_rotate(n: int, b: int) -> int:
    return ((n >> b) | (n << (32 - b))) & 0xffffffff


# copy from source code, the part of calculate the chunk data in the for-loop
def extend_signature(chunk: bytes, h0: int, h1: int, h2: int, h3: int, h4: int, h5: int, h6: int, h7: int) -> tuple[int, int, int, int, int, int, int, int]:
    # break chuck into sixteen 32bits big-endian words
    w = [int.from_bytes(chunk[i:i+4], byteorder="big") for i in range(0, len(chunk), 4)]
    # extend 16 words to 64 words
    for i in range(16, 64):
        s0 = right_rotate(w[i-15], 7) ^ right_rotate(w[i-15], 18) ^ (w[i-15] >> 3)  # right_rotate(w[i-15], 3)
        s1 = right_rotate(w[i-2], 17) ^ right_rotate(w[i-2], 19) ^ (w[i-2] >> 10)   # right_rotate(w[i-2], 10)
        w.append((w[i-16] + s0 + w[i-7] + s1) & 0xffffffff)

    # initialize hash value for this chunk
    a = h0
    b = h1
    c = h2
    d = h3
    e = h4
    f = h5
    g = h6
    h = h7

    # main loop
    for i in range(64):
        s0 = right_rotate(a, 2) ^ right_rotate(a, 13) ^ right_rotate(a, 22)
        s1 = right_rotate(e, 6) ^ right_rotate(e, 11) ^ right_rotate(e, 25)
        choice = (e & f) ^ (~e & g)
        majority = (a & b) ^ (a & c) ^ (b & c)
        temp1 = (h + s1 + choice + k[i] + w[i]) & 0xffffffff
        temp2 = (s0 + majority) & 0xffffffff

        a, b, c, d, e, f, g, h = (temp1 + temp2) & 0xffffffff, a, b, c, (d + temp1) & 0xffffffff, e, f, g

    # add this chunk's hash to result so far
    h0 = (h0 + a) & 0xffffffff
    h1 = (h1 + b) & 0xffffffff
    h2 = (h2 + c) & 0xffffffff
    h3 = (h3 + d) & 0xffffffff
    h4 = (h4 + e) & 0xffffffff
    h5 = (h5 + f) & 0xffffffff
    h6 = (h6 + g) & 0xffffffff
    h7 = (h7 + h) & 0xffffffff

    return (h0, h1, h2, h3, h4, h5, h6, h7)


# L function of the demo in class
def length(n: int) -> bytes:
    return (8 * n).to_bytes(8, byteorder="big")


def length_extension_attack(digest: bytes, append_message: bytes) -> bytes:
    # reverse the final digest value
    h0, h1, h2, h3, h4, h5, h6, h7 = [int.from_bytes(digest[i:i+4], byteorder="big") for i in range(0, len(digest), 4)]

    # append the message and calculate the digest of chunk data
    for i in range(0, len(append_message), 64):
        h0, h1, h2, h3, h4, h5, h6, h7 = extend_signature(append_message[i:i+64], h0, h1, h2, h3, h4, h5, h6, h7)

    # produce the final digest value
    return b"".join(map(lambda x: x.to_bytes(4, byteorder="big"), (h0, h1, h2, h3, h4, h5, h6, h7)))


def main():
    conn.recvuntil(b": ")
    e, n = json.loads(conn.recvuntil(b"\n")).values()
    p = pollard(n)
    q1, q2 = fermat(n // p)
    assert p * q1 * q2 == n
    d = inverse(e, (p - 1) * (q1 - 1) * (q2 - 1))

    ### assume len(secret) = 39

    # the old signature is calculated by:
    # => secret + alg=RS256&typ=JWT256 + . + username=AAA&admin=N&iat=1733755623 + "\x80" + "\x00" * 24 + L(95)

    # the new signature will be calculated by:
    # => secret + alg=RS256&typ=JWT256 + . + username=AAA&admin=N&iat=1733755623 + "\x80" + "\x00" * 24 + L(95) + &admin=Y&iat=1733755623 + "\x80" + "\x00" * 32 + L(151)

    # the new chunk data is:
    # => &admin=Y&iat=1733755623 + "\x80" + "\x00" * 32 + L(151)

    # the message that should be appended is:
    # => "\x80" + "\x00" * 24 + L(95) + &admin=Y&iat=1733755623

    conn.sendlineafter(b": ", b"register")
    conn.sendlineafter(b": ", b"AAA")
    conn.recvuntil(b": ")
    token = conn.recvuntil(b"\n").strip(b"\n").decode()
    header, body, signature = tuple(JWT256.base64decode(payload) for payload in token.split("."))
    signature = long_to_bytes(pow(bytes_to_long(signature), e, n))
    new_body = body + b"\x80" + b"\x00" * 24 + length(95) + b"&admin=Y&iat=" + body[-10:]
    new_signature = length_extension_attack(signature, b"&admin=Y&iat=" + body[-10:] + b"\x80" + b"\x00" * 32 + length(151))
    new_signature = long_to_bytes(pow(bytes_to_long(new_signature), d, n))
    new_token = ".".join(JWT256.base64encode(payload) for payload in (header, new_body, new_signature))

    conn.sendlineafter(b": ", b"login")
    conn.sendlineafter(b": ", new_token.encode())
    if conn.recvuntil(b"\n").startswith(b"Hi"):
        conn.recvuntil(b": ")
        print(conn.recvuntil(b"\n").decode())


if __name__ == "__main__":
    main()
