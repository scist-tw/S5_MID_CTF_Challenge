from pwn import remote

def xor(x: bytes, y: bytes) -> bytes:
    return bytes(i ^ j for i, j in zip(x, y))

conn = remote("0.0.0.0", "10316")

conn.recvuntil(b": ")
flag = bytes.fromhex(conn.recvuntil(b"\n").decode())
plaintext = b"A" * len(flag)

conn.sendlineafter(b": ", b"encrypt")
conn.sendlineafter(b": ", plaintext)

conn.recvuntil(b": ")
enc = bytes.fromhex(conn.recvuntil(b"\n").decode())

keystream = xor(plaintext, enc)

print(xor(flag, keystream).decode())
