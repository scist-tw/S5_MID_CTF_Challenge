from pwn import remote

from server import strategy

conn = remote("0.0.0.0", "10318")

for _ in range(100):
    conn.recvuntil(b"contains")
    candies = list(map(int, conn.recvuntil(b"candy.").strip(b"candy.").strip().split(b", ")))
    while sum(candies) > 0:
        n, k = strategy(candies)
        conn.sendlineafter(b": ", f"({n}, {k})".encode())
        conn.recvuntil(b"\n")
        candies[n - 1] -= k

        data = conn.recvuntil(b"\n").strip(b".\n")
        if data != b"Mission succeeded":
            data = data.split(b" ")
            candies[int(data[-1]) - 1] -= int(data[3])

print(conn.recvuntil(b"\n").decode())
