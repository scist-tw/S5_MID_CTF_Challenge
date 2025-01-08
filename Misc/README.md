## Misc
### Trick or Treat
遊戲規則是要從眾多箱子裡拿到所有的最後一顆糖果，兩個人輪流，一次只能從其中一個箱子裡拿一顆或數顆糖果。此為[尼姆遊戲](https://en.wikipedia.org/wiki/Nim)，策略是要計算用每個箱子的糖果數量計算尼姆數，也就是 `xor` 運算（萬聖節為上課在講 `xor` 時有出現南瓜圖片的提示），讓自己拿完糖果後的尼姆數為 `0` 可以保持優勢，故制定策略如下。
```python
def strategy(candies: list[int]) -> tuple[int, int]:
    # 計算目前狀態的尼姆數
    target = functools.reduce(lambda x, y: x ^ y, candies)
    if target == 0:
        raise ValueError("No solution.")

    # 嘗試哪一個箱子可以透過拿取糖果讓尼姆數為 0
    for idx, candy in enumerate(candies, 1):
        result = candy - (candy ^ target)
        if result > 0:
            return idx, result

    raise ValueError("Strategy implements wrong.")
```
最後依照題目樣子撰寫對應的腳本即有機會通關，因為有可能題目初始尼姆數即為 `0`。
```python
for _ in range(100):
    # 獲取題目初始訊息
    conn.recvuntil(b"contains")
    candies = list(map(int, conn.recvuntil(b"candy.").strip(b"candy.").strip().split(b", ")))

    # 持續遊玩直到全部糖果為 0
    while sum(candies) > 0:
        # 用制定好的策略去進行我的回合
        n, k = strategy(candies)
        conn.sendlineafter(b": ", f"({n}, {k})".encode())
        conn.recvuntil(b"\n")
        candies[n - 1] -= k

        # 接收對方回合的訊息，有可能為任務成功
        data = conn.recvuntil(b"\n").strip(b".\n")
        if data != b"Mission succeeded":
            data = data.split(b" ")
            candies[int(data[-1]) - 1] -= int(data[3])

# 拿到通關的 flag
print(conn.recvuntil(b"\n").decode())
```
成功拿到 flag: `SCIST{trick-or-treat? trick-xor-treat!}`
