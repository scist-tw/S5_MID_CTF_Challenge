## Crypto
### Elgamal oracle
這題實作了 Elgamal 的加解密，並會提供解密的最後一個位元組
#### `server.py`
* 正常的實作加解密流程，其中會將 `(c1, c2)` 包成 `bytes` 型態的 `ciphertext`
```python
class ElGamal:
    def __init__(self, nbit: int = 1024):
        self.nbyte = nbit // 8
        self.p = getPrime(nbit)
        self.g = self.gen_generator()
        self.x = randrange(2, self.p - 2)
        self.y = pow(self.g, self.x, self.p)

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
```
* `main` 裡提供對任意密文做解密的方式，但只會給出明文的最後一個 `byte`
    * 也就是說是 `r = 256` 的 `LSB oracle`
```python
ciphertext = bytes.fromhex(input("> Enter ciphertext: "))
print(f"plaintext last byte: {cipher.decrypt(ciphertext)[-1]}")
```
#### `script.py`
* 先依照題目包裝 `ciphertext` 的方式撰寫呼叫 `decrypt` 的副程式，並回傳最後一個 `byte` 的數字
```python
def decrypt(c1: int, c2: int) -> int:
    ciphertext = b"".join(c.to_bytes(128, byteorder="big") for c in (c1, c2))
    conn.sendlineafter(b": ", b"decrypt")
    conn.sendlineafter(b": ", ciphertext.hex().encode())
    conn.recvuntil(b": ")
    return int(conn.recvuntil(b"\n").decode())
```
* 課堂中，講解 `LSB oracle` 的最後碎碎念中有提到，當 `r > 2` 時的狀況不像 lab 題目那麼單純。
* 因為此題是 `r = 256` 且應用在 `Elgamal` 的情況，以第一次的 `oracle` 來說明，如果滿足 $k * \frac{p}{256} \le m \lt (k + 1)\frac{p}{256}$ 的話，則收到的值應為
    * $256 * m \mod{p} \mod{256}$
    * $\Rightarrow (256 * m - k * p) \mod{256}$
    * $\Rightarrow -k * p \mod{256}$
* 知道回傳值與 `m` 之間的關係，就可以開始進行 `oracle`
```python
# 接收 public_key，用 json 的格式去 parse，然後我們只需要 p
conn.recvuntil(b": ")
p = json.loads(conn.recvuntil(b"\n"))["p"]

# 生成回傳值與區間 k 的對應表
p_reverse_mapping = {-k * p % 256: k for k in range(256)}

# 接收 enc_flag，並依照題目敘述 parse 成 (c1, c2)
conn.recvuntil(b": ")
ciphertext = bytes.fromhex(conn.recvuntil(b"\n").decode())
c1, c2 = tuple(
    int.from_bytes(ciphertext[idx:idx+128], byteorder="big")
    for idx in range(0, len(ciphertext), 128)
)

# 準備開始 oracle
l, r = 0, p

# 通常我會確保 l 到 r 之間的間隔還足夠繼續 oracle 切分
while r - l > 255:
    # 對 c2 做同態加密
    c2 = 256 * c2 % p

    # 用對應表找回 m 所在的區間
    k = p_reverse_mapping[decrypt(c1, c2)]

    # 用 r - l 去切分 256 等分為一個區間
    # 用原始的 l 加上 k 和 k + 1 個區間去定義新的 l 和 r
    l, r = l + k * (r - l) // 256, l + (k + 1) * (r - l) // 256

    # 把目前的差距顯示出來當作進度條
    print(r - l)

# 結束後把 l 和 r 都轉成文字看看，一定會有誤差但能辨識得出來即可
print(long_to_bytes(l))
print(long_to_bytes(r))
```
夾擠出 flag: `SCIST{I said elgamal can perform homomorphic encryption in class. :)}`

### LCG cipher
這題是用 LCG 當作 Cipher 的 keystream 去實現加密
#### `server.py`
* 實作 `LCG` 並把每次的 `seed` 轉換成 `bytes` 傳出去 `generator`
```python
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
```
* `Cipher` 實作用 `PRNG` 做為 `keystream` 來加密，並在初始時複製 `PRNG` 物件以確保外部程式可以重複調用
```python
class Cipher:
    def __init__(self, rpng: PRNG):
        self.rpng = copy.copy(rpng)

    def encrypt(self, plaintext: bytes) -> bytes:
        return bytes(pt ^ key for pt, key in zip(plaintext, self.rpng.next()))
```
* `main` 裡面提供用相同 `PRNG` 去對任意明文加密的方法，這邊就能算回加密 `flag` 時所遍歷的 `keystream` 結果
```python
plaintext = input("> Enter plaintext: ")
print(f"enc: {Cipher(lcg).encrypt(plaintext.encode()).hex()}")
```
#### `script.py`
```python
# 接收加密後的 flag 並從 hex-string 轉成 bytes
conn.recvuntil(b": ")
flag = bytes.fromhex(conn.recvuntil(b"\n").decode())

# 生成與 flag 相同長度的 plaintext 送去加密並接收對應密文
plaintext = b"A" * len(flag)
conn.sendlineafter(b": ", b"encrypt")
conn.sendlineafter(b": ", plaintext)
conn.recvuntil(b": ")
enc = bytes.fromhex(conn.recvuntil(b"\n").decode())

# 已知明文與拿到密文，在 stream cipher 中算回對應的 keystream
keystream = xor(plaintext, enc)

# 拿到 keystream 對 flag 做解密
print(xor(flag, keystream).decode())
```
解出 flag: `SCIST{using linear congruential generator to implement a stream cipher}`

### RS256
題目實作了類似 [JWT](https://en.wikipedia.org/wiki/JSON_Web_Token) 中 RS256 的生成與驗證 token 的方法，但存在很多漏洞。
#### `server.py`
* `RsaKey` 中，模數由三個質數所組成，重點放在質數的生成方式，剩下都是正常組成公鑰和私鑰，正常的簽署和驗證流程
    * `get_forward_prime` 會生成一個 `p - 1` 平滑的質數
    * `get_backward_prime` 會生成一組 `twin prime`
```python
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
```
* `JWT256` 是個[抽象類別](https://docs.python.org/3/library/abc.html)，定義一些基本的呼叫方法
  * `base64encode` 和 `base64decode` 是 JWT 中 `base64` 編碼的變體，可以直接引用就好
  * `encode` 和 `decode` 會分別將生成或驗證好 `header`、`body` 和 `signature`，然後回傳 `token` 或 `body`
      * `header` 由 `alg` 和 `typ` 組成，`alg` 為類別的名字，`typ` 固定為抽象類別名稱 `JWT256`，驗證時會檢查該有的資料是否還在，基本上可以不用理會這邊
      * `body` 為傳進來編碼的 `payload` 和 `iat` 組成，驗證時會檢查 `iat` 的時間戳是否在 `exp` 的範圍內
      * `signature` 為 `header` 和 `body` 做 `urlencode` 後組起來的 `message`，再串上 `secret` 做 `sha256`，這邊可以實現 `LEA`
```python
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
```
* `RS256` 為實作 `JWT256` 的一種類別，主要是 `signature` 的部分會經過 `RsaKey` 的簽名與驗證
```python
def generate_signature(self, message: bytes) -> str:
    return self.key.sign(super().generate_signature(message))

def verify_signature(self, message: bytes, signature: bytes):
    if not self.key.verify(super().generate_signature(message), signature):
        raise ValueError("Verify signature failed.")
```
* `main` 這邊提供 `register` 和 `login` 的方法
    * `register` 會把輸入的 `username` 加進 `admin` 為 `N` 的 `payload` 裡 `encode` 成 `token` 輸出
    * `login` 會依照輸入的 `token` 去 `decode` 出使用者資料，如果 `Y` 在 `admin` 裡就會輸出 flag

#### `script.py`
看完原始碼之後，蠻明顯的是要分解 `RsaKey` 的模數去算出私鑰，然後利用 `LEA` 去竄改使用者資料的 `admin`，最後用私鑰去偽造簽章
* 先來分解 `RsaKey`
    * `p - 1` 平滑可以用 `pollard` 分解出來
    * `twin prime` 相乘可以用 `fermat` 或是線性方程分解
        * $x^2 + 2x - \frac{n}{p} = 0$
```python
import json

import gmpy2
from Crypto.Util.number import GCD, inverse


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


def main():
    conn.recvuntil(b": ")
    e, n = json.loads(conn.recvuntil(b"\n")).values()
    p = pollard(n)
    q1, q2 = fermat(n // p)
    assert p * q1 * q2 == n
    d = inverse(e, (p - 1) * (q1 - 1) * (q2 - 1))
```
* 準備來造 `LEA` 攻擊 function，先從 [source code](https://github.com/killua4564/SHA-family/blob/master/SHA2-256.py) 複製這些下來
```python
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
```
* 然後依照 `digest` 的打包方式做解壓後調用 `extend_signature` function
```python
def length_extension_attack(digest: bytes, append_message: bytes) -> bytes:
    # reverse the final digest value
    h0, h1, h2, h3, h4, h5, h6, h7 = [int.from_bytes(digest[i:i+4], byteorder="big") for i in range(0, len(digest), 4)]

    # append the message and calculate the digest of chunk data
    for i in range(0, len(append_message), 64):
        h0, h1, h2, h3, h4, h5, h6, h7 = extend_signature(append_message[i:i+64], h0, h1, h2, h3, h4, h5, h6, h7)

    # produce the final digest value
    return b"".join(map(lambda x: x.to_bytes(4, byteorder="big"), (h0, h1, h2, h3, h4, h5, h6, h7)))
```
* 接下來構想 `LEA` 的資料，這邊 `secret` 的長度為 `randrange(37, 43)` 是個困擾點，而且 `login` 中如果驗證失敗會直接跳到最外面的 `Login failed.`，也就是說每個連線只能嘗試偽造登入一次...，~~那就多嘗試幾次不就好了XDD~~
    * 假設 `secret` 長度為 `39`，然後 `username` 輸入 `AAA`
    * 所以原本拿到的 `signature` 是由這些資料算出來的
    ```python
    secret + "alg=RS256&typ=JWT256" + "." + "username=AAA&admin=N&iat=1733755623" + "\x80" + "\x00" * 24 + L(95)
    ```
    * 加上要擴充的資料後，新的 `signature` 應該要由這些資料算出來
        * 這邊要注意的是，需要把 `iat` 的數值複製一份到擴充資料裡，不然原本的解析出來後會解析失敗
    ```python
    secret + "alg=RS256&typ=JWT256" + "." + "username=AAA&admin=N&iat=1733755623" + "\x80" + "\x00" * 24 + L(95) + "&admin=Y&iat=1733755623" + "\x80" + "\x00" * 32 + L(151)
    ```
    * 需要放入 `body` 的擴充資料為
    ```python
    "\x80" + "\x00" * 24 + L(95) + "&admin=Y&iat=1733755623"
    ```
    * 需要放入 `LEA` 的擴充資料為
    ```python
    "&admin=Y&iat=1733755623" + "\x80" + "\x00" * 32 + L(151)
    ```
```python
# 在同目錄下存成 server.py 即可調用
from Crypto.Util.number import bytes_to_long, long_to_bytes

from server import JWT256

# L function of the demo in class
def length(n: int) -> bytes:
    return (8 * n).to_bytes(8, byteorder="big")

def main():
    # 上面分解 RsaKey 的腳本放這邊

    # 呼叫 register 拿到 token
    conn.sendlineafter(b": ", b"register")
    conn.sendlineafter(b": ", b"AAA")
    conn.recvuntil(b": ")
    token = conn.recvuntil(b"\n").strip(b"\n").decode()

    # 拆成 urlencoded 的資料，並把 signature 算回 sha256 的 digest
    header, body, signature = tuple(JWT256.base64decode(payload) for payload in token.split("."))
    signature = long_to_bytes(pow(bytes_to_long(signature), e, n))

    # 依照上面的擴充資料生成新的 body 和 signature，body[-10:] 為 iat
    new_body = body + b"\x80" + b"\x00" * 24 + length(95) + b"&admin=Y&iat=" + body[-10:]
    new_signature = length_extension_attack(signature, b"&admin=Y&iat=" + body[-10:] + b"\x80" + b"\x00" * 32 + length(151))

    # 用算出來的私鑰做成 RSA 的簽章後包裝成新的 token
    new_signature = long_to_bytes(pow(bytes_to_long(new_signature), d, n))
    new_token = ".".join(JWT256.base64encode(payload) for payload in (header, new_body, new_signature))

    # 嘗試使用偽造的 token 登入，如果出現 Hi AAA 表示偽造成功，則輸出 flag
    conn.sendlineafter(b": ", b"login")
    conn.sendlineafter(b": ", new_token.encode())
    if conn.recvuntil(b"\n").startswith(b"Hi"):
        conn.recvuntil(b": ")
        print(conn.recvuntil(b"\n").decode())
```
* 執行腳本每次有 $\frac{1}{5}$ 的機率拿到 flag: `SCIST{It's a bad practice to implement RS256 of JWT.}`
