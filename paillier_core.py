import random
import math
from functools import reduce


# 辅助函数：大素数生成（为了演示速度，这里用较小的位数，实际应用需 1024 bit+）
# 如果不想手写素数生成，也可以用 Crypto.Util.number.getPrime
def is_prime(n, k=5):
    if n <= 1: return False
    if n <= 3: return True
    if n % 2 == 0: return False
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits=16):
    while True:
        num = random.getrandbits(bits)
        # 保证是奇数且通过素性测试
        if num % 2 != 0 and is_prime(num):
            return num


class PaillierCipher:
    def __init__(self, key_size=128, generate_keys=True):
        """
        初始化。
        如果 generate_keys=True，则生成新密钥（用于权威机构）。
        如果 generate_keys=False，则跳过生成（用于选民和云端，等待后续手动赋值）。
        """
        self.n = None
        self.n_sq = None
        self.g = None
        self.lam = None
        self.mu = None

        if not generate_keys:
            return  # 直接结束，不进行耗时的素数生成

        # --- Key Generation (KeyGen) ---
        # 下面是原本的生成逻辑 ...
        p = generate_prime(key_size)
        q = generate_prime(key_size)
        while p == q:
            q = generate_prime(key_size)

        self.n = p * q
        self.n_sq = self.n * self.n
        self.g = self.n + 1

        self.lam = (p - 1) * (q - 1) // math.gcd(p - 1, q - 1)
        u = pow(self.g, self.lam, self.n_sq)
        l_u = (u - 1) // self.n
        self.mu = pow(l_u, -1, self.n)

        print(f"[系统初始化] 密钥生成完毕。\n  -> n (模数): {self.n}\n  -> lambda: {self.lam}")

    def encrypt(self, m):
        """
        加密函数 E(m)
        公式: c = g^m * r^n mod n^2
        """
        # 生成随机数 r，要求 0 < r < n 且 gcd(r, n) = 1
        while True:
            r = random.randint(1, self.n - 1)
            if math.gcd(r, self.n) == 1:
                break

        # c = (g^m mod n^2) * (r^n mod n^2) mod n^2
        gm = pow(self.g, m, self.n_sq)
        rn = pow(r, self.n, self.n_sq)
        c = (gm * rn) % self.n_sq
        return c

    def decrypt(self, c):
        """
        解密函数 D(c)
        公式: m = L(c^lambda mod n^2) * mu mod n
        """
        # 1. u = c^lambda mod n^2
        u = pow(c, self.lam, self.n_sq)

        # 2. L(u) = (u - 1) / n
        l_u = (u - 1) // self.n

        # 3. m = L(u) * mu mod n
        m = (l_u * self.mu) % self.n
        return m

    def homomorphic_add(self, c1, c2):
        """
        同态加法
        原理: D(c1 * c2) = m1 + m2
        这里我们只需要对密文进行模乘
        """
        return (c1 * c2) % self.n_sq