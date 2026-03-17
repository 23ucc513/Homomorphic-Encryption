# Homomorphic Encryption — RSA & Paillier

A deep-dive implementation of two foundational **public-key cryptosystems** with homomorphic properties, built as part of a B.Tech Project (BTP) in cryptography.

| Scheme | Year | Homomorphism | Deterministic? |
|---|---|---|---|
| **RSA** | 1977 | Multiplicative | ✅ Yes |
| **Paillier** | 1999 | Additive | ❌ No (probabilistic) |

> **References:**  
> Rivest, Shamir & Adleman, *"A Method for Obtaining Digital Signatures and Public-Key Cryptosystems"*, CACM 1978.  
> Pascal Paillier, *"Public-Key Cryptosystems Based on Composite Degree Residuosity Classes"*, EUROCRYPT 1999.

---

## Table of Contents

1. [What is Homomorphic Encryption?](#what-is-homomorphic-encryption)
2. [RSA Cryptosystem](#rsa-cryptosystem)
   - [Mathematical Background](#rsa-mathematical-background)
   - [Key Generation](#rsa-key-generation)
   - [Encryption](#rsa-encryption)
   - [Decryption](#rsa-decryption)
   - [Homomorphic Properties](#rsa-homomorphic-properties)
   - [Security](#rsa-security)
3. [Paillier Cryptosystem](#paillier-cryptosystem)
   - [Mathematical Background](#paillier-mathematical-background)
   - [Key Generation](#paillier-key-generation)
   - [Encryption](#paillier-encryption)
   - [Decryption](#paillier-decryption)
   - [Homomorphic Properties](#paillier-homomorphic-properties)
   - [Security](#paillier-security)
4. [RSA vs Paillier — Side-by-Side](#rsa-vs-paillier--side-by-side)
5. [Usage](#usage)
6. [File Structure](#file-structure)

---

## What is Homomorphic Encryption?

**Homomorphic encryption** lets you perform computations *on ciphertexts* such that when you decrypt the result, it matches the same computation performed on the original plaintexts — without ever exposing the raw data.

$$
\text{Dec}\!\left(\, f\!\left(\text{Enc}(m_1),\, \text{Enc}(m_2)\right)\right) = f(m_1, m_2)
$$

This enables powerful privacy-preserving applications:
- A cloud server summing encrypted salaries without seeing individual values
- Secure voting where ballots remain encrypted throughout tallying
- Private machine learning inference on encrypted inputs

Different schemes support different operations:

| Scheme | Supported operation | Example |
|---|---|---|
| RSA | Multiplication | $\text{Enc}(6) \times \text{Enc}(7) = \text{Enc}(42)$ |
| Paillier | Addition | $\text{Enc}(6) \times \text{Enc}(7) = \text{Enc}(13)$ |
| FHE (Gentry) | Both (unlimited) | Any circuit |

---

## RSA Cryptosystem

RSA (Rivest–Shamir–Adleman, 1977) is the world's most widely deployed public-key cryptosystem. Its security relies on the **integer factorisation problem**: given $n = p \cdot q$, it is computationally infeasible to recover $p$ and $q$ when they are large primes.

A natural algebraic consequence is that RSA is **multiplicatively homomorphic**:

$$
\text{Enc}(m_1) \times \text{Enc}(m_2) \bmod n = \text{Enc}(m_1 \times m_2 \bmod n)
$$

### RSA Mathematical Background

#### Notation

| Symbol | Meaning |
|---|---|
| $p, q$ | Two large secret primes |
| $n$ | Public modulus $= p \cdot q$ |
| $\phi(n)$ | Euler's totient $= (p-1)(q-1)$ |
| $e$ | Public exponent — part of the public key |
| $d$ | Private exponent — part of the private key |
| $m$ | Plaintext integer, $0 \le m < n$ |
| $c$ | Ciphertext integer, $0 \le c < n$ |

#### Euler's Theorem (the heart of RSA)

For any integer $m$ with $\gcd(m, n) = 1$:

$$
m^{\phi(n)} \equiv 1 \pmod{n}
$$

This means if $e \cdot d \equiv 1 \pmod{\phi(n)}$, then:

$$
(m^e)^d = m^{ed} = m^{1 + k\phi(n)} = m \cdot (m^{\phi(n)})^k \equiv m \cdot 1^k = m \pmod{n}
$$

Encryption and decryption are perfect inverses of each other.

---

### RSA Key Generation

**Step 1 — Generate two large random primes $p$ and $q$:**

Each prime is chosen independently with roughly equal bit-length. The security of RSA depends on the difficulty of factoring $n = p \cdot q$.

**Step 2 — Compute the public modulus:**

$$
n = p \cdot q
$$

$n$ is public. Its bit-length (e.g. 2048 bits) determines the security level.

**Step 3 — Compute Euler's totient:**

$$
\phi(n) = (p - 1)(q - 1)
$$

$\phi(n)$ counts integers in $[1, n)$ that are coprime to $n$. This **must remain secret** — anyone who knows $\phi(n)$ can compute $d$ and decrypt all messages.

**Step 4 — Choose the public exponent $e$:**

$$
1 < e < \phi(n), \quad \gcd(e,\, \phi(n)) = 1
$$

The standard choice is $e = 65537 = 2^{16} + 1$. It is prime, has only two set bits (making modular exponentiation fast), and avoids small-exponent attacks.

**Step 5 — Compute the private exponent $d$:**

$$
d = e^{-1} \bmod \phi(n), \quad \text{i.e.,}\quad e \cdot d \equiv 1 \pmod{\phi(n)}
$$

$d$ is found via the Extended Euclidean Algorithm.

$$
\boxed{
\begin{aligned}
\textbf{Public Key}  &: \quad (n,\; e) \\
\textbf{Private Key} &: \quad (n,\; d)
\end{aligned}
}
$$

---

### RSA Encryption

Given public key $(n, e)$ and plaintext $m$ with $0 \le m < n$:

$$
\boxed{c = m^e \bmod n}
$$

- Modular exponentiation is a **one-way function**: easy to compute $c$ from $m$, but infeasible to reverse without knowing $d$.
- RSA is **deterministic**: the same $m$ always produces the same $c$ (unlike Paillier).

---

### RSA Decryption

Given private key $(n, d)$ and ciphertext $c$:

$$
\boxed{m = c^d \bmod n}
$$

**Correctness:**

$$
c^d = (m^e)^d = m^{ed} \equiv m^{1 + k\phi(n)} = m \cdot (m^{\phi(n)})^k \equiv m \pmod{n}
$$

by Euler's theorem.

---

### RSA Homomorphic Properties

#### 1. Multiplication of Two Ciphertexts

$$
\boxed{\text{Enc}(m_1) \cdot \text{Enc}(m_2) \bmod n = \text{Enc}(m_1 \cdot m_2 \bmod n)}
$$

**Proof:**

$$
c_1 \cdot c_2 = m_1^e \cdot m_2^e = (m_1 \cdot m_2)^e \pmod{n}
$$

This is exactly $\text{Enc}(m_1 \cdot m_2)$.

---

#### 2. Ciphertext Exponentiation (scalar power)

$$
\boxed{\text{Enc}(m)^k \bmod n = \text{Enc}(m^k \bmod n)}
$$

**Proof:**

$$
c^k = (m^e)^k = m^{ek} = (m^k)^e \pmod{n}
$$

---

#### RSA Homomorphic Summary

| Operation | Formula | Decrypts to |
|---|---|---|
| Multiply two ciphertexts | $c_1 \cdot c_2 \bmod n$ | $m_1 \cdot m_2 \bmod n$ |
| Raise ciphertext to power $k$ | $c^k \bmod n$ | $m^k \bmod n$ |
| Multiply by plaintext scalar | $c \cdot \text{Enc}(k) \bmod n$ | $m \cdot k \bmod n$ |

> **RSA is deterministic**: since there is no randomness in encryption, Path A (operate → encrypt) and Path B (encrypt → operate) produce **identical ciphertexts**, not just identical decryptions.

> **RSA does NOT support additive homomorphism.** $\text{Enc}(m_1) + \text{Enc}(m_2) \ne \text{Enc}(m_1 + m_2)$. For addition, use Paillier.

---

### RSA Security

#### Hard Problem

RSA's security rests on the **RSA problem**: given $(n, e, c)$, compute $m$ such that $m^e \equiv c \pmod{n}$.

The best known approach is to factor $n$ into $p$ and $q$, then compute $\phi(n)$ and $d$. Factoring a 2048-bit number with the best known algorithms (GNFS) is computationally infeasible.

#### Key Size Recommendations

| Key size (bits of $n$) | Security level | Status |
|---|---|---|
| 512  | ~56-bit  | **Broken** |
| 1024 | ~80-bit  | **Legacy / not recommended** |
| 2048 | ~112-bit | **Minimum recommended** |
| 3072 | ~128-bit | Recommended |
| 4096 | ~152-bit | High security |

#### Important Notes

- **Deterministic** → RSA is **not IND-CPA secure** in textbook form. In practice, randomised padding (OAEP) is used.
- **Small plaintext vulnerability**: encrypting small messages without padding leaks information.
- **Multiplicative homomorphism is a double-edged sword**: it enables the privacy-preserving operations shown here, but also means an attacker can *manipulate* ciphertexts in a controlled way (malleability).

---

## Paillier Cryptosystem

The Paillier cryptosystem (Pascal Paillier, 1999) is a **probabilistic** public-key scheme that is **additively homomorphic**:

$$
\text{Enc}(m_1) \cdot \text{Enc}(m_2) \bmod n^2 = \text{Enc}(m_1 + m_2 \bmod n)
$$

Multiplying ciphertexts in the encrypted domain corresponds to *adding* the underlying plaintexts.

### Paillier Mathematical Background

#### Notation

| Symbol | Meaning |
|---|---|
| $p, q$ | Two large secret primes |
| $n$ | Public modulus $= p \cdot q$ |
| $n^2$ | Ciphertext space modulus |
| $\lambda$ | Carmichael's function $= \text{lcm}(p-1,\, q-1)$ |
| $g$ | Generator in $\mathbb{Z}_{n^2}^*$ (we use $g = n+1$) |
| $\mu$ | Precomputed decryption helper $= \left(L(g^\lambda \bmod n^2)\right)^{-1} \bmod n$ |
| $L(u)$ | $L(u) = \dfrac{u-1}{n}$ (always exact integer division) |
| $r$ | Random blinding factor, $1 \le r < n$, $\gcd(r,n)=1$ |

#### Key Identity (the binomial trick)

With $g = n + 1$, the binomial theorem gives:

$$
(n+1)^m = \sum_{k=0}^{m} \binom{m}{k} n^k \equiv 1 + m \cdot n \pmod{n^2}
$$

All terms with $k \ge 2$ vanish modulo $n^2$ since $n^k \equiv 0 \pmod{n^2}$ for $k \ge 2$. This linear relationship is what enables additive homomorphism.

#### Composite Residuosity Assumption (DCRA)

Given $n$ and $z \in \mathbb{Z}_{n^2}^*$, it is computationally hard to decide whether $z$ is an $n$-th residue modulo $n^2$ — i.e., whether there exists $y$ such that $z \equiv y^n \pmod{n^2}$.

---

### Paillier Key Generation

**Step 1 — Generate two large random primes $p$ and $q$.**

**Step 2 — Compute the modulus and ciphertext space:**

$$
n = p \cdot q, \qquad n^2 = n \times n
$$

Plaintexts live in $\mathbb{Z}_n$; ciphertexts live in $\mathbb{Z}_{n^2}^*$.

**Step 3 — Compute Carmichael's lambda:**

$$
\lambda = \text{lcm}(p - 1,\; q - 1)
$$

$\lambda$ is the smallest positive integer with $a^\lambda \equiv 1 \pmod{n}$ for all $a \in \mathbb{Z}_n^*$. It must remain secret.

**Step 4 — Choose the generator $g = n + 1$:**

This is the standard simplification. By the binomial trick: $(n+1)^m \equiv 1 + m \cdot n \pmod{n^2}$.

**Step 5 — Compute $\mu$:**

$$
\mu = \left(L\!\left(g^{\lambda} \bmod n^2\right)\right)^{-1} \bmod n
$$

With $g = n+1$: $g^\lambda \equiv 1 + \lambda n \pmod{n^2}$, so $L(g^\lambda) = \lambda$, and thus $\mu = \lambda^{-1} \bmod n$.

$$
\boxed{
\begin{aligned}
\textbf{Public Key}  &: \quad (n,\; g) \\
\textbf{Private Key} &: \quad (\lambda,\; \mu)
\end{aligned}
}
$$

---

### Paillier Encryption

Given public key $(n, g)$ and plaintext $m$ with $0 \le m < n$:

1. Choose random $r \in \mathbb{Z}_n^*$ with $\gcd(r, n) = 1$.

$$
\boxed{c = g^m \cdot r^n \bmod n^2}
$$

**Expanded** (with $g = n+1$):

$$
c = (1 + m \cdot n) \cdot r^n \bmod n^2
$$

- $g^m$ **carries the message** $m$ (embedded linearly via the binomial trick).
- $r^n$ is the **random blinding factor** that hides $m$ from any observer.
- The same $m$ encrypted twice gives **different ciphertexts** → semantic security (IND-CPA).

---

### Paillier Decryption

Given private key $(\lambda, \mu)$ and ciphertext $c$:

$$
\boxed{m = L\!\left(c^{\lambda} \bmod n^2\right) \cdot \mu \bmod n}
$$

**Step-by-step proof of correctness:**

$$
c^\lambda = \left(g^m \cdot r^n\right)^\lambda = g^{m\lambda} \cdot r^{n\lambda} \pmod{n^2}
$$

By Carmichael's theorem, $r^{n\lambda} \equiv 1 \pmod{n^2}$, so:

$$
c^\lambda \equiv g^{m\lambda} \equiv (n+1)^{m\lambda} \equiv 1 + m\lambda \cdot n \pmod{n^2}
$$

Applying $L$:

$$
L(c^\lambda \bmod n^2) = m\lambda
$$

Finally, multiplying by $\mu = \lambda^{-1} \bmod n$:

$$
m\lambda \cdot \lambda^{-1} = m \pmod{n}
$$

The random factor $r$ has been completely eliminated.

---

### Paillier Homomorphic Properties

#### 1. Addition of Two Ciphertexts

$$
\boxed{\text{Enc}(m_1) \cdot \text{Enc}(m_2) \bmod n^2 = \text{Enc}(m_1 + m_2 \bmod n)}
$$

**Proof:**

$$
c_1 \cdot c_2 = g^{m_1} r_1^n \cdot g^{m_2} r_2^n = g^{m_1+m_2} (r_1 r_2)^n \pmod{n^2}
$$

This is a valid encryption of $(m_1 + m_2) \bmod n$ with combined randomness $r_1 r_2$.

---

#### 2. Add a Plaintext Constant

$$
\boxed{\text{Enc}(m) \cdot g^k \bmod n^2 = \text{Enc}(m + k \bmod n)}
$$

---

#### 3. Scalar Multiplication

$$
\boxed{\text{Enc}(m)^k \bmod n^2 = \text{Enc}(k \cdot m \bmod n)}
$$

**Proof:**

$$
c^k = (g^m r^n)^k = g^{km} (r^k)^n \pmod{n^2}
$$

---

#### Paillier Homomorphic Summary

| Operation | Formula | Decrypts to |
|---|---|---|
| Add two encrypted values | $c_1 \cdot c_2 \bmod n^2$ | $m_1 + m_2 \bmod n$ |
| Add plaintext constant $k$ | $c \cdot g^k \bmod n^2$ | $m + k \bmod n$ |
| Multiply by scalar $k$ | $c^k \bmod n^2$ | $k \cdot m \bmod n$ |

> **Paillier does NOT support multiplication of two encrypted values.** For $\text{Enc}(m_1 \cdot m_2)$ from two ciphertexts, a fully homomorphic scheme is needed.

---

### Paillier Security

#### Hard Problem

Security rests on the **Decisional Composite Residuosity Assumption (DCRA)**:

> It is computationally infeasible to distinguish $n$-th residues from non-residues modulo $n^2$.

#### Key Size Recommendations

| Key size (bits of $n$) | Security level | Status |
|---|---|---|
| 1024 | ~80-bit | **Legacy / not recommended** |
| 2048 | ~112-bit | **Minimum recommended** |
| 3072 | ~128-bit | Recommended |
| 4096 | ~152-bit | High security |

#### Security Properties

- **IND-CPA secure**: the random $r$ ensures the same plaintext maps to different ciphertexts every time.
- **Self-blinding**: any ciphertext can be re-randomised by multiplying by $r'^n \bmod n^2$ without changing the plaintext — useful for anonymisation.
- **One-wayness**: recovering $m$ from $c$ is at least as hard as factoring $n$.

---

## RSA vs Paillier — Side-by-Side

| Property | RSA | Paillier |
|---|---|---|
| Year | 1977 | 1999 |
| Hard problem | Integer factorisation | DCRA (composite residuosity) |
| Public key | $(n, e)$ | $(n, g)$ |
| Private key | $(n, d)$ | $(\lambda, \mu)$ |
| Encryption formula | $c = m^e \bmod n$ | $c = g^m \cdot r^n \bmod n^2$ |
| Decryption formula | $m = c^d \bmod n$ | $m = L(c^\lambda \bmod n^2) \cdot \mu \bmod n$ |
| Ciphertext space | $\mathbb{Z}_n$ | $\mathbb{Z}_{n^2}^*$ |
| Homomorphism type | **Multiplicative** | **Additive** |
| Deterministic? | ✅ Yes | ❌ No (probabilistic) |
| Semantic security | ❌ Not in textbook form | ✅ IND-CPA secure |
| Supported on ciphertexts | $\text{Enc}(m_1) \times \text{Enc}(m_2) = \text{Enc}(m_1 \cdot m_2)$ | $\text{Enc}(m_1) \times \text{Enc}(m_2) = \text{Enc}(m_1 + m_2)$ |
| Not supported | Addition of encrypted values | Multiplication of encrypted values |

---

## Usage

### Running the Demos

```bash
# RSA — multiplicative homomorphism
python3 rsa.py

# Paillier — additive homomorphism
python3 paillier_cryptosystem.py
```

### RSA Sample Output

```
========================================================================
   RSA Cryptosystem — Homomorphic Encryption Verification
========================================================================

[*] Generating 1024-bit RSA key-pair …

BASIC TEST : Encrypt → Decrypt round-trip
  Plaintext m   = 42
  Ciphertext c  = m^e mod n  = <large number>
  Decrypted     = c^d mod n  = 42
  ✓ Round-trip successful

TEST 1 : Multiplicative Homomorphism
  Enc(7) × Enc(6) mod n  →  Dec = 42  ✓

TEST 2 : Operate-then-Encrypt == Encrypt-then-Operate
  Dec(Path A) == Dec(Path B) == 221  ✓
  Ciphertexts are IDENTICAL  (RSA is deterministic)

TEST 3 : Exponentiation — Enc(m)^k == Enc(m^k)
  Both paths → 625  (= 5^4)  ✓

TEST 4 : Chained multiplication
  Enc(2)×Enc(3)×…×Enc(11) → Dec = 2310  ✓

All tests passed ✓
```

### Paillier Sample Output

```
========================================================================
   Paillier Cryptosystem — Homomorphic Encryption Verification
========================================================================

[*] Generating 1024-bit Paillier key-pair …

BASIC TEST : Round-trip for m ∈ {0, 1, 25, 999, 123456789}  ✓

TEST 1 : Additive Homomorphism
  Enc(15) × Enc(25) mod n² → Dec = 40  ✓

TEST 2 : Add plaintext constant
  Enc(100) × g^50 → Dec = 150  ✓

TEST 3 : Scalar multiplication
  Enc(7)^8 → Dec = 56  ✓

TEST 4 : Operate-then-Encrypt == Encrypt-then-Operate
  Both paths → 333  ✓
  Ciphertexts DIFFER  (probabilistic — semantically secure)

TEST 5 : Probabilistic — same m=42, five different ciphertexts  ✓

TEST 6 : Chained addition [10,20,30,40,50] → 150  ✓

TEST 7 : Weighted sum 2×5 + 3×10 + 4×15 = 100  ✓

All tests passed ✓
```

### API Quick Reference

```python
# ── RSA ──────────────────────────────────────────────────────────────
from rsa import generate_keypair, encrypt, decrypt
from rsa import multiply_encrypted, exponentiate_plain

pub, priv = generate_keypair(2048)       # (n, e), (n, d)

c1 = encrypt(pub, 6)
c2 = encrypt(pub, 7)

# Homomorphic multiplication
c_prod = multiply_encrypted(pub, c1, c2)
print(decrypt(priv, c_prod))             # → 42

# Homomorphic exponentiation
c_exp = exponentiate_plain(pub, c1, 3)
print(decrypt(priv, c_exp))              # → 216  (= 6^3)


# ── Paillier ──────────────────────────────────────────────────────────
from paillier_cryptosystem import generate_keypair, encrypt, decrypt
from paillier_cryptosystem import add_encrypted, add_plain, multiply_plain

pub, priv = generate_keypair(2048)       # (n, g), (λ, μ)

c1 = encrypt(pub, 15)
c2 = encrypt(pub, 27)

# Homomorphic addition
c_sum = add_encrypted(pub, c1, c2)
print(decrypt(pub, priv, c_sum))         # → 42

# Add a plaintext constant
c_add = add_plain(pub, c1, 5)
print(decrypt(pub, priv, c_add))         # → 20

# Scalar multiplication
c_mul = multiply_plain(pub, c1, 3)
print(decrypt(pub, priv, c_mul))         # → 45
```

---

## File Structure

```
BTP/
├── rsa.py                     # RSA: multiplicative homomorphic encryption
├── paillier_cryptosystem.py   # Paillier: additive homomorphic encryption
└── README.md                  # This file
```


---

## License

This project is for academic / educational purposes (B.Tech Project).
