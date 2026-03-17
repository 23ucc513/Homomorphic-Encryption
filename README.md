# Paillier Cryptosystem

A **public-key encryption scheme** invented by Pascal Paillier in 1999, notable for its **additive homomorphic** properties — allowing computations on ciphertexts that correspond to meaningful operations on the underlying plaintexts.

> **Reference:** Pascal Paillier, *"Public-Key Cryptosystems Based on Composite Degree Residuosity Classes"*, EUROCRYPT 1999.

---

## Table of Contents

1. [Overview](#overview)  
2. [Mathematical Background](#mathematical-background)  
3. [Key Generation](#key-generation)  
4. [Encryption](#encryption)  
5. [Decryption](#decryption)  
6. [Homomorphic Properties](#homomorphic-properties)  
7. [Security](#security)  
8. [Usage](#usage)  

---

## Overview

The Paillier cryptosystem is an **asymmetric (public-key)** encryption scheme that operates over the group $\mathbb{Z}_{n^2}^*$. Its most important feature is **additive homomorphism**: given only the public key, anyone can combine ciphertexts so that the result decrypts to the *sum* of the original plaintexts.

### Properties at a Glance

| Property | Description |
|---|---|
| **Type** | Asymmetric / Public-key |
| **Plaintext space** | $\mathbb{Z}_n = \{0, 1, \ldots, n-1\}$ |
| **Ciphertext space** | $\mathbb{Z}_{n^2}^*$ |
| **Homomorphism** | Additive |
| **Semantic security** | IND-CPA secure under the DCRA |

---

## Mathematical Background

### Notation

| Symbol | Meaning |
|---|---|
| $p, q$ | Large prime numbers |
| $n$ | $n = p \cdot q$ (RSA modulus) |
| $\lambda$ | $\lambda = \text{lcm}(p-1,\; q-1)$ (Carmichael's function) |
| $\mathbb{Z}_n^*$ | Multiplicative group of integers modulo $n$ |
| $g$ | Generator in $\mathbb{Z}_{n^2}^*$ |
| $L(u)$ | $L(u) = \dfrac{u - 1}{n}$ (defined for $u \equiv 1 \pmod{n}$) |

### The L-Function

The function $L$ is central to Paillier and is defined as:

$$
L(u) = \frac{u - 1}{n}
$$

This division is always exact (integer) when $u \equiv 1 \pmod{n}$.

### Composite Residuosity Assumption

The **Decisional Composite Residuosity Assumption (DCRA)** states that given $n$ and $z \in \mathbb{Z}_{n^2}^*$, it is computationally hard to decide whether $z$ is an $n$-th residue modulo $n^2$ (i.e., whether there exists $y$ such that $z \equiv y^n \pmod{n^2}$).

---

## Key Generation

### Steps

1. **Choose two large primes** $p$ and $q$ independently and randomly, each of bit-length $\lfloor k/2 \rfloor$ where $k$ is the desired key size.

2. **Compute the RSA modulus:**

$$
n = p \cdot q
$$

3. **Verify the condition:**

$$
\gcd(p \cdot q,\; (p-1)(q-1)) = 1
$$

   This is automatically satisfied when $p$ and $q$ are of equal length.

4. **Compute Carmichael's function:**

$$
\lambda = \text{lcm}(p - 1,\; q - 1)
$$

5. **Select the generator** (simplified choice):

$$
g = n + 1
$$

   This is the most common choice because it simplifies computation. Any $g \in \mathbb{Z}_{n^2}^*$ whose order is a non-zero multiple of $n$ also works.

6. **Compute the modular multiplicative inverse:**

$$
\mu = \left( L\!\left(g^{\lambda} \bmod n^2\right) \right)^{-1} \bmod n
$$

   With $g = n + 1$ this simplifies to $\mu = \lambda^{-1} \bmod n$.

### Keys

$$
\boxed{
\begin{aligned}
\textbf{Public Key}\; &: \quad (n,\; g) \\
\textbf{Private Key} &: \quad (\lambda,\; \mu)
\end{aligned}
}
$$

---

## Encryption

### Input
- Public key $(n, g)$
- Plaintext $m \in \mathbb{Z}_n$, i.e., $0 \le m < n$

### Steps

1. **Choose a random value** $r$ such that:

$$
r \in \mathbb{Z}_n^*, \quad \gcd(r, n) = 1
$$

2. **Compute the ciphertext:**

$$
\boxed{c = g^m \cdot r^n \bmod n^2}
$$

### Expansion

With the standard choice $g = n + 1$, by the binomial theorem:

$$
(n+1)^m \equiv 1 + m \cdot n \pmod{n^2}
$$

So the ciphertext becomes:

$$
c = (1 + m \cdot n) \cdot r^n \bmod n^2
$$

> **Note:** The random $r$ ensures **semantic security** — encrypting the same plaintext twice produces different ciphertexts.

---

## Decryption

### Input
- Private key $(\lambda, \mu)$
- Ciphertext $c \in \mathbb{Z}_{n^2}^*$

### Steps

1. **Compute:**

$$
u = c^{\lambda} \bmod n^2
$$

2. **Apply the L-function:**

$$
L(u) = \frac{u - 1}{n}
$$

3. **Recover the plaintext:**

$$
\boxed{m = L\!\left(c^{\lambda} \bmod n^2\right) \cdot \mu \bmod n}
$$

### Correctness Proof (Sketch)

Starting from $c = g^m \cdot r^n \bmod n^2$:

$$
c^{\lambda} \equiv g^{m\lambda} \cdot r^{n\lambda} \pmod{n^2}
$$

By Carmichael's theorem, $r^{n\lambda} \equiv 1 \pmod{n^2}$, so:

$$
c^{\lambda} \equiv g^{m\lambda} \pmod{n^2}
$$

Applying $L$:

$$
L(c^{\lambda} \bmod n^2) = m \cdot L(g^{\lambda} \bmod n^2) \bmod n
$$

Multiplying by $\mu = (L(g^{\lambda} \bmod n^2))^{-1} \bmod n$ recovers $m$.

---

## Homomorphic Properties

The Paillier cryptosystem supports three homomorphic operations:

### 1. Addition of Two Ciphertexts

Given $c_1 = \text{Enc}(m_1)$ and $c_2 = \text{Enc}(m_2)$:

$$
\boxed{c_1 \cdot c_2 \bmod n^2 = \text{Enc}(m_1 + m_2 \bmod n)}
$$

**Proof:**

$$
c_1 \cdot c_2 = g^{m_1} r_1^n \cdot g^{m_2} r_2^n = g^{m_1 + m_2} (r_1 r_2)^n \bmod n^2
$$

This is a valid encryption of $(m_1 + m_2) \bmod n$ with randomness $r_1 r_2$.

---

### 2. Addition of Ciphertext and Plaintext

Given $c = \text{Enc}(m_1)$ and a plaintext constant $m_2$:

$$
\boxed{c \cdot g^{m_2} \bmod n^2 = \text{Enc}(m_1 + m_2 \bmod n)}
$$

---

### 3. Scalar Multiplication (Ciphertext × Plaintext)

Given $c = \text{Enc}(m)$ and a scalar $k$:

$$
\boxed{c^k \bmod n^2 = \text{Enc}(k \cdot m \bmod n)}
$$

**Proof:**

$$
c^k = (g^m r^n)^k = g^{km} (r^k)^n \bmod n^2
$$

This is a valid encryption of $(k \cdot m) \bmod n$ with randomness $r^k$.

---

### Summary Table

| Operation | Formula | Result |
|---|---|---|
| Encrypted + Encrypted | $c_1 \cdot c_2 \bmod n^2$ | $\text{Enc}(m_1 + m_2)$ |
| Encrypted + Plaintext | $c \cdot g^{m_2} \bmod n^2$ | $\text{Enc}(m_1 + m_2)$ |
| Encrypted × Scalar | $c^k \bmod n^2$ | $\text{Enc}(k \cdot m)$ |

> **Note:** Paillier does **not** natively support multiplication of two encrypted values ($\text{Enc}(m_1) \otimes \text{Enc}(m_2) = \text{Enc}(m_1 \cdot m_2)$). For that, a **fully homomorphic** encryption scheme is needed.

---

## Security

### Assumptions

The semantic security (IND-CPA) of Paillier rests on the **Decisional Composite Residuosity Assumption (DCRA)**:

> It is computationally infeasible to distinguish $n$-th residues from non-residues modulo $n^2$.

### Key Size Recommendations

| Key size (bits of $n$) | Security level | Status |
|---|---|---|
| 1024 | ~80-bit | **Legacy / not recommended** |
| 2048 | ~112-bit | **Minimum recommended** |
| 3072 | ~128-bit | Recommended |
| 4096 | ~152-bit | High security |

### Properties

- **Semantic security (IND-CPA):** The random $r$ in each encryption ensures that the same plaintext maps to different ciphertexts.
- **Self-blinding:** Given a ciphertext, anyone can re-randomize it (multiply by $r'^n \bmod n^2$) without changing the plaintext — useful for privacy.
- **One-wayness:** Breaking the scheme (recovering $m$ from $c$) is at least as hard as factoring $n$.

---

## Usage

### Running the Demo

```bash
python3 paillier.py
```

### Sample Output

```
============================================================
  Paillier Cryptosystem — Demo
============================================================

[*] Generating 512-bit key-pair …
    ✓ Decryption correct

[*] Homomorphic addition: 17 + 25 = 42
    ✓ Correct

[*] Add plaintext constant: Enc(100) + 55 = 155
    ✓ Correct

[*] Scalar multiplication: 6 × Enc(7) = 42
    ✓ Correct

============================================================
  All tests passed ✓
============================================================
```

### API Quick Start

```python
from paillier import generate_keypair, encrypt, decrypt
from paillier import add_encrypted, add_plain, multiply_plain

# Generate keys (use ≥ 2048 bits for production)
pub, priv = generate_keypair(2048)

# Encrypt
c1 = encrypt(pub, 15)
c2 = encrypt(pub, 27)

# Homomorphic addition
c_sum = add_encrypted(pub, c1, c2)
print(decrypt(priv, c_sum))          # → 42

# Add a plaintext constant
c_add = add_plain(pub, c1, 5)
print(decrypt(priv, c_add))          # → 20

# Scalar multiplication
c_mul = multiply_plain(pub, c1, 3)
print(decrypt(priv, c_mul))          # → 45
```

---

## File Structure

```
BTP/
├── paillier.py                # Core implementation
├── paillier_cryptosystem.py   # Extended / alternate version
└── README.md                  # This file
```

---

## License

This project is for academic / educational purposes (B.Tech Project).
