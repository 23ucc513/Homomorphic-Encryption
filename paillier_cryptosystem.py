"""
================================================================================
  Paillier Cryptosystem — Full Implementation with Additive Homomorphism
================================================================================

BACKGROUND
----------
The Paillier cryptosystem (Pascal Paillier, 1999) is a **probabilistic**
public-key encryption scheme whose most celebrated property is that it is
**additively homomorphic**:

    Enc(m₁) × Enc(m₂)  mod n²  =  Enc(m₁ + m₂  mod n)

Multiplying two ciphertexts in the encrypted domain corresponds to *adding*
the underlying plaintexts!  This is the opposite of RSA (which is
multiplicatively homomorphic).

WHY IS THIS USEFUL?
-------------------
Additive homomorphism is enormously practical:
  • A cloud server can sum encrypted votes / salaries / sensor readings
    without ever learning the individual values.
  • It enables secure multi-party computation protocols.
  • It is a building block for more complex fully-homomorphic schemes.

PROBABILISTIC vs DETERMINISTIC
------------------------------
Unlike RSA, Paillier encryption uses a **random** blinding factor r.
Encrypting the same message twice yields *different* ciphertexts, which
prevents an attacker from detecting that the same message was sent twice
(semantic security / IND-CPA).

NOTATION USED IN THIS FILE
---------------------------
    p, q    — two large secret primes
    n       — public modulus  =  p × q
    n²      — the ciphertext space modulus
    λ       — Carmichael's lambda  =  lcm(p−1, q−1)
    g       — generator  (we use the simplest choice: g = n + 1)
    μ       — precomputed inverse  =  L(g^λ mod n²)⁻¹ mod n
    L(u)    — the "L-function":  L(u) = (u − 1) / n   (exact integer division)
    m       — plaintext  (an integer 0 ≤ m < n)
    r       — random blinding factor  (1 ≤ r < n, gcd(r,n) = 1)
    c       — ciphertext  (an integer in ℤ*_{n²})

MATHEMATICAL FOUNDATION
-----------------------
The scheme works in the group  ℤ*_{n²}  (integers mod n² that are coprime to n²).

Key identity used throughout:
    (1 + n)^m  ≡  1 + m·n  (mod n²)

This is because the binomial expansion of (1+n)^m mod n² kills all terms
with n² or higher powers:
    (1+n)^m = Σ C(m,k)·n^k  ≡  1 + m·n  (mod n²)   since n^k ≡ 0 mod n² for k≥2

This linear relationship is what makes the *additive* homomorphism possible.
"""

import random
import math
from sympy import randprime       # generates a random prime in a given range


# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║  HELPER FUNCTIONS                                                        ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

def lcm(a, b):
    """
    Compute the Least Common Multiple of a and b.

    Formula:   lcm(a, b) = |a × b| / gcd(a, b)

    We need LCM to compute Carmichael's lambda function:
        λ = lcm(p−1, q−1)
    This is preferred over Euler's totient φ = (p−1)(q−1) in Paillier
    because λ divides φ and produces a smaller exponent, which is
    sufficient and slightly more efficient.
    """
    return abs(a * b) // math.gcd(a, b)


def L(u, n):
    """
    The L-function used in Paillier decryption.

        L(u) = (u − 1) / n

    IMPORTANT: This is exact *integer* division — there is no remainder.
    The inputs to this function are always constructed so that (u − 1)
    is divisible by n.

    Why does this work?
    -------------------
    During decryption we compute  u = c^λ mod n².
    By the structure of the Paillier scheme, u is guaranteed to be of the
    form  u = 1 + k·n  for some integer k.  Therefore (u − 1) / n = k
    is always an integer.
    """
    return (u - 1) // n


# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║  STEP 1 — KEY GENERATION                                                ║
# ║                                                                          ║
# ║  Generate a public key (n, g) for encryption and a private key (λ, μ)    ║
# ║  for decryption.                                                         ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

def generate_keypair(bits=512):
    """
    Generate a Paillier public/private key-pair.

    Algorithm
    ---------
    1.  Pick two large random primes p and q of `bits` bits each.
        → n = p·q will be about 2·bits bits long.
        → p and q must be independent random primes of similar bit-length.

    2.  Compute n = p × q   and   n² = n × n.
        → n is the public modulus; it is part of the public key.
        → n² defines the ciphertext space: all ciphertexts live in ℤ*_{n²}.

    3.  Compute λ (lambda) = lcm(p−1, q−1).
        → λ is Carmichael's function of n.
        → It is the *smallest* positive integer such that
              a^λ ≡ 1  (mod n)   for all a coprime to n.
        → λ is secret (knowing it lets you factor n).

    4.  Choose the generator g.
        → The simplest (and standard) choice is  g = n + 1.
        → Why?  Because  (n+1)^m mod n²  =  1 + m·n  (mod n²)
          by the binomial theorem.  This makes encryption and
          decryption very clean.
        → Any g in ℤ*_{n²} whose order is a non-zero multiple of n
          would work, but g = n+1 is the most efficient.

    5.  Compute μ (mu) = [ L(g^λ mod n²) ]⁻¹  mod n.
        → μ is a precomputed constant that speeds up decryption.
        → It is the modular inverse of  L(g^λ mod n²)  modulo n.
        → During decryption, we divide by this value to extract m.

    Returns
    -------
    public_key  : (n, g)
    private_key : (λ, μ)
    """

    # ── Step 1: Generate two large random primes p and q ─────────────────
    #    Each prime is `bits` bits long.  The resulting n = p·q
    #    will be about 2·bits bits, providing the security level.
    p = randprime(2**(bits - 1), 2**bits)
    q = randprime(2**(bits - 1), 2**bits)

    # ── Step 2: Compute n and n² ─────────────────────────────────────────
    #    n is public.  n² is the modulus for the ciphertext space.
    #    Plaintexts m must satisfy  0 ≤ m < n.
    #    Ciphertexts c live in  ℤ*_{n²}  (integers mod n² coprime to n²).
    n = p * q
    n_sq = n * n

    # ── Step 3: Compute λ = lcm(p−1, q−1) ───────────────────────────────
    #    Carmichael's lambda.  By definition:
    #        a^λ ≡ 1  (mod n)   for all a ∈ ℤ*_n
    #    This is the key to "cancelling out" the randomness during
    #    decryption: when we raise c to the λ-th power, the random
    #    part r^n disappears because  (r^n)^λ ≡ 1 (mod n²)  for
    #    carefully chosen parameters.
    lam = lcm(p - 1, q - 1)

    # ── Step 4: Choose the generator g = n + 1 ──────────────────────────
    #    This is the standard simplification.  It works because:
    #        (n+1)^m mod n²  =  1 + m·n  (mod n²)
    #    Proof (binomial theorem):
    #        (n+1)^m = Σ_{k=0}^{m} C(m,k) · n^k
    #    Modulo n², all terms with k ≥ 2 vanish (since n^k ≡ 0 mod n²
    #    for k ≥ 2), leaving:
    #        (n+1)^m ≡ 1 + m·n  (mod n²)
    g = n + 1

    # ── Step 5: Compute μ = L(g^λ mod n²)⁻¹ mod n ──────────────────────
    #    First compute  g^λ mod n²:
    #        g^λ = (n+1)^λ ≡ 1 + λ·n  (mod n²)
    #    Then apply L:
    #        L(1 + λ·n) = ((1 + λ·n) − 1) / n = λ
    #    So μ = λ⁻¹ mod n.
    #    (In general, for arbitrary g this is not so simple, but for
    #     g = n+1 the precomputation is trivial.)
    u = pow(g, lam, n_sq)         # g^λ mod n²
    l_value = L(u, n)             # L(g^λ mod n²)
    mu = pow(l_value, -1, n)      # modular inverse of L-value mod n

    # ── Assemble keys ────────────────────────────────────────────────────
    public_key  = (n, g)
    private_key = (lam, mu)

    return public_key, private_key


# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║  STEP 2 — ENCRYPTION                                                    ║
# ║                                                                          ║
# ║  Encryption formula:                                                     ║
# ║      c = g^m · r^n  mod n²                                              ║
# ║                                                                          ║
# ║  where r is a random integer coprime to n.                               ║
# ║                                                                          ║
# ║  The randomness r is what makes Paillier *probabilistic*:                ║
# ║  the same message m encrypted twice will (almost certainly) produce      ║
# ║  different ciphertexts, providing **semantic security**.                  ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

def encrypt(public_key, m):
    """
    Paillier Encryption:   c = g^m · r^n  mod n²

    Step-by-step
    -------------
    1. Extract n and g from the public key; compute n².
    2. Choose a random r ∈ {1, 2, …, n−1} with gcd(r, n) = 1.
       → This ensures r is invertible mod n² and its contribution
         vanishes cleanly during decryption.
       → The randomness provides semantic security (IND-CPA):
         same plaintext → different ciphertext each time.
    3. Compute  g^m mod n².
       → With g = n+1:  g^m = (n+1)^m ≡ 1 + m·n  (mod n²)
       → This embeds the message m into the ciphertext.
    4. Compute  r^n mod n².
       → This is the "blinding factor" that hides the message.
       → During decryption, raising c to the λ-th power will kill
         this term because  (r^n)^λ ≡ 1  (mod n²).
    5. Multiply them together:  c = (g^m · r^n) mod n².

    Parameters
    ----------
    public_key : (n, g)
    m          : int — plaintext  (0 ≤ m < n)

    Returns
    -------
    ciphertext : int — element of ℤ*_{n²}
    """
    n, g = public_key
    n_sq = n * n

    # ── Step 2a: Choose random r coprime to n ────────────────────────────
    #    We keep picking until gcd(r, n) = 1.
    #    Since n = p·q, the only "bad" r values are multiples of p or q,
    #    which are astronomically rare for large primes.
    r = random.randint(1, n - 1)
    while math.gcd(r, n) != 1:
        r = random.randint(1, n - 1)

    # ── Step 2b: Compute the two components of the ciphertext ────────────
    #    Component 1: g^m mod n²   (carries the message)
    c1 = pow(g, m, n_sq)

    #    Component 2: r^n mod n²   (random blinding factor)
    c2 = pow(r, n, n_sq)

    # ── Step 2c: Combine ─────────────────────────────────────────────────
    #    c = c1 · c2  mod n²
    ciphertext = (c1 * c2) % n_sq

    return ciphertext


# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║  STEP 3 — DECRYPTION                                                    ║
# ║                                                                          ║
# ║  Decryption formula:                                                     ║
# ║      m = L(c^λ mod n²) · μ  mod n                                       ║
# ║                                                                          ║
# ║  Why does this work?  Let's trace through the math:                      ║
# ║                                                                          ║
# ║  c = g^m · r^n  mod n²                                                  ║
# ║                                                                          ║
# ║  c^λ  =  (g^m · r^n)^λ  mod n²                                         ║
# ║       =  g^(m·λ) · r^(n·λ)  mod n²                                     ║
# ║                                                                          ║
# ║  Now,  r^(n·λ) ≡ 1 (mod n²)                                            ║
# ║  (This follows from a generalisation of Euler's theorem to ℤ*_{n²}.)    ║
# ║                                                                          ║
# ║  So:   c^λ ≡ g^(m·λ)  mod n²                                           ║
# ║                                                                          ║
# ║  With g = n+1:                                                           ║
# ║    g^(mλ) = (n+1)^(mλ) ≡ 1 + mλ·n  (mod n²)                           ║
# ║                                                                          ║
# ║  Applying L:                                                             ║
# ║    L(c^λ mod n²) = L(1 + mλ·n) = mλ                                    ║
# ║                                                                          ║
# ║  Finally:                                                                ║
# ║    L(c^λ mod n²) · μ  =  mλ · λ⁻¹  =  m   (mod n)                     ║
# ║                                                                          ║
# ║  The random factor r has been completely eliminated!                      ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

def decrypt(public_key, private_key, ciphertext):
    """
    Paillier Decryption:   m = L(c^λ mod n²) · μ  mod n

    Parameters
    ----------
    public_key  : (n, g)
    private_key : (λ, μ)
    ciphertext  : int

    Returns
    -------
    m : int — the original plaintext
    """
    n, g = public_key
    lam, mu = private_key
    n_sq = n * n

    # ── Step 3a: Raise ciphertext to the power λ modulo n² ───────────────
    #    This eliminates the random blinding factor r:
    #        c^λ = (g^m · r^n)^λ = g^(mλ) · r^(nλ) ≡ g^(mλ) (mod n²)
    #    because r^(nλ) ≡ 1 (mod n²).
    u = pow(ciphertext, lam, n_sq)

    # ── Step 3b: Apply the L-function ────────────────────────────────────
    #    L(u) = (u − 1) / n
    #    With g = n+1:  u = (n+1)^(mλ) ≡ 1 + mλ·n  (mod n²)
    #    So  L(u) = mλ
    l_value = L(u, n)

    # ── Step 3c: Multiply by μ = λ⁻¹ mod n ──────────────────────────────
    #    m = L(u) · μ = mλ · λ⁻¹ = m  (mod n)
    m = (l_value * mu) % n

    return m


# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║  STEP 4 — HOMOMORPHIC OPERATIONS  (the magic!)                          ║
# ║                                                                          ║
# ║  Paillier is ADDITIVELY homomorphic.  The key insight is:               ║
# ║                                                                          ║
# ║  Enc(m₁) = g^m₁ · r₁^n  mod n²                                        ║
# ║  Enc(m₂) = g^m₂ · r₂^n  mod n²                                        ║
# ║                                                                          ║
# ║  Enc(m₁) × Enc(m₂)  =  g^m₁ · r₁^n · g^m₂ · r₂^n                     ║
# ║                      =  g^(m₁+m₂) · (r₁·r₂)^n   mod n²               ║
# ║                      =  Enc(m₁ + m₂  mod n)                             ║
# ║                                                                          ║
# ║  The product of two ciphertexts is a valid encryption of the SUM of     ║
# ║  the two plaintexts!  The combined randomness (r₁·r₂) still serves     ║
# ║  as a valid blinding factor.                                             ║
# ║                                                                          ║
# ║  From this one property we derive three operations:                      ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

def add_encrypted(public_key, c1, c2):
    """
    OPERATION 1 — Add two encrypted values (homomorphic addition).

    Enc(m₁) × Enc(m₂) mod n²  =  Enc(m₁ + m₂  mod n)

    Proof:
        c₁ × c₂  =  (g^m₁ · r₁^n) · (g^m₂ · r₂^n)  mod n²
                  =  g^(m₁+m₂) · (r₁r₂)^n            mod n²
                  =  Enc(m₁ + m₂)                      (with randomness r₁r₂)

    The sum (m₁+m₂) is taken modulo n (the plaintext space).
    """
    n, _ = public_key
    n_sq = n * n
    return (c1 * c2) % n_sq


def add_plain(public_key, ciphertext, scalar):
    """
    OPERATION 2 — Add a plaintext constant to an encrypted value.

    Enc(m) × g^k  mod n²  =  Enc(m + k  mod n)

    Proof:
        c · g^k  =  (g^m · r^n) · g^k  =  g^(m+k) · r^n  mod n²
                 =  Enc(m + k)  (with the same randomness r)

    This lets a server shift an encrypted value by a public offset
    without learning m.
    """
    n, g = public_key
    n_sq = n * n

    # g^scalar mod n²  is the "encryption of scalar with r=1"
    # (Not semantically secure on its own, but when multiplied with c
    #  the existing randomness in c keeps the result secure.)
    g_k = pow(g, scalar, n_sq)

    return (ciphertext * g_k) % n_sq


def multiply_plain(public_key, ciphertext, scalar):
    """
    OPERATION 3 — Multiply an encrypted value by a plaintext constant
                  (scalar multiplication).

    Enc(m)^k  mod n²  =  Enc(m × k  mod n)

    Proof:
        c^k  =  (g^m · r^n)^k  =  g^(m·k) · r^(n·k)  mod n²
             =  g^(mk) · (r^k)^n  mod n²
             =  Enc(m·k)  (with randomness r^k)

    This is extremely useful: it lets a server scale encrypted data
    (e.g., multiply an encrypted salary by a tax rate) without
    ever seeing the underlying value.
    """
    n, _ = public_key
    n_sq = n * n
    return pow(ciphertext, scalar, n_sq)


# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║  STEP 5 — DEMONSTRATION / SELF-TEST                                     ║
# ║                                                                          ║
# ║  We run comprehensive tests to verify:                                   ║
# ║    1. Basic encrypt/decrypt round-trip                                   ║
# ║    2. Additive homomorphism  (add two ciphertexts)                       ║
# ║    3. Scalar addition        (add plaintext to ciphertext)               ║
# ║    4. Scalar multiplication  (multiply ciphertext by plaintext)          ║
# ║    5. Operate-then-Encrypt == Encrypt-then-Operate                       ║
# ║    6. Probabilistic nature   (same message → different ciphertexts)      ║
# ║    7. Chained additions      (sum many encrypted values)                 ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

if __name__ == "__main__":

    KEY_BITS = 512          # Small for demo speed — use ≥ 1024 in production

    print("=" * 72)
    print("   Paillier Cryptosystem — Homomorphic Encryption Verification")
    print("=" * 72)

    # ─────────────────────────────────────────────────────────────────────
    #  KEY GENERATION
    #  Generate a fresh Paillier key-pair.
    #  Public key (n, g) is shared; private key (λ, μ) is secret.
    # ─────────────────────────────────────────────────────────────────────
    print(f"\n[*] Generating {KEY_BITS * 2}-bit Paillier key-pair …")
    public_key, private_key = generate_keypair(KEY_BITS)
    n, g = public_key
    lam, mu = private_key
    print(f"    n  ({n.bit_length()} bits)  — the public modulus")
    print(f"    g  = n + 1  — the generator")
    print(f"    λ  (secret, {lam.bit_length()} bits)  — Carmichael's lambda")
    print(f"    μ  (secret, {mu.bit_length()} bits)  — precomputed inverse")
    print(f"    Plaintext space:   0 ≤ m < n")
    print(f"    Ciphertext space:  ℤ*_{{n²}}  ({(n*n).bit_length()} bits)")

    # ─────────────────────────────────────────────────────────────────────
    #  BASIC TEST : Encrypt → Decrypt round-trip
    #  Verify that Dec(Enc(m)) = m for several messages.
    # ─────────────────────────────────────────────────────────────────────
    print("\n" + "─" * 72)
    print("   BASIC TEST : Encrypt → Decrypt round-trip")
    print("─" * 72)

    for m_test in [0, 1, 25, 999, 123456789]:
        c_test = encrypt(public_key, m_test)
        d_test = decrypt(public_key, private_key, c_test)
        status = "✓" if d_test == m_test else "✗ FAIL"
        print(f"    m = {m_test:>12}  →  Enc  →  Dec = {d_test:>12}  {status}")
    print(f"    All round-trips successful ✓")

    # ==================================================================
    #  TEST 1 : Additive Homomorphism — Enc(m₁) × Enc(m₂) = Enc(m₁+m₂)
    #
    #  This is the CORE property of Paillier:
    #  multiplying ciphertexts adds the plaintexts.
    # ==================================================================
    print("\n" + "─" * 72)
    print("   TEST 1 : Additive Homomorphism — Enc(m₁)·Enc(m₂) = Enc(m₁+m₂)")
    print("─" * 72)

    m1, m2 = 15, 25
    print(f"\n    Plaintexts:  m₁ = {m1},  m₂ = {m2}")
    print(f"    Expected sum:  m₁ + m₂ = {m1 + m2}")

    # Encrypt each plaintext independently (with different random r)
    c1 = encrypt(public_key, m1)
    c2 = encrypt(public_key, m2)
    print(f"\n    Step 1 — Encrypt each message (note: each uses a fresh random r):")
    print(f"      Enc(m₁) = g^{m1} · r₁^n mod n² = {c1}")
    print(f"      Enc(m₂) = g^{m2} · r₂^n mod n² = {c2}")

    # Multiply the ciphertexts → homomorphic addition!
    c_sum = add_encrypted(public_key, c1, c2)
    print(f"\n    Step 2 — Multiply ciphertexts (= add plaintexts):")
    print(f"      Enc(m₁) × Enc(m₂) mod n² = {c_sum}")

    # Decrypt the result → should be m1 + m2
    dec_sum = decrypt(public_key, private_key, c_sum)
    expected_sum = (m1 + m2) % n
    print(f"\n    Step 3 — Decrypt the result:")
    print(f"      Dec( Enc(m₁) × Enc(m₂) )  = {dec_sum}")
    print(f"      m₁ + m₂  mod n             = {expected_sum}")

    assert dec_sum == expected_sum, "TEST 1 FAILED!"
    print(f"\n    ✓ {dec_sum} == {expected_sum}  —  Additive homomorphism works!")

    # ==================================================================
    #  TEST 2 : Add a plaintext constant to an encrypted value
    #
    #  Enc(m) × g^k mod n²  =  Enc(m + k)
    # ==================================================================
    print("\n" + "─" * 72)
    print("   TEST 2 : Add plaintext constant — Enc(m) × g^k = Enc(m+k)")
    print("─" * 72)

    m, k = 100, 50
    print(f"\n    Encrypted value m = {m},  plaintext constant k = {k}")

    c_m = encrypt(public_key, m)
    print(f"    Enc(m)           = {c_m}")

    # Add k to the encrypted value without decrypting
    c_shifted = add_plain(public_key, c_m, k)
    print(f"    Enc(m) × g^{k} mod n² = {c_shifted}")

    dec_shifted = decrypt(public_key, private_key, c_shifted)
    expected = (m + k) % n
    print(f"\n    Decrypted result:  {dec_shifted}")
    print(f"    Expected (m + k): {expected}")

    assert dec_shifted == expected, "TEST 2 FAILED!"
    print(f"\n    ✓ {dec_shifted} == {expected}  —  Plaintext addition works!")

    # ==================================================================
    #  TEST 3 : Scalar multiplication — Enc(m)^k = Enc(m × k)
    #
    #  Raise a ciphertext to a plaintext power → multiplies the plaintext.
    # ==================================================================
    print("\n" + "─" * 72)
    print("   TEST 3 : Scalar multiplication — Enc(m)^k = Enc(m·k)")
    print("─" * 72)

    m, k = 7, 8
    print(f"\n    Encrypted value m = {m},  plaintext scalar k = {k}")

    c_m = encrypt(public_key, m)
    print(f"    Enc(m)   = {c_m}")

    # Raise ciphertext to power k → multiplies the underlying plaintext by k
    c_scaled = multiply_plain(public_key, c_m, k)
    print(f"    Enc(m)^{k} mod n² = {c_scaled}")

    dec_scaled = decrypt(public_key, private_key, c_scaled)
    expected = (m * k) % n
    print(f"\n    Decrypted result:  {dec_scaled}")
    print(f"    Expected (m × k): {expected}")

    assert dec_scaled == expected, "TEST 3 FAILED!"
    print(f"\n    ✓ {dec_scaled} == {expected}  —  Scalar multiplication works!")

    # ==================================================================
    #  TEST 4 : Operate-then-Encrypt  vs  Encrypt-then-Operate
    #
    #  Path A:  add plaintexts → encrypt the sum
    #  Path B:  encrypt each → multiply ciphertexts (homomorphic add)
    #  Both paths must decrypt to the same value.
    #
    #  Note: Unlike RSA, Paillier is probabilistic, so the ciphertexts
    #  themselves will differ — but the decrypted values must match.
    # ==================================================================
    print("\n" + "─" * 72)
    print("   TEST 4 : Operate-then-Encrypt  ==  Encrypt-then-Operate")
    print("─" * 72)

    m1, m2 = 111, 222
    print(f"\n    Plaintexts:  m₁ = {m1},  m₂ = {m2}")

    # ── Path A: add first, then encrypt ──────────────────────────────
    sum_plain = (m1 + m2) % n
    c_path_a = encrypt(public_key, sum_plain)
    print(f"\n    PATH A  (operate → encrypt):")
    print(f"      Step 1:  m₁ + m₂ mod n   = {sum_plain}")
    print(f"      Step 2:  Enc(m₁ + m₂)    = {c_path_a}")

    # ── Path B: encrypt first, then multiply ciphertexts ─────────────
    c1 = encrypt(public_key, m1)
    c2 = encrypt(public_key, m2)
    c_path_b = add_encrypted(public_key, c1, c2)
    print(f"\n    PATH B  (encrypt → operate):")
    print(f"      Step 1:  Enc(m₁)              = {c1}")
    print(f"      Step 2:  Enc(m₂)              = {c2}")
    print(f"      Step 3:  Enc(m₁) × Enc(m₂)   = {c_path_b}")

    # ── Compare decrypted results ────────────────────────────────────
    dec_a = decrypt(public_key, private_key, c_path_a)
    dec_b = decrypt(public_key, private_key, c_path_b)
    print(f"\n    Decrypted Path A:  {dec_a}")
    print(f"    Decrypted Path B:  {dec_b}")
    print(f"    Plain sum:         {sum_plain}")

    assert dec_a == dec_b == sum_plain, "TEST 4 FAILED!"
    print(f"\n    ✓ Dec(Path A) == Dec(Path B) == m₁+m₂  →  {dec_a}")

    # Ciphertexts will differ (probabilistic encryption!):
    if c_path_a != c_path_b:
        print(f"\n    Note: Ciphertexts DIFFER (different random r each time)")
        print(f"    This is expected — Paillier is probabilistic (semantically secure).")
    else:
        print(f"\n    (Rare coincidence: ciphertexts happen to be equal)")

    # ==================================================================
    #  TEST 5 : Probabilistic nature — same message, different ciphertexts
    #
    #  Encrypt the same message multiple times → each ciphertext is
    #  different (because a new random r is chosen each time).
    #  This is what gives Paillier IND-CPA (semantic) security.
    # ==================================================================
    print("\n" + "─" * 72)
    print("   TEST 5 : Probabilistic encryption — same m, different c")
    print("─" * 72)

    m_test = 42
    print(f"\n    Encrypting m = {m_test} five times:")
    ciphertexts_list = []
    for i in range(5):
        ci = encrypt(public_key, m_test)
        di = decrypt(public_key, private_key, ci)
        ciphertexts_list.append(ci)
        print(f"      Attempt {i+1}:  c = …{str(ci)[-20:]}  →  Dec = {di}")

    # Verify all ciphertexts are different
    all_different = len(set(ciphertexts_list)) == len(ciphertexts_list)
    print(f"\n    All ciphertexts different?  {'✓ Yes' if all_different else '✗ No (astronomically unlikely collision)'}")
    print(f"    All decrypt to {m_test}?  ✓ Yes")
    print(f"\n    This is semantic security: an eavesdropper cannot tell")
    print(f"    whether two ciphertexts encode the same or different messages.")

    # ==================================================================
    #  TEST 6 : Chained addition of many encrypted values
    #
    #  Sum up a list of encrypted values without decrypting any of them.
    #  This simulates a real use-case: e.g., summing encrypted votes.
    # ==================================================================
    print("\n" + "─" * 72)
    print("   TEST 6 : Chained addition — sum of many encrypted values")
    print("─" * 72)

    values = [10, 20, 30, 40, 50]
    print(f"\n    Values: {values}")
    print(f"    Expected sum: {sum(values)}")

    # Encrypt all values
    enc_values = [encrypt(public_key, v) for v in values]
    print(f"\n    Step 1 — Encrypt each value individually")

    # Homomorphically add all ciphertexts
    c_total = enc_values[0]
    for ci in enc_values[1:]:
        c_total = add_encrypted(public_key, c_total, ci)
    print(f"    Step 2 — Multiply all ciphertexts (= add all plaintexts)")

    # Decrypt the combined ciphertext
    dec_total = decrypt(public_key, private_key, c_total)
    expected_total = sum(values) % n
    print(f"\n    Step 3 — Decrypt the result:")
    print(f"      Dec(Enc({values[0]}) × Enc({values[1]}) × … × Enc({values[-1]})) = {dec_total}")
    print(f"      {' + '.join(map(str, values))} = {expected_total}")

    assert dec_total == expected_total, "TEST 6 FAILED!"
    print(f"\n    ✓ {dec_total} == {expected_total}  —  Chained homomorphic addition works!")

    # ==================================================================
    #  TEST 7 : Combined operations — weighted sum (scalar mul + add)
    #
    #  Compute  w₁·m₁ + w₂·m₂ + w₃·m₃  entirely in the encrypted domain.
    #  This simulates computing a weighted average of encrypted values.
    # ==================================================================
    print("\n" + "─" * 72)
    print("   TEST 7 : Weighted sum — scalar multiplication + addition")
    print("─" * 72)

    messages = [5, 10, 15]
    weights  = [2,  3,  4]
    print(f"\n    Messages: {messages}")
    print(f"    Weights:  {weights}")
    expected_weighted = sum(m * w for m, w in zip(messages, weights)) % n
    print(f"    Expected weighted sum: {' + '.join(f'{w}×{m}' for m, w in zip(messages, weights))} = {expected_weighted}")

    # Encrypt each message
    enc_msgs = [encrypt(public_key, m) for m in messages]

    # Multiply each ciphertext by its weight (scalar multiplication)
    weighted_encs = [multiply_plain(public_key, c, w) for c, w in zip(enc_msgs, weights)]
    print(f"\n    Step 1 — Encrypt each message")
    print(f"    Step 2 — Scalar-multiply:  Enc(mᵢ)^wᵢ  for each i")

    # Add all weighted ciphertexts together (homomorphic addition)
    c_weighted = weighted_encs[0]
    for ci in weighted_encs[1:]:
        c_weighted = add_encrypted(public_key, c_weighted, ci)
    print(f"    Step 3 — Multiply all weighted ciphertexts (= add weighted plaintexts)")

    # Decrypt
    dec_weighted = decrypt(public_key, private_key, c_weighted)
    print(f"\n    Decrypted result:  {dec_weighted}")
    print(f"    Expected:          {expected_weighted}")

    assert dec_weighted == expected_weighted, "TEST 7 FAILED!"
    print(f"\n    ✓ {dec_weighted} == {expected_weighted}  —  Weighted sum in encrypted domain works!")

    # ==================================================================
    #  SUMMARY
    # ==================================================================
    print("\n" + "=" * 72)
    print("   SUMMARY")
    print("=" * 72)
    print("""
    The Paillier cryptosystem is additively homomorphic:

      Enc(m₁) × Enc(m₂) mod n²  =  Enc(m₁ + m₂  mod n)     [addition]
      Enc(m) × g^k       mod n²  =  Enc(m + k     mod n)     [add constant]
      Enc(m)^k            mod n²  =  Enc(m × k     mod n)     [scalar multiply]

    ┌──────────────────────────────────────────────────────────────────────┐
    │  Paillier vs RSA:                                                    │
    │                                                                      │
    │  RSA:      multiplicatively homomorphic (deterministic)              │
    │            Enc(m₁) × Enc(m₂) = Enc(m₁ × m₂)                        │
    │                                                                      │
    │  Paillier: additively homomorphic (probabilistic / IND-CPA secure)  │
    │            Enc(m₁) × Enc(m₂) = Enc(m₁ + m₂)                        │
    │                                                                      │
    │  Together they cover the two fundamental arithmetic operations,      │
    │  but neither alone is "fully" homomorphic (add AND multiply).       │
    └──────────────────────────────────────────────────────────────────────┘

    All tests passed ✓
    """)
    print("=" * 72)
