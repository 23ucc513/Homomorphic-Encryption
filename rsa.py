"""
================================================================================
  RSA Cryptosystem — Full Implementation with Multiplicative Homomorphism
================================================================================

BACKGROUND
----------
RSA (Rivest–Shamir–Adleman, 1977) is one of the first public-key cryptosystems.
Its security rests on the **difficulty of factoring the product of two large
primes**.  A beautiful side-effect of its algebraic structure is that RSA is
**multiplicatively homomorphic**:

    Enc(m₁) × Enc(m₂)  mod n  =  Enc(m₁ × m₂  mod n)

This means you can multiply ciphertexts in the "encrypted world" and, when you
decrypt the result, you get the product of the original plaintexts — all
*without* ever seeing the raw data.

WHAT IS HOMOMORPHIC ENCRYPTION?
-------------------------------
Homomorphic encryption lets you **compute on ciphertexts** so that the result,
once decrypted, matches the same computation done on the plaintexts.

    Plaintext world:   m₁  ⊕  m₂  =  m₃
    Ciphertext world:  Enc(m₁) ⊗ Enc(m₂) = Enc(m₃)

For RSA the supported operation (⊕) is **multiplication** (mod n).
RSA does NOT natively support addition on ciphertexts — for that, look at the
Paillier cryptosystem (paillier_cryptosystem.py).

NOTATION USED IN THIS FILE
---------------------------
    p, q    — two large secret primes
    n       — public modulus  =  p × q
    φ(n)    — Euler's totient  =  (p−1)(q−1)
    e       — public exponent   (part of the public key)
    d       — private exponent  (part of the private key)
    m       — plaintext message  (an integer 0 ≤ m < n)
    c       — ciphertext         (an integer 0 ≤ c < n)
"""

import random
import math
from sympy import randprime       # generates a random prime in a given range


# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║  STEP 1 — KEY GENERATION                                                ║
# ║                                                                          ║
# ║  We create a *public key* (n, e) that anyone can use to encrypt,         ║
# ║  and a *private key* (n, d) that only the owner can use to decrypt.      ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

def generate_keypair(bits=512):
    """
    Generate an RSA public/private key-pair.

    Algorithm
    ---------
    1. Pick two large random primes p and q, each of `bits` bits.
       → The product n = p·q will be about 2·bits bits long.
       → The bigger the primes, the harder it is to factor n → more secure.

    2. Compute n = p × q.
       → n is the **modulus**; it appears in both keys and is public.

    3. Compute Euler's totient  φ(n) = (p−1)(q−1).
       → φ(n) counts the integers in [1, n) that are coprime to n.
       → Knowing φ(n) is equivalent to knowing the factorisation of n,
         so φ(n) must remain SECRET.

    4. Choose the public exponent e.
       → e must satisfy  1 < e < φ(n)  and  gcd(e, φ(n)) = 1.
       → The standard choice is e = 65537 (= 2¹⁶ + 1).
         It is prime, has only two bits set (fast modular exponentiation),
         and is large enough to resist certain attacks.

    5. Compute the private exponent d = e⁻¹ mod φ(n).
       → d is the modular multiplicative inverse of e modulo φ(n).
       → This means  e·d ≡ 1  (mod φ(n)).
       → Knowing d lets you "undo" encryption:  (mᵉ)ᵈ = m^(ed) ≡ m (mod n)
         by Euler's theorem, since ed ≡ 1 (mod φ(n)).

    Returns
    -------
    public_key  : (n, e)
    private_key : (n, d)
    """

    # ── Step 1a: Generate two large random primes ────────────────────────
    #    randprime(a, b) returns a random prime p such that a ≤ p < b.
    #    We want primes of exactly `bits` bits, so we pick from
    #    [2^(bits-1), 2^bits).
    p = randprime(2**(bits - 1), 2**bits)
    q = randprime(2**(bits - 1), 2**bits)
    #    Security note: p and q should not be too close together;
    #    for production code additional checks are needed.

    # ── Step 2: Compute n = p × q ────────────────────────────────────────
    #    n is public.  Its bit-length ≈ 2 × bits.
    n = p * q

    # ── Step 3: Compute Euler's totient φ(n) = (p−1)(q−1) ───────────────
    #    This uses the formula for φ of a product of two distinct primes.
    #    φ(n) must stay secret — anyone who learns φ(n) can compute d.
    phi = (p - 1) * (q - 1)

    # ── Step 4: Choose the public exponent e ─────────────────────────────
    #    65537 is the industry-standard choice.
    #    If by some astronomically unlikely chance gcd(e, φ) ≠ 1,
    #    we fall back to picking a random e.
    e = 65537
    while math.gcd(e, phi) != 1:
        e = random.randrange(2, phi)

    # ── Step 5: Compute the private exponent d ≡ e⁻¹ (mod φ) ────────────
    #    Python 3.8+ supports  pow(e, -1, phi)  for the modular inverse.
    #    d satisfies:  e × d  ≡  1  (mod φ(n))
    d = pow(e, -1, phi)

    # ── Assemble keys ────────────────────────────────────────────────────
    public_key  = (n, e)
    private_key = (n, d)

    return public_key, private_key


# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║  STEP 2 — ENCRYPTION                                                    ║
# ║                                                                          ║
# ║  Anyone who has the public key (n, e) can encrypt a message m:           ║
# ║      c = m^e  mod n                                                      ║
# ║                                                                          ║
# ║  • m must be an integer with 0 ≤ m < n.                                  ║
# ║  • The ciphertext c is also an integer in [0, n).                        ║
# ║  • Without knowing d, recovering m from c is as hard as factoring n.     ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

def encrypt(public_key, message):
    """
    RSA Encryption:   c = m^e  mod n

    Why does this work?
    -------------------
    • Modular exponentiation is a **one-way function**: easy to compute
      c = m^e mod n, but extremely hard to reverse (find m given c, e, n)
      without knowing the factorisation of n.

    Parameters
    ----------
    public_key : (n, e)
    message    : int — the plaintext integer  (0 ≤ m < n)

    Returns
    -------
    ciphertext : int
    """
    n, e = public_key

    # Compute c = m^e mod n  using Python's built-in fast modular
    # exponentiation (square-and-multiply, runs in O(log e) multiplications).
    ciphertext = pow(message, e, n)

    return ciphertext


# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║  STEP 3 — DECRYPTION                                                    ║
# ║                                                                          ║
# ║  The owner of the private key (n, d) can decrypt c:                      ║
# ║      m = c^d  mod n                                                      ║
# ║                                                                          ║
# ║  Why does decryption recover m?                                          ║
# ║      c^d  =  (m^e)^d  =  m^(e·d)  mod n                                ║
# ║  Since  e·d ≡ 1 (mod φ(n)),  by Euler's theorem:                        ║
# ║      m^(e·d)  ≡  m^(1 + k·φ(n))                                         ║
# ║              =  m · (m^φ(n))^k                                           ║
# ║              ≡  m · 1^k           (Euler's theorem: m^φ(n) ≡ 1 mod n)   ║
# ║              =  m                                                        ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

def decrypt(private_key, ciphertext):
    """
    RSA Decryption:   m = c^d  mod n

    Parameters
    ----------
    private_key : (n, d)
    ciphertext  : int

    Returns
    -------
    message : int — the original plaintext
    """
    n, d = private_key

    # Compute m = c^d mod n  (fast modular exponentiation)
    message = pow(ciphertext, d, n)

    return message


# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║  STEP 4 — HOMOMORPHIC OPERATIONS  (the magic!)                          ║
# ║                                                                          ║
# ║  RSA's encryption function  Enc(m) = m^e mod n  is a **homomorphism**    ║
# ║  with respect to multiplication modulo n.                                ║
# ║                                                                          ║
# ║  Algebraic proof:                                                        ║
# ║      Enc(m₁) × Enc(m₂)  =  m₁^e × m₂^e  =  (m₁ × m₂)^e  mod n       ║
# ║                          =  Enc(m₁ × m₂  mod n)                         ║
# ║                                                                          ║
# ║  Three useful operations follow from this property:                      ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

def multiply_encrypted(public_key, c1, c2):
    """
    OPERATION 1 — Multiply two ciphertexts (homomorphic multiplication).

    Given:
        c₁ = Enc(m₁) = m₁^e mod n
        c₂ = Enc(m₂) = m₂^e mod n

    Compute:
        c₁ × c₂ mod n  =  m₁^e × m₂^e mod n
                        =  (m₁ × m₂)^e  mod n      ← by exponent rule
                        =  Enc(m₁ × m₂  mod n)

    So when you decrypt this result you get  m₁ × m₂  mod n.
    """
    n, _ = public_key
    return (c1 * c2) % n


def multiply_plain(public_key, ciphertext, scalar):
    """
    OPERATION 2 — Multiply an encrypted value by a *known* plaintext scalar.

    Approach:  encrypt the scalar → use homomorphic multiply.

        Enc(m) × Enc(k) mod n  =  Enc(m × k  mod n)

    This is useful when a server wants to scale an encrypted value by a
    public constant without ever seeing the underlying plaintext.
    """
    c_scalar = encrypt(public_key, scalar)
    return multiply_encrypted(public_key, ciphertext, c_scalar)


def exponentiate_plain(public_key, ciphertext, exponent):
    """
    OPERATION 3 — Raise an encrypted value to a *known* plaintext power.

    Given:
        c = Enc(m) = m^e mod n

    Compute:
        c^k mod n  =  (m^e)^k mod n
                   =  m^(e·k)  mod n
                   =  (m^k)^e  mod n      ← exponentiation is commutative
                   =  Enc(m^k  mod n)

    So decrypting  c^k  yields  m^k mod n.
    """
    n, _ = public_key
    return pow(ciphertext, exponent, n)


# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║  STEP 5 — DEMONSTRATION / SELF-TEST                                     ║
# ║                                                                          ║
# ║  We run four tests to verify the homomorphic properties hold.            ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

if __name__ == "__main__":

    KEY_BITS = 512          # Small for demo speed — use ≥ 1024 in production

    print("=" * 72)
    print("   RSA Cryptosystem — Homomorphic Encryption Verification")
    print("=" * 72)

    # ─────────────────────────────────────────────────────────────────────
    #  KEY GENERATION
    #  Generate a fresh RSA key-pair.  The public key (n, e) is shared
    #  openly; the private key (n, d) is kept secret.
    # ─────────────────────────────────────────────────────────────────────
    print(f"\n[*] Generating {KEY_BITS * 2}-bit RSA key-pair …")
    public_key, private_key = generate_keypair(KEY_BITS)
    n, e = public_key
    _, d = private_key
    print(f"    n  ({n.bit_length()} bits)  — the public modulus")
    print(f"    e  = {e}  — the public exponent")
    print(f"    d  (secret, {d.bit_length()} bits)  — the private exponent")

    # ─────────────────────────────────────────────────────────────────────
    #  BASIC ENCRYPT / DECRYPT SANITY CHECK
    #  Before testing homomorphic properties, let's confirm basic
    #  encryption and decryption work correctly.
    # ─────────────────────────────────────────────────────────────────────
    print("\n" + "─" * 72)
    print("   BASIC TEST : Encrypt → Decrypt round-trip")
    print("─" * 72)

    m_test = 42
    print(f"\n    Plaintext m   = {m_test}")
    c_test = encrypt(public_key, m_test)
    print(f"    Ciphertext c  = m^e mod n  = {c_test}")
    d_test = decrypt(private_key, c_test)
    print(f"    Decrypted     = c^d mod n  = {d_test}")
    assert d_test == m_test, "Basic encrypt/decrypt FAILED!"
    print(f"    ✓ Round-trip successful: {m_test} → Enc → Dec → {d_test}")

    # ==================================================================
    #  TEST 1 : Product of two ciphertexts == Enc(product of plaintexts)
    #
    #  Core homomorphic property:
    #      Enc(m₁) × Enc(m₂) mod n  =  Enc(m₁ × m₂ mod n)
    # ==================================================================
    print("\n" + "─" * 72)
    print("   TEST 1 : Multiplicative Homomorphism — two values")
    print("─" * 72)

    m1, m2 = 7, 6
    print(f"\n    Plaintexts:  m₁ = {m1},  m₂ = {m2}")
    print(f"    Expected product:  m₁ × m₂ = {m1 * m2}")

    # Encrypt each plaintext individually
    c1 = encrypt(public_key, m1)
    c2 = encrypt(public_key, m2)
    print(f"\n    Step 1 — Encrypt each message:")
    print(f"      Enc(m₁) = {m1}^{e} mod n = {c1}")
    print(f"      Enc(m₂) = {m2}^{e} mod n = {c2}")

    # Multiply the ciphertexts (in the encrypted domain)
    c_product = multiply_encrypted(public_key, c1, c2)
    print(f"\n    Step 2 — Multiply ciphertexts (homomorphic operation):")
    print(f"      Enc(m₁) × Enc(m₂) mod n = {c_product}")

    # Decrypt the product ciphertext
    dec_product = decrypt(private_key, c_product)
    plain_product = (m1 * m2) % n
    print(f"\n    Step 3 — Decrypt the result:")
    print(f"      Dec( Enc(m₁) × Enc(m₂) )  = {dec_product}")
    print(f"      m₁ × m₂  mod n             = {plain_product}")

    assert dec_product == plain_product, "TEST 1 FAILED!"
    print(f"\n    ✓ {dec_product} == {plain_product}  —  Homomorphic multiplication works!")

    # ==================================================================
    #  TEST 2 : Operate-then-Encrypt  vs  Encrypt-then-Operate
    #
    #  Two equivalent paths to the same result:
    #    Path A:  multiply plaintexts → encrypt the product
    #    Path B:  encrypt each plaintext → multiply ciphertexts
    #  For deterministic RSA, even the ciphertexts are identical!
    # ==================================================================
    print("\n" + "─" * 72)
    print("   TEST 2 : Operate-then-Encrypt  ==  Encrypt-then-Operate")
    print("─" * 72)

    m1, m2 = 13, 17
    print(f"\n    Plaintexts:  m₁ = {m1},  m₂ = {m2}")

    # ── Path A: multiply first, then encrypt ─────────────────────────
    product_plain = (m1 * m2) % n
    c_path_a = encrypt(public_key, product_plain)
    print(f"\n    PATH A  (operate → encrypt):")
    print(f"      Step 1:  m₁ × m₂ mod n       = {product_plain}")
    print(f"      Step 2:  Enc(m₁ × m₂)        = {c_path_a}")

    # ── Path B: encrypt first, then multiply ciphertexts ─────────────
    c1 = encrypt(public_key, m1)
    c2 = encrypt(public_key, m2)
    c_path_b = multiply_encrypted(public_key, c1, c2)
    print(f"\n    PATH B  (encrypt → operate):")
    print(f"      Step 1:  Enc(m₁) = {c1}")
    print(f"      Step 2:  Enc(m₂) = {c2}")
    print(f"      Step 3:  Enc(m₁) × Enc(m₂) mod n = {c_path_b}")

    # ── Compare decrypted results ────────────────────────────────────
    dec_a = decrypt(private_key, c_path_a)
    dec_b = decrypt(private_key, c_path_b)
    print(f"\n    Decrypted Path A:  {dec_a}")
    print(f"    Decrypted Path B:  {dec_b}")
    print(f"    Plain product:     {product_plain}")

    assert dec_a == dec_b == product_plain, "TEST 2 FAILED!"
    print(f"\n    ✓ Dec(Path A) == Dec(Path B) == m₁×m₂  →  {dec_a}")

    # RSA is deterministic → ciphertexts should be identical:
    #   Path A:  Enc(m₁·m₂) = (m₁·m₂)^e mod n
    #   Path B:  Enc(m₁)·Enc(m₂) = m₁^e · m₂^e = (m₁·m₂)^e mod n
    if c_path_a == c_path_b:
        print(f"    ✓ Ciphertexts are IDENTICAL  (RSA is deterministic)")
        print(f"      (m₁·m₂)^e mod n  ==  m₁^e · m₂^e mod n")

    # ==================================================================
    #  TEST 3 : Exponentiation — Enc(m)^k == Enc(m^k)
    #
    #  Direct consequence of multiplicative homomorphism:
    #    Enc(m)^k  =  (m^e)^k  =  m^(ek)  =  (m^k)^e  =  Enc(m^k)
    # ==================================================================
    print("\n" + "─" * 72)
    print("   TEST 3 : Exponentiation — Enc(m)^k == Enc(m^k)")
    print("─" * 72)

    m, k = 5, 4
    print(f"\n    Plaintext m = {m},  exponent k = {k}")

    # Path A: exponentiate plaintext, then encrypt
    mk_plain = pow(m, k, n)
    c_exp_a = encrypt(public_key, mk_plain)
    print(f"\n    PATH A  (operate → encrypt):")
    print(f"      m^k mod n   = {m}^{k} mod n = {mk_plain}")
    print(f"      Enc(m^k)    = {c_exp_a}")

    # Path B: encrypt plaintext, then raise ciphertext to power k
    c_m = encrypt(public_key, m)
    c_exp_b = exponentiate_plain(public_key, c_m, k)
    print(f"\n    PATH B  (encrypt → operate):")
    print(f"      Enc(m)      = {c_m}")
    print(f"      Enc(m)^k    = {c_exp_b}")

    dec_exp_a = decrypt(private_key, c_exp_a)
    dec_exp_b = decrypt(private_key, c_exp_b)
    print(f"\n    Decrypted Path A:  {dec_exp_a}")
    print(f"    Decrypted Path B:  {dec_exp_b}")

    assert dec_exp_a == dec_exp_b == mk_plain, "TEST 3 FAILED!"
    print(f"\n    ✓ Both paths → {mk_plain}  (= {m}^{k})")
    if c_exp_a == c_exp_b:
        print(f"    ✓ Ciphertexts are IDENTICAL")
        print(f"      (m^k)^e ≡ (m^e)^k ≡ m^(ek)  mod n")

    # ==================================================================
    #  TEST 4 : Chained multiplication of multiple values
    #
    #  The homomorphic property extends to any number of factors:
    #    Enc(a)·Enc(b)·Enc(c)·…  =  Enc(a·b·c·…  mod n)
    # ==================================================================
    print("\n" + "─" * 72)
    print("   TEST 4 : Chained multiplication — multiple values")
    print("─" * 72)

    values = [2, 3, 5, 7, 11]
    print(f"\n    Values: {values}")

    # Path A: multiply all plaintexts, then encrypt
    product_all = 1
    for v in values:
        product_all = (product_all * v) % n
    c_chain_a = encrypt(public_key, product_all)

    # Path B: encrypt each value, then multiply all ciphertexts
    ciphertexts = [encrypt(public_key, v) for v in values]
    c_chain_b = ciphertexts[0]
    for ci in ciphertexts[1:]:
        c_chain_b = multiply_encrypted(public_key, c_chain_b, ci)

    dec_chain_a = decrypt(private_key, c_chain_a)
    dec_chain_b = decrypt(private_key, c_chain_b)

    print(f"\n    PATH A (multiply plaintexts → encrypt):")
    print(f"      {'×'.join(map(str, values))} = {product_all}")
    print(f"      Enc({product_all}) → Dec = {dec_chain_a}")

    print(f"\n    PATH B (encrypt each → multiply ciphertexts):")
    print(f"      Enc({values[0]})×Enc({values[1]})×…×Enc({values[-1]}) → Dec = {dec_chain_b}")

    assert dec_chain_a == dec_chain_b == product_all, "TEST 4 FAILED!"
    print(f"\n    ✓ Both paths → {product_all}")
    if c_chain_a == c_chain_b:
        print(f"    ✓ Ciphertexts are IDENTICAL!")

    # ==================================================================
    #  SUMMARY
    # ==================================================================
    print("\n" + "=" * 72)
    print("   SUMMARY")
    print("=" * 72)
    print("""
    RSA is deterministic and multiplicatively homomorphic:

      Enc(m₁) × Enc(m₂) mod n  =  Enc(m₁ × m₂  mod n)
      Enc(m)^k           mod n  =  Enc(m^k        mod n)

    ┌────────────────────────────────────────────────────────────────────┐
    │  Operate THEN Encrypt  ≡  Encrypt THEN Operate                    │
    │                                                                    │
    │  Enc(m₁ × m₂)  ==  Enc(m₁) × Enc(m₂)   mod n                    │
    │  Enc(m^k)       ==  Enc(m)^k             mod n                    │
    │                                                                    │
    │  Both produce the SAME ciphertext (RSA is deterministic).         │
    │                                                                    │
    │  Limitation: RSA supports multiplication only — NOT addition.     │
    │  For additive homomorphism, see the Paillier cryptosystem.        │
    └────────────────────────────────────────────────────────────────────┘

    All tests passed ✓
    """)
    print("=" * 72)
