from functools import reduce
import random


def encrypt(message, key):
    a, b = key
    encrypted_message = [modulo(ord(message[x]), a, b) for x in range(len(message))]

    return encrypted_message


def decrypt(message, key):
    a, b = key
    decrypted_message = [modulo(message[x], a, b) for x in range(len(message))]
    decrypted_str = reduce(lambda acc, x: acc + chr(x), decrypted_message, "")

    return decrypted_str


def generate_keys(m=None, n=None):
    if not m or not n:
        # Generate two primes
        prime_set = primes(20, 200)
        a = random.choice(list(prime_set))
        prime_set.remove(a)  # a and b must be different values
        b = random.choice(list(prime_set))
    else:
        prime_set = sorted(list(primes(1, 1000)))

        a = prime_set[m]
        b = prime_set[n]

    c = a * b
    m = (a - 1) * (b - 1)

    pub = public_key(m, c)
    priv = private_key(pub[0], m, c)

    return {
        'public': pub,
        'private': priv
    }


def public_key(m, c):
    e = m * 2 + 1

    while True:
        if GCD(e, m) == 1 and GCD(e, c) == 1 and mod_inverse(e, m) != 1:
            break
        else:
            e += 1

    return [e, c]


def private_key(e, m, c):
    return [mod_inverse(e, m), c]


def factors(n):
    factors = reduce(list.__add__, [[i, n // i] for i in range(1, int(n ** 0.5) + 1) if n % i == 0])
    return set(factors)


def primes(start, up_to):
    found_primes = set()

    for x in range(start, up_to):
        if factors(x) == {1, x}:
            found_primes.add(x)

    return found_primes


def GCD(a, b):
    if b == 0:
        return a
    else:
        return GCD(b, a % b)


def mod_inverse(a, m):
    def totient(n):
        num_coprimes = 0

        for x in range(n):
            if GCD(x, n) == 1:
                num_coprimes += 1

        return num_coprimes

    return (a ** (totient(m) - 1)) % m


def modulo(a, b, c):
    return (a ** b) % c
