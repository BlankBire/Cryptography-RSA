import pytest
from Crypto.PublicKey import RSA
import random
from attacks import factorization, timing_attack, cca_attack
import rsa_core


# ---------- FACTORIZATION TEST ----------
def test_trial_division_simple():
    n = 55  # 5 * 11
    p, q = factorization.trial_division(n)
    assert p * q == n and p != 1 and q != 1

def test_fermat_for_close_primes():
    p, q = 101, 103
    n = p * q
    pf1, pf2 = factorization.fermat_factor(n)
    assert pf1 * pf2 == n

def test_pollard_rho_composite():
    n = 8051  # 83 * 97
    p, q = factorization.pollards_rho(n)
    assert p * q == n

# ---------- TIMING ATTACK TEST ----------
def test_timing_attack_returns_timings():
    pub, priv = rsa_core.load_keys()
    results = timing_attack.timing_attack(priv, pub, trials=10)
    assert isinstance(results, list)
    assert len(results) == 10
    assert all(isinstance(t, float) for t in results)

# ---------- CCA ATTACK TEST ----------
def test_cca_attack_detects_valid_changes():
    pub, priv = rsa_core.load_keys()
    message = "Attack at dawn!"
    ciphertext = rsa_core.encrypt_message(message, pub)
    count = cca_attack.simulate_cca_attack(ciphertext, priv, pub)
    assert count >= 0
