import random
import statistics
import time
from typing import Dict, List

from Crypto.Cipher import PKCS1_v1_5
from Crypto import Random
from Crypto.PublicKey import RSA


def simulate_decryption_time(private_key: RSA.RsaKey, ciphertext: bytes) -> float:
    cipher = PKCS1_v1_5.new(private_key)
    start = time.perf_counter()
    sentinel = Random.new().read(15)

    delay_iterations = 500
    if hasattr(private_key, "d") and private_key.d is not None:
        if (private_key.d >> 4) & 1:
            delay_iterations = 1000

    for _ in range(delay_iterations):
        _ = 1 + 1

    cipher.decrypt(ciphertext, sentinel)
    return time.perf_counter() - start


def timing_attack(private_key: RSA.RsaKey, public_key: RSA.RsaKey, trials: int = 100) -> Dict:
    start_time = time.perf_counter()
    records: List[Dict[str, float | str | int]] = []
    cipher = PKCS1_v1_5.new(public_key)

    for trial in range(trials):
        plaintext = random.getrandbits(64).to_bytes(8, "big")
        ciphertext = cipher.encrypt(plaintext)
        duration = simulate_decryption_time(private_key, ciphertext)
        records.append({"trial": trial + 1, "duration": duration, "plaintext": plaintext.hex()})

    durations = [record["duration"] for record in records]
    return {
        "success": True,
        "results": records,
        "statistics": {
            "trials": trials,
            "average_time": sum(durations) / len(durations),
            "min_time": min(durations),
            "max_time": max(durations),
            "time_variance": max(durations) - min(durations),
        },
        "execution_time": time.perf_counter() - start_time,
    }


def simulate_timing_attack(n: int, e: int, trials: int = 10) -> Dict:
    start_total = time.perf_counter()
    try:
        key_size = max(512, min(n.bit_length(), 4096))
        generated_key = RSA.generate(key_size, e=e)
        private_key_for_sim = generated_key
        public_key_for_sim = generated_key.publickey()

        actual_d_bit_5 = (private_key_for_sim.d >> 4) & 1
        result = timing_attack(private_key_for_sim, public_key_for_sim, trials)

        durations = [entry["duration"] for entry in result["results"]]
        median_time = statistics.median(durations)
        group_fast = [duration for duration in durations if duration < median_time]
        group_slow = [duration for duration in durations if duration >= median_time]
        avg_fast = sum(group_fast) / len(group_fast)
        avg_slow = sum(group_slow) / len(group_slow)
        inference_threshold = (avg_fast + avg_slow) / 2

        inferred_d_bit_5 = 1 if result["statistics"]["average_time"] >= inference_threshold else 0
        inference_correct = inferred_d_bit_5 == actual_d_bit_5

        result["inference"] = {
            "target_bit_index": 4,
            "actual_bit_value": actual_d_bit_5,
            "inferred_bit_value": inferred_d_bit_5,
            "inference_correct": inference_correct,
        }
        result["execution_time"] = time.perf_counter() - start_total
        return result
    except Exception as exc:  # pragma: no cover - defensive
        return {
            "success": False,
            "message": f"Error in timing attack simulation: {exc}",
            "statistics": {
                "trials": trials,
                "average_time": 0,
                "min_time": 0,
                "max_time": 0,
                "time_variance": 0,
            },
            "results": [],
            "execution_time": time.perf_counter() - start_total,
            "inference": {
                "target_bit_index": 4,
                "actual_bit_value": None,
                "inferred_bit_value": None,
                "inference_correct": False,
            },
        }
