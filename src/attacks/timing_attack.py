import time
import random
from typing import Dict, List
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto import Random
from math import sqrt
import statistics

def simulate_decryption_time(private_key, ciphertext):
    """
    Mô phỏng thời gian giải mã phụ thuộc vào khóa.
    Giải mã và đo thời gian thực hiện.
    Sẽ giới thiệu một độ trễ mô phỏng dựa trên một bit của khóa riêng tư.
    """
    cipher = PKCS1_v1_5.new(private_key)
    start = time.perf_counter()
    sentinel = Random.new().read(15)
    
    # Mô phỏng biến thể thời gian dựa trên một bit của khóa riêng tư (ví dụ: bit thứ 5 của 'd')
    # Đây là để làm cho sự khác biệt thời gian có thể nhìn thấy cho mục đích trình diễn.
    if hasattr(private_key, 'd') and private_key.d is not None:
        # Xác định độ lớn của vòng lặp bận rộn dựa trên bit của 'd'
        delay_iterations = 0
        if (private_key.d >> 4) & 1: # Kiểm tra bit thứ 5 (0-indexed) của d
            delay_iterations = 1000 # Tăng số lần lặp cho độ trễ 1 giây (1000ms)
        else:
            delay_iterations = 500 # Tăng số lần lặp cho độ trễ 0.5 giây (500ms)

        # Vòng lặp bận rộn để tạo độ trễ nhân tạo
        for _ in range(delay_iterations):
            x = 1 + 1 # Thực hiện một phép tính có thật để CPU thực sự bận

    cipher.decrypt(ciphertext, sentinel)
    end = time.perf_counter()
    return end - start

def timing_attack(private_key, public_key, trials=100) -> Dict:
    """
    Mô phỏng attack bằng cách phân tích thời gian giải mã.
    Có thể tiết lộ thông tin về khóa bí mật.
    
    Args:
        private_key: Khóa bí mật RSA
        public_key: Khóa công khai RSA
        trials: Số lần thử
        
    Returns:
        Dict chứa kết quả phân tích
    """
    start_time = time.perf_counter()
    results = []
    cipher = PKCS1_v1_5.new(public_key)

    for i in range(trials):
        plaintext = random.getrandbits(64).to_bytes(8, 'big')
        ciphertext = cipher.encrypt(plaintext)
        duration = simulate_decryption_time(private_key, ciphertext)
        results.append({
            'trial': i + 1,
            'duration': duration,
            'plaintext': plaintext.hex()
        })

    avg_time = sum(r['duration'] for r in results) / len(results)
    min_time = min(r['duration'] for r in results)
    max_time = max(r['duration'] for r in results)
    
    return {
        'success': True,
        'results': results,
        'statistics': {
            'trials': trials,
            'average_time': avg_time,
            'min_time': min_time,
            'max_time': max_time,
            'time_variance': max_time - min_time
        },
        'execution_time': time.perf_counter() - start_time
    }

def simulate_timing_attack(n: int, e: int, trials: int = 10) -> Dict:
    """
    Giao diện mô phỏng timing attack.
    
    Args:
        n: Modulus của khóa RSA (dùng để gợi ý kích thước khóa)
        e: Public exponent (dùng cho khóa được tạo)
        trials: Số lần thử
        
    Returns:
        Dict chứa kết quả phân tích
    """
    start_total = time.perf_counter()
    try:
        # Tạo một cặp khóa RSA hoàn chỉnh cho mô phỏng.
        # Điều này đảm bảo khóa riêng tư có 'd' cần thiết cho giải mã.
        # 'n' và 'e' từ người dùng được sử dụng để xác định kích thước khóa được tạo và public exponent.
        key_size = n.bit_length() # Sử dụng kích thước bit của n từ người dùng để xác định key_size
        if key_size < 512: # Đảm bảo kích thước khóa tối thiểu cho RSA
            key_size = 512
        elif key_size > 4096: # Giới hạn kích thước khóa tối đa để tránh quá lâu trong mô phỏng
            key_size = 4096
            
        generated_key = RSA.generate(key_size, e=e)
        private_key_for_sim = generated_key
        public_key_for_sim = generated_key.publickey()

        # Lấy bit thứ 5 thực tế của d (0-indexed)
        actual_d_bit_5 = (private_key_for_sim.d >> 4) & 1

        result = timing_attack(private_key_for_sim, public_key_for_sim, trials)
        
        # --- Logic suy luận bit d --- #
        inferred_d_bit_5 = None
        inference_correct = False
        durations = [r['duration'] for r in result['results']]
        
        # Ngưỡng giữa hai mức độ trễ của chúng ta (0.5s và 0.25s)
        # base_decryption_time là rất nhỏ, nên có thể bỏ qua trong ngưỡng.
        # Midpoint = (0.5 + 0.25) / 2 = 0.375
        median_time = statistics.median(durations)
        group1 = [t for t in durations if t < median_time]
        group2 = [t for t in durations if t >= median_time]
        avg1 = sum(group1) / len(group1)
        avg2 = sum(group2) / len(group2)
        inference_threshold = (avg1 + avg2) / 2 # Đây là một ngưỡng đơn giản cho demo
        
        if result['statistics']['average_time'] >= inference_threshold:
            inferred_d_bit_5 = 1
        else:
            inferred_d_bit_5 = 0
            
        if inferred_d_bit_5 == actual_d_bit_5:
            inference_correct = True

        # Thêm thông tin suy luận vào kết quả
        result['inference'] = {
            'target_bit_index': 4, # Bit thứ 5 (0-indexed)
            'actual_bit_value': actual_d_bit_5,
            'inferred_bit_value': inferred_d_bit_5,
            'inference_correct': inference_correct
        }

        result['success'] = True
        result['execution_time'] = time.perf_counter() - start_total
        return result
        
    except Exception as e:
        return {
            'success': False,
            'message': f'Error in timing attack simulation: {str(e)}',
            'statistics': {
                'trials': trials,
                'average_time': 0,
                'min_time': 0,
                'max_time': 0,
                'time_variance': 0
            },
            'results': [],
            'execution_time': time.perf_counter() - start_total,
            'inference': {
                'target_bit_index': 4,
                'actual_bit_value': None,
                'inferred_bit_value': None,
                'inference_correct': False
            }
        }
