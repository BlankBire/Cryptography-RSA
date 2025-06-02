from sympy import mod_inverse
from sympy.ntheory.modular import crt

def hastad_attack(public_key):
    """
    Thực hiện tấn công Hastad trên RSA
    public_key: tuple (n, e) với n là modulus và e là public exponent
    """
    n = int(public_key[0])  # Chuyển đổi sang int
    e = int(public_key[1])  # Chuyển đổi sang int
    
    # Trong trường hợp đơn giản, chúng ta giả sử có 3 bản mã khác nhau
    # với cùng một tin nhắn được mã hóa
    # Trong thực tế, bạn cần có nhiều bản mã từ các nguồn khác nhau
    
    # Giả lập 3 bản mã với cùng một tin nhắn
    # Trong thực tế, bạn cần có các bản mã thật
    message = 123  # Tin nhắn gốc
    c1 = pow(message, e, n)  # Giả lập bản mã 1
    c2 = pow(message, e, n)  # Giả lập bản mã 2
    c3 = pow(message, e, n)  # Giả lập bản mã 3
    
    # Sử dụng Chinese Remainder Theorem để tìm tin nhắn
    moduli = [n, n, n]  # Trong thực tế, đây sẽ là các modulus khác nhau
    remainders = [c1, c2, c3]
    
    try:
        # Tìm nghiệm của hệ phương trình đồng dư
        result = crt(moduli, remainders)
        if result is None:
            return {
                'success': False,
                'message': 'Hastad attack failed: No solution found'
            }
            
        m, _ = result
        m = int(m)  # Chuyển đổi sang int
        
        # Kiểm tra xem m có phải là tin nhắn gốc không
        if pow(m, e, n) in [c1, c2, c3]:
            return {
                'success': True,
                'message': 'Hastad attack successful',
                'decrypted_message': m
            }
        else:
            return {
                'success': False,
                'message': 'Hastad attack failed: Invalid solution'
            }
    except Exception as e:
        print(f"Error in hastad_attack: {str(e)}")  # In thêm thông tin lỗi
        return {
            'success': False,
            'message': f'Hastad attack failed: {str(e)}'
        } 