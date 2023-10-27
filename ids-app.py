from scapy.all import *

def analyze_packet(packet):
    # Xem xét nội dung gói tin và kiểm tra biểu hiện không bình thường
    if Raw in packet:
        data = packet[Raw].load
        if b"malicious_code" in data:
            print("Possible RCE attack detected in packet.")

def packet_callback(packet):
    # Gọi hàm phân tích gói tin cho mỗi gói tin nhận được
    analyze_packet(packet)

if __name__ == "__main__":
    # Sử dụng scapy để lắng nghe lưu lượng mạng
    sniff(prn=packet_callback)

