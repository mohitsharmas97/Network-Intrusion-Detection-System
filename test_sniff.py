from scapy.all import sniff, conf

print("Attempting to sniff...")
try:
    # Try default first
    print("1. Trying default sniff(count=1, timeout=2)...")
    sniff(count=1, timeout=2)
    print("   Success!")
except Exception as e:
    print(f"   Failed: {e}")

try:
    # Try L3socket
    print("\n2. Trying sniff(..., L2socket=conf.L3socket)...")
    sniff(count=1, timeout=2, L2socket=conf.L3socket)
    print("   Success with L3socket!")
except Exception as e:
    print(f"   Failed with L3socket: {e}")
