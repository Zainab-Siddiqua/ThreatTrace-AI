import email
import glob
import os

def analyze_sample_relay_chains():
    """Reads all sample .eml files and prints extracted IP relay hops."""
    samples_path = os.path.join(os.path.dirname(__file__), "samples", "*.eml")
    files = glob.glob(samples_path)
    
    print(f"🔍 Analyzing {len(files)} sample email files for network hops:\n")
    
    for filepath in files:
        file_name = os.path.basename(filepath)
        with open(filepath, "rb") as f:
            msg = email.message_from_binary_file(f)
        
        received_hops = msg.get_all("Received") or []
        print(f"📄 File: {file_name}")
        print(f"   From: {msg.get('From')}")
        print(f"   Subject: {msg.get('Subject')}")
        print(f"   Network Hops Count: {len(received_hops)}")
        for idx, hop in enumerate(received_hops, start=1):
            # Clean up newlines in header strings
            clean_hop = " ".join(hop.split())
            print(f"     [Hop {idx}]: {clean_hop[:80]}...")
        print("-" * 65)

if __name__ == "__main__":
    analyze_sample_relay_chains()