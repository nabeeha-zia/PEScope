import hashlib

# its basically a fingerprint for the file 
def calculate_sha256(file_path):
    print("\n[+] FILE HASH")
    
    try:
        # Open file and read it in chunks
        sha256 = hashlib.sha256()
        
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        
        hash_value = sha256.hexdigest()
        print(f"    SHA256: {hash_value}")
        return hash_value

    except Exception as e:
        print(f"    [ERROR] Could not hash file: {e}")
        return None