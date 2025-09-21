# create_testfile.py
import os
path = "testfile.bin"
size_mb = 50
with open(path, "wb") as f:
    for _ in range(size_mb):
        f.write(os.urandom(1024*1024))
print("Created", path, "size:", os.path.getsize(path))
