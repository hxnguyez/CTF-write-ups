# 1. **Challenge Decription**
<img width="904" height="534" alt="image" src="https://github.com/user-attachments/assets/06665f8c-606e-47cf-aa90-48b8c92d1506" />

   The objective is to recover a hidden flag from a provided disk image 
   (disk.img.gz). The challenge involves disk forensics, partition analysis, 
   and deep inspection of Git internal objects within a recovered filesystem

# 2. Enumeration and Partition Analysis
   First, we extract the image and analyze the partition layout to find 
   where the user data resides.

   Command:
   ```gunzip disk.img.gz```
   ```file disk.img```


# 3. **Filesystem Investigation**
   We use ```fls``` from The Sleuth Kit (TSK) to list files in the third partition 
   and look for Git-related metadata or repositories

   Command:
   ```fls -r -o 1140736 disk.img | grep -i ".git"```

   Observation:
   A directory named ".git" was found at Inode 65665, located deep within 
   the user directory: ```/home/ctf-player/Code/killer-chat-app/.git```

# 4. Data Recovery
   We recover the files from the identified partition to a local directory 
   for detailed inspection

   Command:
   ```mkdir recovered_data```
   ```tsk_recover -i raw -o 1140736 -e disk.img recovered_data```

# 5. Git Repository Forensics
   Navigating to the recovered repository, we found that standard Git commands 
   (git log, git status) failed with ```fatal: not a git repository```
   This suggests that the Git metadata (like HEAD or config) was corrupted or 
   incomplete during the recovery process

   However, the ```.git/objects``` directory contained 21 files. Since Git stores 
   content as zlib-compressed objects, we cannot use ```grep``` directly on them

# 6. Object Carving And Decompression
   To bypass the corrupted repository structure, we manually decompress the 
   Git objects using a Python script to scan for the flag format "pico"

   Script:
   ```python
python3 -c "
import zlib
import os

path = '.git/objects'
for root, dirs, files in os.walk(path):
    for file in files:
        if len(file) < 2: continue
        full_path = os.path.join(root, file)
        try:
            with open(full_path, 'rb') as f:
                # Git object có header, zlib decompress sẽ đọc được toàn bộ
                data = zlib.decompress(f.read())
                if b'pico' in data:
                    print(f'\n--- FOUND IN: {full_path} ---')
                    print(data.decode('utf-8', errors='ignore'))
        except Exception:
            continue
"
```
   

# 7. Flag Recovery
   The script successfully decompressed a 'blob' object containing the chat logs of the "killer-chat-app"

   Extracted Content:
   Rex: Meet at the old arcade basement for the secret hideout
   Jay: Ask Rusty at the door and use password picoCTF{g17_r35cu3_16ac6bf3}.
   Rex: Bring the decoder map so we can plan the route

# 8. Conclusion
   The flag was found hidden within a compressed Git blob object in a 
   partially recovered filesystem
   
![image](https://hackmd.io/_uploads/BknbArCtZx.png)

   FLAG: picoCTF{g17_r35cu3_16ac6bf3}
--------------------------------------------------------------------------------
