# 1. **Challenge Decription**

<img width="904" height="534" alt="image" src="https://github.com/user-attachments/assets/06665f8c-606e-47cf-aa90-48b8c92d1506" />
Decription: The agents interrupted the perpetrator's disk deletion routine. Can you recover this git repo?

# 2. **Enumeration and Partition Analysis**
   First, we extract the image and analyze the partition layout to find 
   where the user data resides

   ```gunzip disk.img.gz```
   ```file disk.img```
   
<img width="1451" height="254" alt="image" src="https://github.com/user-attachments/assets/a07d0043-cd96-4774-86ae-a4c1d80a52e7" />

# 3. **Filesystem Investigation**
   ```mmls``` to check offset of 3 partition in this file
   
   <img width="1159" height="277" alt="image" src="https://github.com/user-attachments/assets/82678597-cb4d-4cf1-883e-a72e847dd9a8" />
  
   We use ```fls``` to list files in the third partition and look for Git-related metadata or repositories
   ```fls -r -o 1140736 disk.img | grep -i ".git"```
   
   <img width="1210" height="672" alt="image" src="https://github.com/user-attachments/assets/4bb28555-11c2-43ba-ab9d-44d666c6b1b7" />

   A directory named ".git" was found at Inode 65665
# 4. Data Recovery
   We will recover the files from the identified partition to a local directory 
   for detailed inspection
   Now, ```tsk_recover``` is a powerful automation tool in the Sleuth Kit. It allows for the recursive extraction of all files from a disk image partition to a local directory
   ```-i raw```: Specifies the input image type.
   ```-o 1140736```: Jumps to the specific partition offset.
   ```-e```: Recover all files (both allocated and unallocated)
   ```mkdir recovered_data```
   ```tsk_recover -i raw -o 1140736 -e disk.img recovered_data```

# 5. Git Repository Forensics
   Navigating to the recovered repository, we found that standard Git commands 
   (git log, git status) failed with ```fatal: not a git repository```
   
   <img width="945" height="142" alt="image" src="https://github.com/user-attachments/assets/74c823fe-290d-46df-899f-113a08ef9b48" />

   This suggests that the Git metadata (like HEAD or config) was corrupted or 
   incomplete during the recovery process

   After recovery, I navigated to /home/ctf-player/Code/killer-chat-app/. I noticed the .git directory existed, but the internal pointers were broken. In a real-world forensic scenario, metadata corruption is common. Instead of trying to fix the Git environment, I decided to go "Lower Level" by targeting the raw Git objects directly
   However, the ```.git/objects``` directory contained 21 files. Since Git stores 
   content as zlib-compressed objects, we cannot use ```grep``` directly on them

 <img width="1436" height="140" alt="image" src="https://github.com/user-attachments/assets/a81e24d5-fdbb-4b10-9733-370e626db0c9" />

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
   
<img width="710" height="387" alt="image" src="https://github.com/user-attachments/assets/309841c5-eb07-473f-9070-84b5f0ceed4c" />

   FLAG: picoCTF{g17_r35cu3_16ac6bf3}
--------------------------------------------------------------------------------
