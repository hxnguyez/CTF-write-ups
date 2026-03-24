# 1. **Challenge Decription**

<img width="906" height="508" alt="image" src="https://github.com/user-attachments/assets/9054a558-7838-49df-b14d-3494835dc4d6" />
Decription: Can you find the flag in this disk image?
File: disk.img: DOS/MBR boot sector; partition 1 : ID=0x83, active, start-CHS (0x2,0,33), end-CHS (0x263,8,56), startsector 2048, 614400 sectors; partition 2 : ID=0x82, start-CHS (0x263,8,57), end-CHS (0x3ff,15,63), startsector 616448, 524288 sectors; partition 3 : ID=0x83, start-CHS (0x3ff,15,63), end-CHS (0x3ff,15,63), startsector 1140736, 956416 sectors

# 2. **File Analysis**
If you do not understand about img file, checking Forensics Git 0
We will use mmls for finding offset of Linux 1 and 3 partition
<img width="1142" height="286" alt="image" src="https://github.com/user-attachments/assets/1f52bf9e-3f29-4ac9-adb2-8598607d32cb" />

Offset 1 from 616447
Offset 3 from 2097151

# 3. **Filesystem investigation**
We know the exactly offset of part 1 and part 3, to list all file from these two parts, a tool ```fls``` (File list) will be used with ```-r``` (recursive, including deep files) and ```-o``` (offset)
<img width="748" height="399" alt="image" src="https://github.com/user-attachments/assets/b40bbb38-cc4d-4468-ae73-2d80755be483" />

I do not see any suspicious artifacts in part 1, then we can check partition 3
<img width="1475" height="669" alt="image" src="https://github.com/user-attachments/assets/2c9bd0c1-2b48-484c-a9f8-c04dc95a4df3" />

With a large amount of files, we will check content of them by ```icat -o offset filename node```
After read through some files, we can see that
<img width="1458" height="254" alt="image" src="https://github.com/user-attachments/assets/132076cb-fb28-4042-a327-731c2dabfc33" />
The commit show flag was created and removed in commit 1 and 2, by this log, we know SHA-1 code of commit 1 is ```177789af0b300e043ea8f54ea57d6cee352291ae```, corresponding to node 65700
<img width="974" height="630" alt="image" src="https://github.com/user-attachments/assets/426f1f5a-30ce-4e3d-8a75-308dc54eb832" />
# 4. **FLag Recovering**
Tool: ```pigz``` (Decompress), with ```-d``` to decompress data inputted from file
<img width="1467" height="319" alt="image" src="https://github.com/user-attachments/assets/a6d7043c-94c1-4420-8386-237be90077f0" />
```commit 179tree a62340e078686778969b9a555fc722147cf14e5a ...``` points to a Tree object with the hash starting with a623.... This Tree acts like a snapshot of the directory at that time

Next, we decompressed the Tree object to see which files it contained then get ```tree 36100644 flag.txt .....```
The tree confirmed the existence of flag.txt. Although the hash was displayed in binary characters, we matched the object path from my previous fls scan. The hash corresponded to the file located at objects/50/f47a5d... (Inode ```65695```)

So repeat previous action (65695) to get the flag
