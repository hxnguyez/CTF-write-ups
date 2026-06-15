# 1. **Challenge Decription**

<img width="907" height="502" alt="image" src="https://github.com/user-attachments/assets/933db009-ea6a-44b6-b4fe-832bc0aea31a" />
Decription: Can you find the flag in this disk image?
File: disk.img: DOS/MBR boot sector; partition 1 : ID=0x83, active, start-CHS (0x2,0,33), end-CHS (0x263,8,56), startsector 2048, 614400 sectors; partition 2 : ID=0x82, start-CHS (0x263,8,57), end-CHS (0x3ff,15,63), startsector 616448, 524288 sectors; partition 3 : ID=0x83, start-CHS (0x3ff,15,63), end-CHS (0x3ff,15,63), startsector 1140736, 956416 sectors

# 2. **File Analysis**
In general, ```disk.img``` is a raw disk image, can be seem like a virtual hard drive separated by 3 partitions which have their own functions
+ Linux ( ID = 0x83 ) - Start sector 2048: Root segment (```/```), an Active partition, stored kernel and config files
+ Linux swap ( ID = 0x82 ): Virtual memory, when computer's RAM is full, kernel will push unused data to this part to free up memory
+ Linux - Start sector 1140736: Data segment(```/home``` and ```/var```), stored around 467 MB ( sector num / 2048 ). It was isolated to avoid serious errors

So first, we need to check what exactly offset of each segment by ```mmls``` - can be installed with ```sudo apt update && sudo apt install sleuthkit -y```
<img width="1159" height="312" alt="image" src="https://github.com/user-attachments/assets/60db466d-79cd-4b0a-bbca-b08af9ffea82" />

From this we can see that, part 1 and 3 we need to check from 2048 and 1140736

# 3. **Filesystem Investigation**
We know the exactly offset of part 1 and part 3, to list all file from these two parts, a tool ```fls``` (File list) will be used with ```-r``` (recursive, including deep files) and ```-o``` (offset) 

<img width="645" height="332" alt="image" src="https://github.com/user-attachments/assets/29237ac2-34dc-428a-8c0f-47b27e99f3a8" />

I do not see any suspicious artifacts in part 1, then we can check partition 3

<img width="532" height="441" alt="image" src="https://github.com/user-attachments/assets/ab238362-8bea-442c-86e6-1f550073943c" />

```r/r```: Normal file like image, text,..
```d/d```: Directory
```l/l```: Symbolic list( a link to another file)
```v/v```: Virtual file created by kernel, usually start by ```$``` sign

# 4. **Finding**
```
Performing keyword search using strings and grep: strings  disk.img | grep -i "picoCTF{"
flrsh@chillfish:~/workspace1$ strings disk.img | grep -i "picoCTF{}"
5425754000 The picoCTF flag format is 'picoCTF{}' where there is some leetspeak phrase in between the curly braces
```
After read pass through directory, we need to check content of suspicious files

<img width="762" height="532" alt="image" src="https://github.com/user-attachments/assets/c54509fd-5f3c-4470-962a-461ab3b3bfe5" />

To read, we use icat for cat content from a specific node: ```icat -o offset filename node```

# 5. **Flag Recovering**
<img width="1466" height="342" alt="image" src="https://github.com/user-attachments/assets/7d2ea3c3-f92c-469b-be2d-21bbcdeb3c21" />

Note: Even if the flag is not in the current text files, the presence of a .git directory suggests that previous versions might hold the secret. By analyzing Git objects (Inodes 65695, 65698, 65700), one could potentially recover the original flag from deleted commits using icat and zlib decompression
