<img width="1159" height="312" alt="image" src="https://github.com/user-attachments/assets/645e84e9-a9e8-4dc6-b0a8-94ef1534e939" /># 1. **Challenge Decription**

<img width="907" height="502" alt="image" src="https://github.com/user-attachments/assets/933db009-ea6a-44b6-b4fe-832bc0aea31a" />
Decription: Can you find the flag in this disk image?
File: disk.img: DOS/MBR boot sector; partition 1 : ID=0x83, active, start-CHS (0x2,0,33), end-CHS (0x263,8,56), startsector 2048, 614400 sectors; partition 2 : ID=0x82, start-CHS (0x263,8,57), end-CHS (0x3ff,15,63), startsector 616448, 524288 sectors; partition 3 : ID=0x83, start-CHS (0x3ff,15,63), end-CHS (0x3ff,15,63), startsector 1140736, 956416 sectors

# 2. **File Analysis**
In general, ```disk.img``` is a raw disk image, can be seem like a virtual hard drive separated by 3 partitions which have their own functions
+ Linux ( ID = 0x83 ) - Start sector 2048: Root segment (```/```), an Active partition, stored kernel and config files
+ Linux swap ( ID = 0x82 ): Virtual memory, when computer's RAM is full, kernel will push unused data to this part to free up memory
+ Linux - Start sector 1140736: Data segment(```/home``` and ```/var```), stored around 467 MB ( sector num / 2048 ). It was splited to avoid serious errors

So first, we need to check what exactly offset of each segment by ```mmls``` - can be installed with ```sudo apt update && sudo apt install sleuthkit -y```
<img width="1159" height="312" alt="image" src="https://github.com/user-attachments/assets/60db466d-79cd-4b0a-bbca-b08af9ffea82" />

From this we can see that, part 1 and 3 we need to check from 2046 and 1140736

# 3. **Filesystem Investigation**
We know the exactly offset of part 1 and part 3, to list file from these two parts, a tool ```fls``` (File list) will be used

