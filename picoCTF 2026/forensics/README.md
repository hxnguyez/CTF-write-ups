# Digital Forensics Archive

This directory contains my detailed writeups and methodologies for Forensics challenges

---

## Toolset

To solve these challenges, I utilize industry-standard forensic tools:
* **The Sleuth Kit (TSK):** `mmls`, `fls`, `icat`, `istat` for low-level file system analysis
  ```bash
  sudo apt update && sudo apt install sleuthkit autopsy -y```
  
* **Autopsy:** GUI-based digital forensics platform
* **Volatility:** Advanced memory forensics framework
  ```bash
  git clone [https://github.com/volatilityfoundation/volatility3.git](https://github.com/volatilityfoundation/volatility3.git)
  ```
  ```bash
  cd volatility3 && pip3 install -r requirements.txt```
* **Wireshark:** In-depth network traffic (pcap) analysis
  ```bash
  sudo apt install wireshark -y```
* **Binwalk and ExifTool:** Firmware analysis and metadata extraction.
```bash
sudo apt install binwalk -y
sudo apt install libimage-exiftool-perl -y
```
* **Pigz:** Advance gunzip for better speed
```bash
sudo apt update && sudo apt install pigz -y
```

## Featured Investigations

| Challenge Name | Key Technique | Status |
| :--- | :--- | :--- |
| **Forensics Git 0** | TSK / Inode Recovery | ✅ Solved |
| **Forensics Git 1** | ⏳ In Progress | ✅ Solved |
| **Forensics Git 2** | TSK / Inode Recovery | ✅ Solved |
| *Timeline 0* | ⏳ In Progress | ⏳ In Progress |
| *Tịmeline 1* | ⏳ In Progress | ⏳ In Progress |
| *Binary Digits* | ⏳ In Progress | ⏳ In Progress |
| *DISKO 4* | ⏳ In Progress | ⏳ In Progress |
| *Rogue Tower* | ⏳ In Progress | ⏳ In Progress |

---

## Disclaimer
*Writeups are published only after the respective competitions have ended. Original flags are redacted to maintain the educational integrity of the challenges.*
