# Digital Forensics Archive

This directory contains my detailed writeups and methodologies for Forensics challenges

---

## Toolset

To solve these challenges, I utilize standard forensic tools and custom scripts:

* **The Sleuth Kit (TSK):** Command-line tools for low-level file system analysis, partition layout, and data recovery
    * `mmls`: Display the partition layout
    * `fls`: List file and directory names in a disk image
    * `icat`: Output the contents of a file based on its Inode
    * `mactime`: Create an ASCII timeline of file activity
    ```bash
    sudo apt update && sudo apt install sleuthkit autopsy -y
    ```

* **Binary & Data Forensics:**
    * **Python 3:** For custom carving scripts, binary-to-hex conversion, and automated object decompression
    * **Strings & Grep:** For rapid keyword searching within raw disk images
    ```bash
    sudo apt install python3 -y
    ```

* **Decompression & Extraction:**
    * **Pigz/Gunzip:** For high-speed decompression of archive artifacts
    * **Binwalk:** For searching and extracting hidden files within firmware or images
    * **ExifTool:** For analyzing metadata and hidden comments
    ```bash
    sudo apt install binwalk libimage-exiftool-perl pigz -y
    ```

* **Advanced Frameworks:**
    * **Volatility 3:** Advanced memory forensics framework
    * **Wireshark:** In-depth network traffic (pcap) analysis

---

## Featured Investigations

| Challenge Name | Key Technique | Status |
| :--- | :--- | :--- |
| **Forensics Git 0** | TSK / Inode Recovery | ✅ Solved |
| **Forensics Git 1** | TSK / Zlib Decompression | ✅ Solved |
| **Forensics Git 2** | Automated Forensic Scripting / Zlib Scavenging / Corrupted Git Recovery | ✅ Solved |
| **Timeline 0** | TSK mactime / Timestomping Detection | ✅ Solved |
| **Binary Digits** | Binary to Hex Conversion (Python Scripting) | ✅ Solved |
| **DISKO 4** | FAT32 Analysis / Deleted File Recovery (icat) | ✅ Solved |


---

## Disclaimer
*Writeups are published only after the respective competitions have ended. Original flags are redacted to maintain the educational integrity of the challenges.*
