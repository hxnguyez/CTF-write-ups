# 🚩Binary Exploitation Archive

This directory contains my detailed writeups and methodologies for pwnable challenges ⚔️

---

## 🛠️ Toolset

You need a Linux environment (recommended: Ubuntu 22.04 LTS or Kali Linux) with the following tools:
* 🐍 **Python 3, Pip and GDB**: Common language for writing exploit scripts and a tool for dynamic analysing
```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-dev git libssl-dev libffi-dev build-essential gdb
```
* ⚙️ **Pwntools**: Framework for Pwn challenges
```bash
python3 -m pip install --upgrade pip
python3 -m pip install pwntools
```
* 💎 **GEF (GDB Enhanced Features)**: A GDB plugin that provides a much better UI (instantly displaying Stack, Registers, and Code)
```bash
bash -c "$(curl -fsSL https://gef.blah.cat/sh)"
```
[GDB cheatsheet here](https://darkdust.net/files/GDB%20Cheat%20Sheet.pdf)

## 🔍 Featured Investigations

| Challenge Name | Key Technique | Status |
| :--- | :--- | :--- |
| **Quizploit** | quizz(easy) | ✅ Solved |
| **offset-cycle** | ret2win | ✅ Solved |
| **offset-cycleV2** | ret2win | ✅ Solved |
| **Echo Escape 1** | ret2win | ✅ Solved |
| **Echo Escape 2** | ret2win | ✅ Solved |



---

## ⚠️ Disclaimer
*Writeups are published only after the respective competitions have ended. Original flags are redacted to maintain the educational integrity of the challenges. 🛡️*
