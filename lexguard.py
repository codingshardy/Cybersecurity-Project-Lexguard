"""
LexGuard — Unified Cyber Defense & Legal Forensics Platform.
Interactive Command Line Interface (CLI) Engine.
Aligned with Course CM51205 (Government Polytechnic, Pune).
"""
import hashlib
import json
import os
import re
import secrets
import math
from datetime import datetime

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization, padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.backends import default_backend

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KEY_FILE = os.path.join(BASE_DIR, "lexguard.key")

CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"

# --- Substitution & Transposition Algorithms ---
def caesar(text, shift, mode="encrypt"):
    if mode == "decrypt": shift = -shift
    res = []
    for c in text:
        if c.isupper(): res.append(chr((ord(c) - 65 + shift) % 26 + 65))
        elif c.islower(): res.append(chr((ord(c) - 97 + shift) % 26 + 97))
        else: res.append(c)
    return "".join(res)

def monoalphabetic(text, key_alphabet, mode="encrypt"):
    std = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    key = key_alphabet.upper()
    if len(key) != 26 or len(set(key)) != 26:
        return "[!] Key must be 26 unique characters."
    if mode == "encrypt":
        trans = str.maketrans(std + std.lower(), key + key.lower())
    else:
        trans = str.maketrans(key + key.lower(), std + std.lower())
    return text.translate(trans)

def vigenere(text, key, mode="encrypt"):
    key = re.sub(r"[^A-Za-z]", "", key).upper()
    if not key: return text
    res, idx = [], 0
    for c in text:
        if c.isalpha():
            shift = ord(key[idx % len(key)]) - 65
            if mode == "decrypt": shift = -shift
            if c.isupper(): res.append(chr((ord(c) - 65 + shift) % 26 + 65))
            else: res.append(chr((ord(c) - 97 + shift) % 26 + 97))
            idx += 1
        else: res.append(c)
    return "".join(res)

def rail_fence(text, rails, mode="encrypt"):
    if rails <= 1: return text
    if mode == "encrypt":
        fence = [[] for _ in range(rails)]
        rail, dirn = 0, 1
        for ch in text:
            fence[rail].append(ch)
            rail += dirn
            if rail == rails - 1: dirn = -1
            elif rail == 0: dirn = 1
        return "".join("".join(r) for r in fence)
    else:
        pattern = [[None] * len(text) for _ in range(rails)]
        rail, dirn = 0, 1
        for i in range(len(text)):
            pattern[rail][i] = "*"
            rail += dirn
            if rail == rails - 1: dirn = -1
            elif rail == 0: dirn = 1
        idx = 0
        for r in range(rails):
            for c in range(len(text)):
                if pattern[r][c] == "*" and idx < len(text):
                    pattern[r][c] = text[idx]
                    idx += 1
        res, rail, dirn = [], 0, 1
        for i in range(len(text)):
            res.append(pattern[rail][i])
            rail += dirn
            if rail == rails - 1: dirn = -1
            elif rail == 0: dirn = 1
        return "".join(res)

def vernam(text, key):
    if len(key) < len(text):
        return "[!] Key length must match or exceed plaintext length."
    res = [chr(ord(t) ^ ord(k)) for t, k in zip(text, key)]
    raw = "".join(res)
    return f"XOR Hex: {raw.encode('utf-8', errors='surrogateescape').hex()}"

# --- Interactive Menus ---
def menu_ciphers():
    print(f"\n{BOLD}{CYAN}=== CRYPTOGRAPHY & CIPHERS LAB ==={RESET}")
    print("1. Caesar Cipher (Substitution)")
    print("2. Monoalphabetic Cipher (Substitution)")
    print("3. Vigenère Cipher (Polyalphabetic)")
    print("4. Rail Fence Cipher (Transposition)")
    print("5. Vernam Cipher (One-Time Pad)")
    print("6. RSA Algorithm & Digital Signature")
    print("7. Diffie-Hellman Key Exchange")
    print("8. Hashing (MD-5 vs SHA-256)")
    ch = input(f"{BOLD}Select Option: {RESET}").strip()

    if ch == "1":
        txt = input("Enter text: ")
        s = int(input("Shift (1-25): ") or 3)
        print(f"{GREEN}Encrypted:{RESET} {caesar(txt, s, 'encrypt')}")
        print(f"{GREEN}Decrypted:{RESET} {caesar(caesar(txt, s, 'encrypt'), s, 'decrypt')}")
    elif ch == "2":
        txt = input("Enter text: ")
        key = input("26-Letter Key (default: QWERTYUIOPASDFGHJKLZXCVBNM): ") or "QWERTYUIOPASDFGHJKLZXCVBNM"
        enc = monoalphabetic(txt, key, "encrypt")
        print(f"{GREEN}Encrypted:{RESET} {enc}")
        print(f"{GREEN}Decrypted:{RESET} {monoalphabetic(enc, key, 'decrypt')}")
    elif ch == "3":
        txt = input("Enter text: ")
        key = input("Keyword: ") or "SECURITY"
        enc = vigenere(txt, key, "encrypt")
        print(f"{GREEN}Encrypted:{RESET} {enc}")
        print(f"{GREEN}Decrypted:{RESET} {vigenere(enc, key, 'decrypt')}")
    elif ch == "4":
        txt = input("Enter text: ")
        r = int(input("Number of rails: ") or 3)
        enc = rail_fence(txt, r, "encrypt")
        print(f"{GREEN}Encrypted:{RESET} {enc}")
        print(f"{GREEN}Decrypted:{RESET} {rail_fence(enc, r, 'decrypt')}")
    elif ch == "5":
        txt = input("Plaintext: ")
        k = input("One-Time Pad Key: ")
        print(f"{GREEN}Vernam Result:{RESET} {vernam(txt, k)}")
    elif ch == "6":
        print(f"{YELLOW}Generating 2048-bit RSA Keypair...{RESET}")
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        pub = priv.public_key()
        msg = input("Enter message to sign: ").encode()
        sig = priv.sign(msg, asym_padding.PSS(mgf=asym_padding.MGF1(hashes.SHA256()), salt_length=asym_padding.PSS.MAX_LENGTH), hashes.SHA256())
        print(f"{GREEN}[✓] Digital Signature Generated (RSA-PSS with SHA-256).{RESET}")
    elif ch == "7":
        p, g = 23, 5
        a, b = 6, 15
        A, B = pow(g, a, p), pow(g, b, p)
        K1, K2 = pow(B, a, p), pow(A, b, p)
        print(f"{GREEN}Diffie-Hellman Shared Secret:{RESET} K = {K1} (Match: {K1 == K2})")
    elif ch == "8":
        txt = input("Enter string to hash: ").encode()
        print(f"MD-5:    {hashlib.md5(txt).hexdigest()} {RED}(Collision vulnerable){RESET}")
        print(f"SHA-256: {hashlib.sha256(txt).hexdigest()} {GREEN}(Standard secure hash){RESET}")

def main():
    while True:
        print(f"\n{BOLD}{CYAN}======================================================={RESET}")
        print(f"{BOLD}{CYAN}  LEXGUARD CYBER DEFENSE & LEGAL FORENSICS SUITE (CLI) {RESET}")
        print(f"{BOLD}{CYAN}  Course CM51205 Standard Compliant                    {RESET}")
        print(f"{BOLD}{CYAN}======================================================={RESET}")
        print("1. Cryptography & Ciphers Lab (Caesar, Vigenère, Rail Fence, RSA)")
        print("2. Foundations & Active vs Passive Attack Classifier")
        print("3. Authentication & Access Control (DAC/MAC/RBAC)")
        print("4. Indian IT Act 2000 Statutory Reference & FIR Generator")
        print("5. Exit")
        ch = input(f"\n{BOLD}Select Option (1-5): {RESET}").strip()
        if ch == "1": menu_ciphers()
        elif ch == "2":
            print(f"\n{BOLD}Active vs Passive Attacks:{RESET}")
            print("• Passive: Packet Sniffing, Traffic Analysis, Shoulder Surfing, Dumpster Diving")
            print("• Active: DoS/DDoS, Phishing, Spoofing, Man-in-the-Middle, Replay, Data Diddling")
        elif ch == "3":
            print(f"\n{BOLD}Access Control Models:{RESET}")
            print("• DAC: Discretionary Access Control (owner sets permissions)")
            print("• MAC: Mandatory Access Control (central authority clearance)")
            print("• RBAC: Role-Based Access Control (roles: Admin, Analyst, User)")
        elif ch == "4":
            print(f"\n{BOLD}Indian IT Act 2000 Key Provisions:{RESET}")
            print("• Section 43/66: Unauthorized Access & Computer Damage (up to 3 yrs)")
            print("• Section 66C: Identity Theft & Password Fraud (up to 3 yrs)")
            print("• Section 66D: Cheating by Personation using Computer (up to 3 yrs)")
            print("• Section 66F: Cyber Terrorism (Life Imprisonment)")
            print("• Section 67: Obscene Electronic Material Publication (3 to 5 yrs)")
        elif ch == "5":
            print(f"{GREEN}Exiting LexGuard.{RESET}")
            break

if __name__ == "__main__":
    main()
