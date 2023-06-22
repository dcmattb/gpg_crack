#!/bin/env python3
'''
IMPORTANT
1) You must have gpg suite installed (see https://gpgtools.org/)
2) You must enable loopback PIN ENTRY in the gpg configuration:
    echo "allow-loopback-pinentry" >> ~/.gnupg/gpg-agent.conf

This script attempts to crack PGP Private Keys which are password-protected using a password list
This avoids repeated typing in the GPG GUI program and the 3-attempt limit
GPG recommends passwords are at least 8 characters with 1 digit or special character

Example command:
    python gpg_crack.py MyPrivateKey.priv ~/wordlist.txt

Internally, this runs multiple attempts (with different passwords) of:
    gpg --export-secret-key --armor --pinentry-mode loopback --passphrase 'PasswordCandidate' MyPrivateKey.priv

~dcmattb
'''

import subprocess, sys

if (len(sys.argv)<3):
    print("Usage:")
    print(f"\tpython {sys.argv[0]} gpg_key_identifier passwordlist")
    print(f"\teg: python {sys.argv[0]} MyPrivateKey.priv ~/wordlist.txt")
    exit()

privkey = sys.argv[1]
wordlist = sys.argv[2]

#First, check if the key is not protected:
res = subprocess.run(['gpg', '--export-secret-key', '--armor', '--pinentry-mode', 'loopback', '--passphrase', "", privkey], capture_output=True)
if res.stdout[:5] == (b"-----"):    #Looks like PGP armour
    print(res.stdout.decode("UTF-8"))
    exit("No password!")

#Get all the words:
#Note - for LARGE wordlists, please re-factor this to avoid using up all your RAM!
with open(wordlist, 'r') as f:
    words = f.readlines()

#Apply any number of transforms to the passwords (make your own!)
transforms = [
    lambda x:x, #Identity
    lambda x:x.title(), #Titlecase
    lambda x:x.lower(), #lowercase
    lambda x:x+"1",     #Suffix1
    lambda x:x+"123",   #Suffix123
    lambda x:x+"!",     #Suffix!
    #Add more transforms here if required...
    ]
for i,transform in enumerate(transforms):
    print(f"{(i+1)}/{len(transforms)}") #Count the transforms - rudimentary progress indicator
    for word in words:
        res = subprocess.run(['gpg', '--export-secret-key', '--armor', '--pinentry-mode', 'loopback', '--passphrase', transform(word.strip()), privkey], capture_output=True)
        if res.stdout[:5] == (b"-----"):    #Looks like PGP armour, password found!
            print(res.stdout.decode("UTF-8"))
            print(f"The password was {transform(word.strip())}")
            exit()
print("Password not found") #We have exhausted the list
