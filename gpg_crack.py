#!/usr/bin/env python3
'''
2024-08-07 - Version 1.1 - added Golden Dictionary, moved cases to internal program loop, optimised
2023-06-22 - Version 1.0 - initial code to attack PGP keys with wordlist and lambda transforms

IMPORTANT
1) You must have gpg suite installed (see https://gpgtools.org/)
2) You must enable loopback PIN ENTRY in the gpg configuration:
    echo "allow-loopback-pinentry" >> ~/.gnupg/gpg-agent.conf

This script attempts to crack PGP Private Keys which are password-protected using a password list
This avoids repeated typing in the GPG GUI program and the 3-attempt limit
A few default suffixes are attempted, but please add your own case-specific transforms below
Note: GPG recommends passwords are at least 8 characters with 1 digit or special character,
      however this is not enforced by the program.

Example command:
    python gpg_crack.py MyPrivateKey.priv ~/wordlist.txt

Internally, this runs multiple attempts (with different passwords) of:
    gpg --export-secret-key --armor --pinentry-mode loopback --passphrase 'PasswordCandidate' MyPrivateKey.priv

~dcmattb
'''

import subprocess, os, sys, re, json
golden_dictionary = 'golden_dictionary.json'

def add_to_golden_dictionary(key, password):
    if os.path.exists(golden_dictionary):
        with open(golden_dictionary, 'r') as file:
            gd = json.load(file)
    else:
        gd = {}
    gd[key] = password
    with open(golden_dictionary, 'w') as file:
        json.dump(gd, file)

def check_golden_dictionary(key):
    try:
        with open(golden_dictionary, 'r') as file:
            gd = json.load(file)
        return gd[key]
    except:
        return False

def try_password(password, privkey):
    pass_args = ['gpg', '--export-secret-key', '--armor', '--pinentry-mode', 'loopback', '--passphrase']
    args = pass_args + [password, privkey]
    res = subprocess.run(args, capture_output=True)
    if res.stdout[:5] == (b"-----"): #Looks like PGP armour, password found!
        return True
    return False

def crack_password(privkey, pass_args, words):
    '''
        This function runs through the wordlist, trying all words for the given key
        There are a number of transforms below which are applied to each word
        until either the password is found or the wordlist and transform list
        are exhausted. If your wordlist already contains transformed words,
        comment out the other transforms (leave the identity)
        You can also add other expected transforms, eg known suffixes or
        edit the ones below. Be creative!
    '''
    gd_password = check_golden_dictionary(privkey)
    if gd_password:
        if try_password(gd_password, privkey):
            print(f"Password in Golden Dictionary: {gd_password}")
            return (gd_password,)
        else:
            print(f"Password in Golden Dictionary is wrong: {gd_password}")
    transforms = [
        lambda x:x,         #Identity
        lambda x:x+"1",     #Suffix '1'
        lambda x:x+"!",
        lambda x:x+"123",
        lambda x:x+"*",
        lambda x:"@"+x,     #Prefix '@'
        #Add more transforms here if required...
        ]
    #transforms = [lambda x:x]  #Override and just use the identity
    tried = []  #Maintain list of attempted passwords to avoid duplication
    for i,transform in enumerate(transforms):
        print(f"{(i+1)}/{len(transforms)}") #Count the transforms
        for word in words:
            p = transform(word)
            cases = [p, p.title(), p.lower(), p.upper()]   #Try different cases
            for password in cases:
                if password in tried:
                    continue
                if try_password(password, privkey):
                    print(f"Password found: {password}")
                    add_to_golden_dictionary(privkey, password)
                    return (password,)
                tried += [password]
    return ('',)

def get_password(k, pass_args, words):
    print(f"Cracking {k[0]} ({k[2]})...")
    if try_password('', k[0]):
        return ('[NO PASSWORD]',)   #Protected by a blank password
    return crack_password(k[0], pass_args, words)

def main():
    list_args = ['gpg', '--list-secret-keys', '--keyid-format', 'short']
    pass_args = ['gpg', '--export-secret-key', '--armor', '--pinentry-mode', 'loopback', '--passphrase']
    if (len(sys.argv)<2):
        print("Usage:")
        print(f"\tpython {sys.argv[0]} gpg_key_identifier passwordlist")
        print(f"\teg: python {sys.argv[0]} MyPrivateKey.priv ~/wordlist.txt\n")
        print("Try to crack all secret keys in keyring:")
        print(f"\tpython {sys.argv[0]} passwordlist")
        print(f"\teg: python {sys.argv[0]} ~/wordlist.txt")
        exit()

    if (len(sys.argv)==2):  #Wordlist only, try for all secret keys
        wordlist = sys.argv[1]
    else:
        list_args += [sys.argv[1]]  #Append the keyID to the arguments and try the selected key only
        wordlist = sys.argv[2]

    words = []
    with open(wordlist, 'r') as f:
        for line in f:
            words.append(line.rstrip())
    print(f"{len(words)} words loaded into memory") #Not suited for large wordlists...

    #Get info about the requested key(s):
    keyinfo = subprocess.run(list_args, stdout=subprocess.PIPE, text=True)
    pattern = re.compile(r'sec\s+.*?/(\S+)\s(\S+).*?uid\s+\[.*?\]\s+(.*?)\n', re.DOTALL)
    keydata = pattern.findall(keyinfo.stdout)
    print(f"{len(keydata)} secret key(s) loaded.")

    keys = [t + get_password(t, pass_args, words) for t in keydata]

    print(f" Key ID   Created    Name {'':<27} Password")
    for k in keys:
        name_col = (k[2][:30] + '..') if len(k[2]) > 30 else k[2]
        print(f"{k[0]} {k[1]} {name_col:<32} {k[3]}")

if __name__ == "__main__":
    main()
