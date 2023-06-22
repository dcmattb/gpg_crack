# gpg_crack
Python script which attempts to use a password list to crack encrypted PGP Private Keys

IMPORTANT
1) You must have gpg suite installed (see https://gpgtools.org/)
2) You must enable loopback PIN ENTRY in the gpg configuration:
    ```
    echo "allow-loopback-pinentry" >> ~/.gnupg/gpg-agent.conf
    ```

This script attempts to crack PGP Private Keys which are password-protected using a password list
This avoids repeated typing in the GPG GUI program and the 3-attempt limit
GPG recommends passwords are at least 8 characters with 1 digit or special character

Example command:
```
python gpg_crack.py MyPrivateKey.priv ~/wordlist.txt
```

Internally, this runs multiple attempts (with different passwords) of:
```
gpg --export-secret-key --armor --pinentry-mode loopback --passphrase 'PasswordCandidate' MyPrivateKey.priv
```

~dcmattb
