# pam-gnupg

Unlock GnuPG key on login

## What is it?

A PAM module that launches `gpg-agent` if needed and hands over your login
password to `gpg-preset-passphrase`. This can be e.g. useful if you are using a
GnuPG-based password manager.

Requires GnuPG 2.1

## Disclaimer

The code was written mainly by looking at and occasionally copying from Gnome
Keyring's PAM module and is based on a somehwat mediocre understanding of the
details of both PAM and C. Since it's a security related module, you should be
aware that there may be potentially dangerous bugs lurking.

## Usage

(tbd.)
