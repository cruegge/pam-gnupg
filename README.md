# pam-gnupg

Unlock GnuPG keys on login

## What is it?

A PAM module that hands over your login password to `gpg-preset-passphrase`.
This can be e.g. useful if you are using a GnuPG-based password manager,
e.g. [pass](https://www.passwordstore.org/).

Requires GnuPG 2.1, and probably only works on Linux (PRs for other systems are
of course welcome).

## Disclaimer

The code was written mainly by looking at and occasionally copying from Gnome
Keyring's PAM module and pam_mount and is based on a somehwat mediocre
understanding of the details of both PAM and C. Since it's a security related
module, you should be aware that there may be potentially dangerous bugs
lurking.

## Installation

The ususal

    autogen.sh
    configure
    make
    make install

should work.

`configure` takes an option `--with-moduledir` to set the installation path of
the PAM module. It defaults to `/lib/security`, but your distribution might use
a different path.

## Usage

### PAM setup

The module implements PAM's `auth` and `session` functions. The `auth` part
stores the passphrase and tries to send it to `gpg-agent`. If that fails, e.g.
due to `gpg-agent` not runnign, the `session` part starts the agent and sends
the passphrase again.

How to include the module in PAM's config depends on your distribution. On Arch,
I'm using

    auth     optional  pam_gnupg.so
    session  optional  pam_gnupg.so

at the end of `/etc/pam.d/system-local-login`. Additionally, I have

    auth     optional  pam_gnupg.so

in `/etc/pam.d/i3lock`, so I can clear the password cache when locking the
screen, and have my keys unlocked automatically afterwards.

### GnuPG setup

Presetting passphrases needs to be enabled by adding

    allow-preset-passphrase

to `~/.gnupg/gpg-agent.conf`. Moreover, preset passphrases do not expire after
`default-cache-ttl` but after `max-cache-ttl`, so you may want to tweak that for
your use case.

### Key selection

The keygrips of all keys to be unlocked should be written to `~/.pam-gnupg`, one
per line. Empty lines and lines starting with `#` are ignored, as is whitespace
at the beginning of the line. Keygrips should be exactly 40 characters in
length. Everything after that is ignored as well, so you can also add comments
after the keygrip.

To show the keygrips of your private keys, use

    gpg -K --with-keygrips

Make sure to pick the keygrip of the proper subkey you want to unlock. For usage
with `pass`, that will be the encryption key.

Obviously, the respective keys need to have the same passphrase as your user
account.
