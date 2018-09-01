# pam-gnupg

Unlock GnuPG keys on login

## What is it?

A PAM module that hands over your login password to `gpg-preset-passphrase`.
This can be e.g. useful if you are using a GnuPG-based password manager,
e.g. [pass][].

Requires GnuPG 2.1, and probably only works on Linux.

## Disclaimer

The code was written mainly by looking at and occasionally copying from Gnome
Keyring's PAM module and pam_mount and is based on a somewhat mediocre
understanding of the details of both PAM and C. Since this is security related,
you should be aware that there may be potentially dangerous bugs lurking.

## Installation

The usual

    ./autogen.sh
    ./configure
    make
    make install

should work.

`configure` takes an option `--with-moduledir` to set the installation path of
the PAM module. It defaults to `/lib/security`, but your distribution might use
a different path.

For Arch users, there's an [AUR package][].

## Usage

### PAM setup

The module implements PAM's `auth` and `session` functions. The `auth` part
stores the passphrase and tries to send it to `gpg-agent`. If that fails, e.g.
due to `gpg-agent` not running, the `session` part starts the agent and sends
the passphrase again.

How to include the module in PAM's config depends on your distribution. You
generally have to add the lines

    auth     optional  pam_gnupg.so
    session  optional  pam_gnupg.so

in the appropriate place(s). For graphical sessions, you should usually add it
somewhere at the end of your display manager's config, e.g.
`/etc/pam.d/lightdm`, `/etc/pam.d/lxdm`, `/etc/pam.d/sddm`, etc. On Arch, I also
added it to `/etc/pam.d/system-local-login` for console logins.

Additionally, I have

    auth     optional  pam_gnupg.so

in `/etc/pam.d/i3lock`, so I can clear the password cache when locking the
screen, and have my keys unlocked automatically afterwards. Adding the `session`
line is not needed here, since i3lock only authenticates the user, but does not
open a new session.

#### Compatibility with systemd user sessions

The `session` part uses `gpg-connect-agent` to implicitly start `gpg-agent` if
it is not already running. In case you prefer to start `gpg-agent` as a systemd
user service, make sure the `session` line in your PAM config comes after the
`session` line for `pam_systemd.so`. This way, `gpg-agent` will already be
running as a user service by the time `pam_gnupg.so` is called.

#### Options

The `auth` part takes an optional paramter `store-only`. If present, it prevents
the module from trying to preset the passphrase right away, and just stores it
to be used by the `session` part.

The `session` part takes an optional parameter `no-autostart`. If present, it
prevents the module from starting the agent at all. This is useful in
combination with systemd, if you want to make sure that the agent is not started
by `pam_gnupg` if systemd fails to do so for some reason.

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

    gpg -K --with-keygrip

The output should look something like this:

    sec   rsa2048 2014-06-28 [SC]
          D58B0819B978E3857AF4D701BBA3C6314425E90A
          Keygrip = 178A776A023EFD0D2A4C7113DDD3ED1B17FEAD37
    uid           [ultimate] Christoph Ruegge <me@mail.net>
    ssb   rsa2048 2014-06-28 [E]
          Keygrip = 6322CB84600BFA0F523B7BE4AB49E73CA4327AE2
    ssb   rsa2048 2014-06-28 [A]
          Keygrip = FF8600AF0D05B744B7840AED80220657E2C22899

Make sure to pick the keygrip of the proper subkey you want to unlock. For usage
with `pass`, that will be the encryption key (the one marked `[E]`), but adding
the authentication subkey `[A]` can also be useful in case you have one.

Obviously, the respective keys need to have the same passphrase as your user
account.

### Environment and moving `~/.gnupg`

When calling `gpg-connect-agent` to set the passphrase, the pam-provided
environment is used. So if you want to move your `.gnupg` to a non-standard
location and set `$GNUPGHOME` accordingly, you can do so using `pam_env(8)` by
adding

    GNUPGHOME DEFAULT=@{HOME}/path/to/your/gnupg

to `~/.pam_environment`. Just make sure that `pam_env.so` is run before
`pam_gnupg.so`.


[pass]: https://www.passwordstore.org/
[AUR package]: https://aur.archlinux.org/packages/pam-gnupg-git/
