# pam-gnupg

Unlock GnuPG keys on login

## What is it?

A PAM module that hands over your login password to `gpg-agent`. This can be
useful if you are using a GnuPG-based password manager like [pass][].

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

The module implements PAM's `auth` and `session` functions. `auth` stores the
passphrase and tries to send it to `gpg-agent`. If that fails, e.g. due to the
agent not running, `session` (optionally) starts it and sends the passphrase
again.

How to include the module in PAM's config depends on your distribution. You
generally need to add the lines

    auth     optional  pam_gnupg.so
    session  optional  pam_gnupg.so

in the appropriate place(s). For graphical sessions, that should usually be
somewhere at the end of your display manager's config, e.g.
`/etc/pam.d/lightdm`, `/etc/pam.d/lxdm`, `/etc/pam.d/sddm`, etc.

On Arch, I also added it to `/etc/pam.d/system-local-login` for console logins.
Additionally, I have

    auth     optional  pam_gnupg.so

in `/etc/pam.d/i3lock`, so I can clear the password cache when locking the
screen (via `gpg-connect-agent --no-autostart reloadagent /bye`), and have my
keys unlocked automatically afterwards. The `session` line is not needed here,
since i3lock only authenticates the user, but does not open a new session.

#### Options

The following optional arguments can be specified:

- <code>auth optional pam_gnupg.so <strong>store-only</strong></code>: don't
  send the passphrase right away, just store it for `session`.

- <code>session optional pam_gnupg.so <strong>no-autostart</strong></code>:
  don't start the agent if it is not running. This can be useful if you want to
  start it via other means, e.g. as a systemd user service. In that case, make
  sure the `session`-line for `pam_systemd.so` comes before this one.

### GnuPG setup

Presetting passphrases needs to be enabled by adding

    allow-preset-passphrase

to `~/.gnupg/gpg-agent.conf`. Moreover, preset passphrases do not expire after
`default-cache-ttl` but after `max-cache-ttl`, so you may want to add a line like

    max-cache-ttl 86400

to have it expire after a day.

### Key selection

The default config file is `~/.pam-gnupg`. If that is not found,
`$XDG_CONFIG_HOME/pam-gnupg` is checked, with `XDG_CONFIG_HOME` defaulting to
`~/.config` as usual. If you want to change `XDG_CONFIG_HOME`, make sure to do it
via `.pam_environment` (see below), not your shell init file.

The keygrips of all keys to be unlocked should be written to config file, one
per line. Empty lines and lines starting with `#` are ignored, as is whitespace
at the beginning of the line. Keygrips should be exactly 40 characters in
length. Everything after that is ignored as well, so you can also add comments
after the keygrip.

To show the keygrips of your private keys, use

    gpg -K --with-keygrip

The output should look something like this:

<pre><code>sec   rsa2048 2018-11-16 [SC]
      9AB5DD43C5E5FD40475FA6DA0D776275F7F5B2E7
      Keygrip = 6F4ABB77A88E922406BCE6627AFEEE2363914B76
uid           [ultimate] Chris Ruegge &lt;mail@cxcs.de&gt;
ssb   rsa2048 2018-11-16 <strong>[E]</strong>
      Keygrip = <strong>FBDEAD7B0C484CDC85F1CF70352833EB0C921D58</strong>
</code></pre>

Make sure to pick the keygrip of the proper subkey you want to unlock. For usage
with `pass`, that will be the encryption key (the one marked `[E]`), but adding
the authentication subkey can also be useful in case you have one (it will be
marked `[A]`).

Obviously, the respective keys need to have the same passphrase as your user
account.

### Environment and moving `~/.gnupg`

When calling `gpg-connect-agent` to set the passphrase, the PAM-provided
environment is used. So if you want to move your `.gnupg` to a non-standard
location and set `$GNUPGHOME` accordingly, you can do so using `pam_env(8)` by
adding

    GNUPGHOME DEFAULT=@{HOME}/path/to/your/gnupg

to `~/.pam_environment`. Just make sure that `pam_env.so` is run before
`pam_gnupg.so`.

### SSH Keys

pam_gnupg indirectly supports unlocking SSH keys via gpg-agent's built-in SSH
agent, documented in `gpg-agent(1)`. To use it, you first need to set the
`SSH_AUTH_SOCK` variable to gpg-agent's SSH socket, e.g. via
`.{,z,bash_}profile`,

```
export SSH_AUTH_SOCK=$(gpgconf --list-dirs agent-ssh-socket)
```

or via `.pam_environment`, see above. Note that `pam_env` does not support
subshells, you'll need to set the explicit path there. Afterwards, SSH keys can
be imported to the agent using `ssh-add`. This only needs to be done once,
afterwards the keys are stored by the agent independently of the files in
`~/.ssh`. Finally, obtain the keygrip from

```
gpg-connect-agent 'keyinfo --ssh-list' /bye
```

and add it to `.pam_gnupg` as described above.

## Contact

- Email: mail@cxcs.de, [gpg key][]. The `gpg -K` output above is real, so the second line is the actual fingerprint.
- Keybase: [chrs](https://keybase.io/chrs)


[pass]: https://www.passwordstore.org/
[AUR package]: https://aur.archlinux.org/packages/pam-gnupg/
[gpg key]: https://gist.githubusercontent.com/cruegge/273380ce582d8d6c38b00bfaac433711/raw/3b6d506bd650d2e1b92c138bc608c6c567f048cc/mail@cxcs.de.pub.asc
