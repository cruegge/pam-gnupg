# pam-gnupg

Unlock GnuPG keys on login

## What is it?

A PAM module that hands over your login password to `gpg-agent`, which can be
useful if you are using a GnuPG-based password manager like
[pass](https://www.passwordstore.org/).

Requires GnuPG 2.1, and probably only works on Linux.

## Disclaimer

The code was written mainly by looking at and occasionally copying from Gnome
Keyring's PAM module and pam_mount and is based on a somewhat mediocre
understanding of the details of both PAM and C. You should be aware that there
may be potentially dangerous bugs lurking.

## Installation

### Packages

- Arch: [pam-gnupg](https://aur.archlinux.org/packages/pam-gnupg/) from the AUR
- Void: [pam-gnupg](https://github.com/void-linux/void-packages/tree/master/srcpkgs/pam-gnupg)
- NixOS: [security.pam.services.\<name\>.gnupg](https://search.nixos.org/options?channel=unstable&from=0&size=30&sort=relevance&query=security.pam.services.%3Cname%3E.gnupg) (currently only in the unstable channel)

### Manually

The usual

    ./autogen.sh
    ./configure
    make
    make install

should work. `configure` takes an option `--with-moduledir` to set the
installation path of the PAM module. It defaults to `/lib/security`, but your
distribution might use a different path.

## Usage

### Setup guide

- For services that open a new session (gdm, sddm, login, ...), add the lines

      auth     optional  pam_gnupg.so store-only
      session  optional  pam_gnupg.so

  at the end (¹) of the corresponding file in `/etc/pam.d`, or in one of the
  files included from there, e.g. `system-local-login` on Arch.

  When opening the session, gpg-agent will be autostarted if necessary. If you
  want to start it by other means, e.g. as a systemd user service, make sure it
  is up before `pam_gnupg.so` is run, e.g. by putting the lines somewhere below
  `pam_systemd.so`, and (optionally) add `no-autostart` to the `session` line.

  (¹): The end is usually a good place, but details depend on your PAM setup.
  In particular, modules declared `sufficient` can terminate the PAM stack
  early. At least, `pam_gnupg.so` should come after `pam_unix.so`,
  `pam_systemd_home.so`, `pam_systemd.so` and `pam_env.so` in case you use
  those modules.

- For services that only authenticate (i3lock, physlock, ...), use

      auth     optional  pam_gnupg.so

  For screen lockers, this only really makes sense if you arrange for the
  password cache to be cleared prior to locking the screen by calling

      gpg-connect-agent --no-autostart reloadagent /bye

  During authentication, the agent will never be autostarted.

- Add

      allow-preset-passphrase

  to `~/.gnupg/gpg-agent.conf`. Optionally, customize the cache timeout via
  `max-cache-ttl`, e.g. set

      max-cache-ttl 86400

  to have it expire after a day.

- Run

      gpg -K --with-keygrip

  The output should look something like this:

  <pre><code>sec   rsa2048 2018-11-16 [SC]
        9AB5DD43C5E5FD40475FA6DA0D776275F7F5B2E7
        Keygrip = 6F4ABB77A88E922406BCE6627AFEEE2363914B76
  uid           [ultimate] Chris Ruegge &lt;mail@cxcs.de&gt;
  ssb   rsa2048 2018-11-16 <strong>[E]</strong>
        Keygrip = <strong>FBDEAD7B0C484CDC85F1CF70352833EB0C921D58</strong>
  </code></pre>

  Write the keygrip for the encryption subkey marked `[E]` – shown in boldface
  in the output above – into `~/.pam-gnupg`. If you want to unlock multiple
  keys or subkeys, add all keygrips on separate lines.

  Keygrips are exactly 40 characters in length. Leading whitespace, lines
  starting with `#` and everything after the keygrip is ignored.

  If `~/.pam-gnupg` does not exists, `$XDG_CONFIG_HOME/pam-gnupg` will be
  tried, with `XDG_CONFIG_HOME` defaulting to `~/.config` as usual. If you want
  to customize this variable, read the section on environment variables below.

- Set the same password for your gpg key and your user account. All pam-gnupg
  does is to send the password as entered to gpg-agent. It is therefore not
  compatible with auto-login of any kind; you actually have to type your
  password for things to work.

### SSH Keys

SSH key support is indirect via gpg-agent's built-in SSH support (there's no
SSH specific code in pam-gnupg). The full details are in `gpg-agent(1)`, but
here's a basic step-by-step guide:

- Add

      enable-ssh-support

  to `~/.gnupg/gpg-agent.conf`. (This is not actually strictly necessary in all
  setups, but doesn't hurt either.)

- Set the `SSH_AUTH_SOCK` variable to gpg-agent's SSH socket by putting

      export SSH_AUTH_SOCK=$(gpgconf --list-dirs agent-ssh-socket)

  into your relevant init script.

- Add your SSH keys to the agent using `ssh-add` as usual. This only needs to
  be done once. The agent will re-encrypt the keys and store them in
  `~/.gnupg`, independent of the ones in `~/.ssh`.

- Get the SSH keygrips using

      gpg-connect-agent 'keyinfo --ssh-list' /bye

  The output should look like

      S KEYINFO DBB0B60CFE5F23716ABEE8787C6184C27E2486E1 D - - - P - - S
      OK

  with one keygrip per line. Alternatively, get them from `~/.gnupg/sshcontrol`.

- Add the keygrips to `~/.pam-gnupg` the same way as for the gpg keys.

### Environment, `GNUPGHOME` & `XDG_CONFIG_HOME`

If you change your gnupg directory from the default `~/.gnupg` by setting
`GNUPGHOME` (²), or change the config directory via `XDG_CONFIG_HOME`, these
variables need to be made available to pam-gnupg when presetting.

For the `auth` module (without `store-only`, otherwise it does not matter
anyway, i.e. mostly for screen lockers), the existing session environment will
be used, so no additional setup is required.

The `session` module, however, runs before your usual init scripts and
therefore needs to obtain the environment from PAM. Setting it is easiest using
`pam_env.so`, which needs to be run before `pam_gnupg.so` and use the
`user_readenv=1` option. It will then read environment variables from
`~/.pam_environment`, which should contain lines like

    GNUPGHOME DEFAULT=@{HOME}/path/to/your/gnupg
    XDG_CONFIG_HOME DEFAULT=@{HOME}/path/to/your/config

(²): Note that changing `GNUPGHOME` changes the agent's socket location, so if
you start it via systemd, adjust the various `gpg-agent*.socket` units
accordingly.

#### Caveat

Since PAM version 1.5, `pam_env` emits a deprecation warning when using the
`user_readenv` option, and some future version will remove it entirely. After
that, variables can only be set system-wide in `/etc/security/pam_env.conf`
(which is of course not generally feasible).

For accounts managed by systemd-homed, PAM environment variables can also be
set via `homectl --setenv`, but other than that, I don't know any option for
setting per-user variables.

I may add an option to set `GNUPGHOME` in the config file once needed, but
`XDG_CONFIG_HOME` support can't be fixed this way.

### Debug output

Both the `auth` and the `session` module take a `debug` option to enable some
basic debug logging to syslog / journal.

### Known issues

- Using `pass` during startup of systemd user services has a racing condition
  even if the service declares `After=gpg-agent.socket`, because systemd does
  not know about pam-gnupg and will start the service right after the socket is
  up, but maybe before the key has been unlocked. Until I figure out a cleaner
  solution, you can circumvent this by adding a small startup delay to the
  service, e.g.

      ExecStartPre=/usr/bin/sleep 5

- Screen lockers need to call `pam_setcred` after authentication to actually
  send the passphrase. Those who don't will not work with pam-gnupg.
- Specifically for [suckless' slock](https://tools.suckless.org/slock/) with the
  [pam-auth
  patch](https://tools.suckless.org/slock/patches/pam_auth/slock-pam_auth-20190207-35633d4.diff),
  you have to set `user` and `group` to your user name and your primary group
  (as displayed by `id -gn`) in slock's `config.h`, which will therefore not work for multiple users. Alternatively, you can try the (untested) steps outlined in [this issue comment](https://github.com/cruegge/pam-gnupg/issues/34#issuecomment-857182214).

## Contact

- Email: mail@cxcs.de, [gpg key](https://gist.githubusercontent.com/cruegge/273380ce582d8d6c38b00bfaac433711/raw/3b6d506bd650d2e1b92c138bc608c6c567f048cc/mail@cxcs.de.pub.asc). The `gpg -K` output above is real, so the second line is the actual fingerprint.
- Keybase: [chrs](https://keybase.io/chrs)
