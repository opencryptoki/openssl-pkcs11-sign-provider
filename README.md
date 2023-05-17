# openssl-pkcs11-sign-provider

This repository provides the implementation of an OpenSSL Provider for
asymmetric operations with private PKCS\#11 keys. Requests with other key
material will be forwarded to an OpenSSL built-in provider.

This provider is a prove-of-concept at the current state.

## Build

This project requires OpenSSL 3.0 or later, as well as opencryptoki.
Support for other PKCS\#11 implementations is currently not available.

To build the provider, use the following commands:

```
autoreconf -fiv
./configure
make
```

## Test

This project provides some base test for the provider. The provider is
PKCS\#11-Module independent, but at the moment opencryptoki is the only
tested module.

The tests require a working opencryptoki setup. By default, the all keys are
stored in the token `softtok` in slot `3`. The setup script uses the PIN
`12345678` by default.

To setup and run the tests with the default settings for opencryptoki,
use the following commands:

```
make clean
make test
```

To setup and run the tests with other token/slot settings for
opencryptoki, use the following commands:

```
export OCK_USER_PIN="4711"
export OCK_SLOT="42"
export OCK_TOKEN="othertok"

make clean
make test
```

---
** Note **

The module setup is only executed, if the module's temporary
sub-directory doesn't exist. This sub-directory is removed for all
clean targets (e.g. `make clean`).

---

---
** Warning **

The setup script will remove generated key material in the PKCS\#11
token by name. Please make sure, that no other keys with the same name
exists in the token, otherwise they will be removed as well!  It is
highly recommended to backup all key material of a token, before
starting with testing.

---

If the environment variables `PKCS11SIGN_DEBUG` (path to the logfile)
is set, the provider will write debug output to a log-file.

The environment variable `PKCS11SIGN_DEBUG_LEVEL` specifies the
log-level error (`0`), warning (`1`), info (`2`) or debug (`3`).

## Install

The installation step may require further permissions. To install the
provider library, use the following commands:

```
make
sudo make install
```

## Configuration

For configuration, please refer to the man pages.
