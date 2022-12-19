====================
PKCS11-Sign-Provider
====================

Abstract
========

The *pkcs11-sign-provider* implements the OpenSSL 3.0 provider interface and
provides cryptographic operation on asymmetric key material, available in
PKCS#11 infrastructure (e.g. opencryptoki). The *pkcs11-sign-provider* will
register a key storage for PKCS#11 URIs. All keys which are referenced by a
PKCS#11 URI will be handled by the *pkcs11-sign-provider*. Other keys (e.g.
file-based) are are forwarded by the *pkcs11-sign-provider* to another
OpenSSL-Provider, e.g. the built-in default provider.

The *pkcs11-sign-provider* will only execute algorithms with existing
(private) asymmetric keys in the related PKCS11-token. All other actions
will be handled by the forward-provider as clear-key operations. It will not
be possible with the *pkcs11-sign-provider* to create keys in a
PKCS11-token.

Supported mechanisms for PKCS#11 operations:

- CKM_RSA_PKCS
- CKM_SHAxxx_RSA_PKCS
- CKM_RSA_PSS
- CKM_SHAxxx_RSA_PSS
- CKM_ECDSA
- CKM_ECDSA_SHAxxx
- (xxx can be 256, 384, 512)

Supported RSA key length for PKCS#11 operations:

- 2048 and 4096 bits

Supported EC curves for PKCS#11 operations:

- P256, P384, P521

Configuration
=============

The *pkcs11-sign-provider* can be configured application-specific or
system-wide.  In both cases, the OpenSSL configuration file need to define
and reference a section for the *pkcs11-sign-provider*.

The *pkcs11-sign-provider* section specifies the shared library of the
provider itself (mandatory), the shared library of the Cryptoki
implementation (mandatory) and initialization parameters for the Cryptoki
implementation (optional). It is also possible to specify a forward
provider. If no forward provider is specified, the built-in default-provider
is selected.

The *pkcs11-sign-provider* must be set in the algorithm-properties, so that
all requests are directed to the *pkcs11-sign-provider*. This can either be
done in the application or in the configuration file (recommended).

PIN handling
------------

The PIN is required to login to a PKCS#11 token, to manage or work with
sensitive PKCS#11 objects (keys) and should not be proposed to anyone
without a need-to-know.

An application, which is using key material in a PKCS#11 token, has such a
need-to-know, so the PIN should be under control of the application.

The *pkcs11-sign-provider* supports the PIN handling in the PKCS#11 URI with
the `pin-value` and the `pin-source` query-attributes. While the first one
contains the plain-text PIN, the latter one can refer to a file, which
contains the PIN. It is highly recommended to use the file reference and set
the access permissions of the PIN file accordingly.

Example OpenSSL configuration
-----------------------------

The initialization parameters for the Cryptoki implementation are not
required for a configuration with opencryptoki.

::

  openssl_conf = openssl_init

  <...>

  [openssl_init]
  providers = provider_sect
  alg_section = evp_properties

  <...>

  [provider_sect]
  default = default_sect
  base = base_sect
  pkcs11sign = pkcs11sign_sect

  <...>

  [evp_properties]
  default_properties = ?provider=pkcs11sign

  <...>

  [pkcs11sign_sect]
  module = /path/to/pkcs11sign.so
  identity = pkcs11sign
  pkcs11sign-module-path = /path/to/libopencryptoki.so.0
  pkcs11sign-forward = provider=default
  activate = 1

  <...>

.. note::

   The provider name in the `default_properties` must match the identity in
   the provider section and should not be changed.

Application Interface
=====================

An application, which should use asymmetric keys in PKCS#11
infrastructure, must use an OpenSSL configuration for the
*pkcs11-sign-provider* (see above) and refer to the keys by their PKCS#11
URI. The rest of the application should not need any changes.

If the system-wide configuration does not configure the
*pkcs11-sign-provider*, the application can use its own OpenSSL
configuration file and refer to it in its environment variable
`OPENSSL_CONF`.

Instead of referring to a private key file (`file:[...]`), the application
should use the PKCS#11 URI of the key (`pkcs11:[...]`).

The PKCS#11 URI should specify path parameters of the key, at least
the ID or label of the key, as well as its type.

Example for a PKCS#11 URI to a private key:

`pkcs11:object=my-key:prv;type=private&pin-source=/path/to/token-pinfile.txt`

.. note::

   The current version of *pkcs11-sign-provider* supports only the path
   parameters `id`, `object` and `type`. All other path parameters
   (e.g. for selecting a slot or a token) are not yet supported.

   Due to this limitation it is recommended to configure only a single
   token in opencryptoki and use unique key object labels.

.. note::

   The current version of *pkcs11-sign-provider* supports only the queue
   parameters `pin-value` and `pin-source`. All other queue parameters
   are not yet supported.

PIN handling
------------

The PIN gives access to a PKCS#11 token and its objects (keys,
certificated, data). It should be treated as a secret information and
only the application should have access to it. With the right setup,
the usage of a PIN file provides the best protection if the PIN.

- use one PIN file per token.
- the PIN file must only contain the PIN, no comments, no other characters.
- the PIN file must be readable by the application.
- the PIN file should not be writable by the application.
- the PIN file must not be readable nor writable by unprivileged users.

The following snippet shows, how to create such a protected PIN
file. The steps require root privileges (`sudo`) only if the PIN file
is created for another than the current user.

.. ::

   PINFILE="/path/to/application/configdir/token1_pin.txt"
   PIN="12345678"

   #
   # create the PIN file and set the permissions
   #
   touch ${PINFILE}
   sudo chown <appl_uid>:<appl_gid> ${PINFILE}
   sudo chmod u=rw,go= ${PINFILE}

   #
   # write the PIN to the protected file
   #
   echo "12345678" | sudo tee -a ${PINFILE} > /dev/null
   sudo chmod u-w ${PINFILE}

.. note::

   Never use PIN `12345678` in production environment!
