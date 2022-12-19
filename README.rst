openssl-pkcs11-sign-provider
============================

This repository provides the implementation of an OpenSSL Provider for
asymmetric operations with private PKCS#11 keys. Requests with other key
material will be forwarded to an OpenSSL built-in provider.

This provider is a prove-of-concept at the current state.

build
-----

This project requires OpenSSL 3.0 or later, as well as opencryptoki. Support
for other PKCS#11 implementations is currently not available.

To build the provider, use the following commands:

.. code::

    autoreconf -fiv
    ./configure
    make check
    make install


.. note::

   The installation step may require further permissions.

For configuration, please refer to `docs/pkcs11sign_interface.rst`.
