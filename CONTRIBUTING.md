# Contributing

You can contribute to `openssl-pkcs11-sign-provider` by submitting issues
(feature requests, bug reports) or pull requests (code contributions) to the
GitHub repository.


## Bug reports

When filing a bug report, please include all relevant information.

In all cases include the `openssl-pkcs11-sign-provider` version,
PKCS\#11-library version, operating system and kernel version used.

Additionally, if it is a build error, include the toolchain version used. If
it is a runtime error, include the PKCS\#11 hardware configuration and
processor model used.

Ideally, detailed steps on how to reproduce the issue would be included.


## Code contributions

All code contributions are reviewed by the `openssl-pkcs11-sign-provider`
maintainers who have the right to accept or reject a pull request.

All code contributions must have a developers sign of origin, like described
in the [Developer's Certificate of Origin 1.1 of the Linux Foundation][DCO].

Please state clearly if your pull request changes the
`openssl-pkcs11-sign-provider` API or ABI, and if so, whether the changes
are backward compatible.

If your pull request resolves an issue, please put a `"Fixes #<issue
number>"` line in the commit message. Ideally, the pull request would add a
corresponding regression test.

If your pull request adds a new feature, please add a corresponding unit
test.

All code of the `openssl-pkcs11-sign-provider` project should follow the
[Linux kernel coding guidelines][CS], wherever applicable.

[DCO]: <https://developercertificate.org/> "DCO"
[CS]:  <https://www.kernel.org/doc/html/latest/process/coding-style.html> "CS"
