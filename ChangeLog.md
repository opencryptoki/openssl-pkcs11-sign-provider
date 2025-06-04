# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

- various fixes and cleanups
- update man-pages
- fix key management registration and key typing
- fix several double frees

## [1.0.1] - 2024-02-06

- example RPM packaging
- fork handling (issue #2)
- support passphrase callback for PIN (issue #5)
- additional testcases
- fix URI parsing (issues #9, #10)
- various fixes and cleanups

## [1.0.0] - 2023-05-17

### Added

- Initial provider implementation
- PKCS\#11 key URI support (RFC 7512)
- ECDSA signature support (PKCS\#1, PSS)
- RSA sign support (PKCS\#1)
- RSA decrypt support (raw, PKCS\#1, OAEP)
- forwarding for all public key operations

[unreleased]: https://github.com/opencryptoki/openssl-pkcs11-sign-provider/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/opencryptoki/openssl-pkcs11-sign-provider/compare/base...v1.0.0
