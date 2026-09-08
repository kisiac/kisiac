# Changelog

## [2.0.0](https://github.com/kisiac/kisiac/compare/v1.9.0...v2.0.0) (2026-07-22)


### ⚠ BREAKING CHANGES

* perform deep merge of config files at different levels

### Features

* support setting zfs recordsize ([70e3dab](https://github.com/kisiac/kisiac/commit/70e3dab05a864d2ebc458dfaf2a7ca233a037a53))


### Bug Fixes

* apply setgid, sticky, and setuid only on dirs ([5f5feff](https://github.com/kisiac/kisiac/commit/5f5feffefedef6ad2f207ca7218c06265f1b7e51))
* ensure ACL flags are given in the right order ([0a4ac09](https://github.com/kisiac/kisiac/commit/0a4ac09358bf87347abb3149fb82b184df4882c8))
* escape quotes in commands ([#38](https://github.com/kisiac/kisiac/issues/38)) ([1cc227e](https://github.com/kisiac/kisiac/commit/1cc227e1f355ee9cc1316efe77d50ae635ec8627))
* fix quote escapting in profile template ([0bbbf88](https://github.com/kisiac/kisiac/commit/0bbbf88356d7d52282aeeb4206cf878878cc3494))
* let user dir be expanded automatically ([c30f611](https://github.com/kisiac/kisiac/commit/c30f611e0cba456f340ea1d0a38be8c5a6c761b0))
* perform deep merge of config files at different levels ([49b6ec3](https://github.com/kisiac/kisiac/commit/49b6ec3226e2b44add2c5457e43c50cd7f513503))
* set ACL mask if required ([c081079](https://github.com/kisiac/kisiac/commit/c0810794e3967186b759b0a505a3ee90c5d9f6ea))
* setgit and setuid only on dirs (S) ([c47c7af](https://github.com/kisiac/kisiac/commit/c47c7affd2c5c23301fafcdaa6b194d374d9483f))
* use proper path for user files ([#36](https://github.com/kisiac/kisiac/issues/36)) ([56ac8c9](https://github.com/kisiac/kisiac/commit/56ac8c98cc7e0330a4b7d80f492d937618bf7053))
* whitespace handling in bash messages ([0fe5746](https://github.com/kisiac/kisiac/commit/0fe5746670cc3a689587708f165b69ff8b9664e9))

## [1.9.0](https://github.com/kisiac/kisiac/compare/v1.8.0...v1.9.0) (2026-06-09)


### Features

* support for untagged pvs ([#28](https://github.com/kisiac/kisiac/issues/28)) ([aa81ff0](https://github.com/kisiac/kisiac/commit/aa81ff03a476914158bbca27164b600713434a53))


### Bug Fixes

* avoid re-mounting of existing zfs datasets ([#33](https://github.com/kisiac/kisiac/issues/33)) ([a2d02aa](https://github.com/kisiac/kisiac/commit/a2d02aa1a15eaa29277193f469e7419a123aa3eb))
* mount unmounted zfs datasets and handle encryption key input ([#34](https://github.com/kisiac/kisiac/issues/34)) ([76faa54](https://github.com/kisiac/kisiac/commit/76faa544c14ae5344065949e99ce3281c8d1b3dd))

## [1.8.0](https://github.com/kisiac/kisiac/compare/v1.7.0...v1.8.0) (2026-06-08)


### Features

* ashift support ([#26](https://github.com/kisiac/kisiac/issues/26)) ([80bbda0](https://github.com/kisiac/kisiac/commit/80bbda09e48e0529905093d8a8a5e92fe0b5210f))

## [1.7.0](https://github.com/kisiac/kisiac/compare/v1.6.0...v1.7.0) (2026-05-29)


### Features

* support sync property for datasets ([#23](https://github.com/kisiac/kisiac/issues/23)) ([61a5e46](https://github.com/kisiac/kisiac/commit/61a5e4674d59755cd6c2a5b9393b6284e3b9ee9b))


### Bug Fixes

* confirm zfs actions ([#25](https://github.com/kisiac/kisiac/issues/25)) ([0f91cd1](https://github.com/kisiac/kisiac/commit/0f91cd17d28ca9e1bfa35dc3e7b7565b5645ebdc))

## [1.6.0](https://github.com/kisiac/kisiac/compare/v1.5.2...v1.6.0) (2026-05-19)


### Features

* zfs support ([#21](https://github.com/kisiac/kisiac/issues/21)) ([0bfd3ba](https://github.com/kisiac/kisiac/commit/0bfd3bad48e9dcd7d3ff452bb56447184dfa74ed))

## [1.5.2](https://github.com/kisiac/kisiac/compare/v1.5.1...v1.5.2) (2026-03-17)


### Bug Fixes

* add acl as default system software ([2bca64e](https://github.com/kisiac/kisiac/commit/2bca64e3cad5a7fdc88c4942528f8602e2eaaab1))
* correct permission settings ([f117fff](https://github.com/kisiac/kisiac/commit/f117fffd9312b37a85867c2bee247ac35f839d9b))
* properly remove ACL defaults if setgid is not set ([4631a12](https://github.com/kisiac/kisiac/commit/4631a12db36cc00eefcdd8b4d4c4a92145e2dbbc))

## [1.5.1](https://github.com/kisiac/kisiac/compare/v1.5.0...v1.5.1) (2026-03-15)


### Miscellaneous Chores

* release 1.5.1 ([76d510f](https://github.com/kisiac/kisiac/commit/76d510fda20c4e05b79fd02ee68d1983784b1780))

## [1.5.0](https://github.com/kisiac/kisiac/compare/v1.4.1...v1.5.0) (2026-03-15)


### Features

* support for LVM caching ([#16](https://github.com/kisiac/kisiac/issues/16)) ([4ae6850](https://github.com/kisiac/kisiac/commit/4ae685063f2d7379eec756d746a38f14e8b85e58))

## [1.4.1](https://github.com/kisiac/kisiac/compare/v1.4.0...v1.4.1) (2025-12-15)


### Bug Fixes

* support multiline input in setup-config ([24815ee](https://github.com/kisiac/kisiac/commit/24815eef471ce7dfaa0dbe8a333c917d5c6ad45f))

## [1.4.0](https://github.com/kisiac/kisiac/compare/v1.3.0...v1.4.0) (2025-12-06)


### Features

* check-hosts ([#12](https://github.com/kisiac/kisiac/issues/12)) ([97ae217](https://github.com/kisiac/kisiac/commit/97ae21745a1bb3d89c3790fe4fed246dfffe59a8))
* show missing pvs ([#14](https://github.com/kisiac/kisiac/issues/14)) ([52a29e1](https://github.com/kisiac/kisiac/commit/52a29e18ddf05dfeed397a2e5d6cc5b9fbc42bc9))

## [1.3.0](https://github.com/kisiac/kisiac/compare/v1.2.0...v1.3.0) (2025-12-05)


### Features

* specify encryption via mapping ([#10](https://github.com/kisiac/kisiac/issues/10)) ([8682a79](https://github.com/kisiac/kisiac/commit/8682a7991ab71e3133274856b1026e7ab38e68f1))

## [1.2.0](https://github.com/kisiac/kisiac/compare/v1.1.0...v1.2.0) (2025-12-04)


### Features

* allow yte config ([#8](https://github.com/kisiac/kisiac/issues/8)) ([4dda2b4](https://github.com/kisiac/kisiac/commit/4dda2b4160fbbe107d0b4b3a9d185a9c85716d66))

## [1.1.0](https://github.com/kisiac/kisiac/compare/v1.0.4...v1.1.0) (2025-12-04)


### Features

* encryption support ([#7](https://github.com/kisiac/kisiac/issues/7)) ([8340ed6](https://github.com/kisiac/kisiac/commit/8340ed68633597b3658731d700c7ba54d5548c25))


### Bug Fixes

* proper defaults for filesystem spec ([c775169](https://github.com/kisiac/kisiac/commit/c7751696c2c9f1c830ec1677c753db49a9ac93c4))

## [1.0.4](https://github.com/kisiac/kisiac/compare/v1.0.3...v1.0.4) (2025-11-24)


### Bug Fixes

* add license ([c4b4798](https://github.com/kisiac/kisiac/commit/c4b4798f7fde5836bff676c1bdc20b5e41a69ce6))

## [1.0.3](https://github.com/kisiac/kisiac/compare/v1.0.2...v1.0.3) (2025-11-24)


### Documentation

* update cli help ([8a436db](https://github.com/kisiac/kisiac/commit/8a436dbf32a9bb15f0c3a0f222d1240e2a7859af))

## [1.0.2](https://github.com/kisiac/kisiac/compare/v1.0.1...v1.0.2) (2025-11-24)


### Bug Fixes

* use correct package for building ([f91bd42](https://github.com/kisiac/kisiac/commit/f91bd42750005194913938017fc2e10759ef9df9))

## [1.0.1](https://github.com/kisiac/kisiac/compare/v1.0.0...v1.0.1) (2025-11-24)


### Miscellaneous Chores

* release 1.0.0 ([168e6ce](https://github.com/kisiac/kisiac/commit/168e6cecee807f254f8fefefe2bc87f3c48272e2))
* Release 1.0.1 ([a3e7ab2](https://github.com/kisiac/kisiac/commit/a3e7ab2465bbb9a56ad909b3e5b50193fdd355cd))

## 1.0.0 (2025-11-24)


### Miscellaneous Chores

* release 1.0.0 ([168e6ce](https://github.com/koesterlab/kisiac/commit/168e6cecee807f254f8fefefe2bc87f3c48272e2))
