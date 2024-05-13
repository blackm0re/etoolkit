# Changelog

## [2.0.0](https://github.com/blackm0re/etoolkit/tree/2.0.0) (2024-05-13)

[Full Changelog](https://github.com/blackm0re/etoolkit/compare/1.2.0...2.0.0)

**Changes:**

- etoolkit encryption format v2, adding rnd. padding for values < 32 bytes

- re-encryption support

- replaced *os.system* with *subprocess*

- new etoolkit.EtoolkitInstance API (not compatible with v1)


## [1.2.0](https://github.com/blackm0re/etoolkit/tree/1.2.0) (2022-04-04)

[Full Changelog](https://github.com/blackm0re/etoolkit/compare/1.1.0...1.2.0)

**Changes:**

- instances with names starting with *_* are treated as abstract and not listed

- new *%p* macro - parent value (for the same key)


## [1.1.0](https://github.com/blackm0re/etoolkit/tree/1.1.0) (2022-03-14)

[Full Changelog](https://github.com/blackm0re/etoolkit/compare/1.0.0...1.1.0)

**Changes:**

- a master password can now be set using the *ETOOLKIT_MASTER_PASSWORD* env. variable

- a new parameter *-P* / *--master-password-prompt* can be used in order to force password prompt

- improved tests

- use *setuptools* instead of the deprecated *distutils*


# [1.0.0](https://github.com/blackm0re/etoolkit/tree/1.0.0) (2021-12-23)

**Changes:**

- Initial release
