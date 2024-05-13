# etoolkit

*etoolkit* is a simple toolkit for defining and setting environment variables
in a flexible and secure way.


## General

*etoolkit* started as a simple idea while I was working at the University
of Oslo. Later I felt the need for even more flexible solution. The following
goals were set:

- the ability to define env. var. "instances" with support for inheritance

- encrypting values using a master password

- the ability to spawn a child process with the defined variables

- support for macros


## Requirements

Apart from Python >= 3.8, the only requirement is
[cryptography](https://pypi.org/project/cryptography/)


## Overview

In a typical UNIX environment, env. variables are usually set in one
or more of the initialization / startup files like f.i. */etc/profile*,
*~/.bash_profile*, *~/.bashrc*, *~/.tcshrc*, *~/.cshrc* ... depending
on the OS, shell, distribution... etc.
Env. variables represent key-value pairs (env. variable name and its value).

A potential problem when dealing with env. variables containing sensitive
values like passwords, tokens, connection strings... is that they are inherited
by all child processes spawned from the login / interactive shell.

A malicious / exploited process (like f.i. web browser) will then be able to
fetch those values by using *getenv*. Such process may in addition be able to
simply read *~/.bashrc* or any similar file readable by the process owner and
get the values from there if necessary.

*etoolkit* attempts to solve both of these problems.

When started, it reads env. variables from its own configuration file.
Sensitive data may be encrypted using a master password. Hence reading
etoolkit's configuration file will not reveal the real value of the data.

When *etoolkit* has processed (decryption, macro replacement, etc) its data,
it may define new env. variables corresponding to that data and may start a new
interactive shell. The processed environment variables will not be available
for processes that were not spawned by that same *etoolkit* session.


## Installation

### pip (pypi)

   ```bash
   pip install etoolkit
   ```


### Gentoo

   ```bash
   # add sgs' custom repository using app-eselect/eselect-repository
   eselect repository add sgs

   emerge dev-python/etoolkit
   ```

## Encryption & decryption scheme

The etoolkit encryption format is currently at version 2.
Encrypted values start with *enc-val$2$*.

This new version introduces padding for values that are shorter than 32 bytes.
The idea behind padding is to generate (32 - value length) random bytes and
append them to the original value.
That prevents a potential attacker from knowing the length of the encrypted
short value (f.i. password, PIN number, username... etc).

Values encrypted in the old format (*enc-val$1$*) can still be decrypted
seamlessly.

Authenticated encryption with associated data (AEAD) is implemented using
AES-GCM.


### Encryption

Input:

- plain-text value to be encrypted (P)

- plain-text master-password used for key derivation (M)


Output:

- an encrypted value digest (base64) (B)


Operation:

- generate 32 bytes of random data to be used as a salt (S)

- derive a 32 bytes key (K): K = scrypt(M, S, n=2**14, r=8, p=1)

- use the first 12 bytes of S as nonce (NONCE)

- calculate the padding length (L) as 32 - length of P, if P < 32, 0 otherwise

- set the padding length bytes (N) (2bytes) to "%02d", if L > 0, "-1" otherwise

- generate L bytes of random data to be used for padding (D)

- encrypt and auth. P, auth.only S (E): E = AES_GCM_ENC(K, NONCE, N + P + D, S)

- encrypted value digest (B) = enc-val$2$:BASE64_ENCODE(S)$BASE64_ENCODE(E)

example:
enc-val$2$uYpZM1VfAGq0CDZL2duITs076CQj+hIFEgx+F4mn80o=$UWP5YeRsh5/2vZ2J1UOS+BJti73Kbp6C1pJmCo8hFSujpe35X/XpzBegJJpo86AiCsNsUS6B6JM=


### Decryption

Input:

- encrypted value digest (base64) (B)

- plain-text master-password used for key derivation (M)


Output:

- plain-text password (P)


Operation:

- remove the prefix (enc-val$2$) from B and split the remaining value by '$'

- base64-decode the salt (S): S = BASE64_DECODE(B1)

- base64-decode the rest of the data (E): E = BASE64_DECODE(B2)

- derive a 32 bytes key (K): K = scrypt(M, S, n=2**14, r=8, p=1)

- use the first 12 bytes of S as nonce (NONCE)

- decrypt the encrypted data (D): D = AES_GCM_DECRYPT(K, NONCE, E, S)

- fetch the first 2 bytes (padding length bytes) (N): N = D[0 : 2]

- calculate the padding length (L): L = INT(N) if N != "-1", 0 otherwise

- fetch the plain-text (P): P = D[2 : -L] if L != 0, D[2 :] otherwise


## Setup and examples

Most users (including me) will simply use the command line interface (CLI).


### CLI

*etoolkit* comes with a simple CLI:

   ```bash
   python -m etoolkit -h
   ```

... or even (if *etoolkit* was installed using the methods described above)

   ```bash
   etoolkit -h
   ```


The *etoolkit* CLI loads the configuration located by default in
*~/.etoolkit.json*. That file is based on
[etoolkit_sample.json](https://github.com/blackm0re/etoolkit/blob/master/etoolkit_sample.json).

The *"instances"* part of the configuration defines unique instances, each of
which represents its own environment with its own defined env. variables.
Each instance consists of key-value pairs corresponding to env. name and value.
All pairs will result in corresponding env. variables being defined, with the
exception of the following *etoolkit* internal keys:

- *ETOOLKIT_PARENT* - string - reference to another instance

- *ETOOLKIT_SENSITIVE* - list - env. variables containing sensitive data

All pairs defined in *"general"* (currently only *MASTER_PASSWORD_HASH*) are
*etoolkit* internal as well.

An instance may inherit (and if desired overwrite) key value pairs from its
parent.

Variables containing sensitive data can be encrypted / decrypted using a master
password. Currently *etoolkit* requires that all values in a configuration
file are encrypted with the same master password. Setting a master password
hash is a recommended but not mandatory.

   ```bash
   etoolkit --generate-master-password-hash
   ```

That command will prompt for master password and output a hash that can then
be stored  
in ["general"]["MASTER_PASSWORD_HASH"].  
The hash is only used for verifying that a correct master password has been
provided at a later time. Issuing:

   ```bash
   etoolkit --encrypt-value
   ```

will prompt for the master password, then for the value to be encrypted and
finally display the encrypted string of the value. Unless invoked with the
*-E* / *--echo* parameter *etoolkit* will not display the value that is about
to be encrypted.

More than one value can be encrypted / decrypted with a single master password
prompt if *-m* / *--multiple-values* parameter is provided. Manual decryption
of single value(s):

   ```bash
   etoolkit --decrypt-value --multiple-values
   ```

Another possibility is to pass the value to *etoolkit*'s *stdin* using a pipe.
*etoolkit* will then only prompt for password and not for a value:

   ```bash
   echo mysecret | etoolkit --encrypt-value
   ```

... or if the *ETOOLKIT_MASTER_PASSWORD* env. variable is defined, its value
will be used instead of prompting for password.

Listing available instances defined in the configuration file and then
loading a specific instance can be achieved by:

   ```bash
   etoolkit --list
   etoolkit <instance-name>
   ```

Instances with names starting with *_* will be considered *abstract* and will
not be displayed by *--list*.

*etoolkit* will prompt for the master password the first time it encounters
and encrypted value. Once provided the master password will be used to decrypt
the rest of the encrypted values.

When all values are fetched from a given instance (and its parents) and then
decrypted, they are further processed by replacing macros with their
corresponding values. Currently the following macros are supported:

- **%h** - the home directory of the user running *etoolkit* (~/)

- **%i** - the name of the instance that is about to be loaded

- **%p** - the parent value (for the same key)

- **%u** - the username of the user running *etoolkit* (*getpass.getuser()*)

In addition, value starting with *":"* is appended to the existing value
(if any) of the env. variable about to be set
(like *MYVAR=$MYVAR\<new value\>)*).  
The opposite is true for value ending with *":"* (*MYVAR=\<new value\>$MYVAR*).

When the variables are finally processed, *etoolkit* sets / changes them as env.
variables (using *setenv* / *os.environ.update*) and spawns an interactive
child process (by invoking *system($SHELL)*).

One can also spawn a different process than an interactive shell by using the
*-s* / *--spawn* parameter.

   ```bash
   etoolkit --spawn /bin/othershell <instance-name>
   ```

It is possible to re-encrypt all encrypted values in a specific instance or in
all defined instances either by using the same or a new master password.

   ```bash
   etoolkit --reencrypt all
   ```

will prompt for the current master password, then for a new master password
(with confirmation) and finally the new config file (if "all") or instance
contents will be displayed.

Contact the author for questions and suggestions! :)


### Using the *EtoolkitInstance* class

*etoolkit* comes with its own *etoolkit* package that contains the
*EtoolkitInstance* class.

The class encapsulates the function of creating and processing instances
from a given structure (dict).

It may be useful if one should prefer for example making her own CLI interface.
or the *instances* structure being loaded from a diferent configuration file
(f.i. .yml).

   ```python
   import os

   import etoolkit


   # using some static methods in order to create encrypted values
   etoolkit.EtoolkitInstance.encrypt('The very secret passwd', 'secret1')
   # Out: 'enc-val$2$NDdp6WMbX7gdEyzGM5nI4jhyer4XL+BoQwAHtL2CXHw=$+Pztn1pfaXKjPpem5PIQrCNxR9pyE6zqgSoGg9qXvmhH6VsNQvUTmiaOvUFl35EbiYE='

   etoolkit.EtoolkitInstance.encrypt('The very secret passwd', 'secret2')
   # Out: 'enc-val$2$H953GxW+qrYXIp+I97lJBmG1gv89wxcfmTu7PEpZzjE=$Tb3F8/izDbHAMklpIjYk73JAiav+w8ZhrMsO93FlQjGh4MTChjp2Yen5BxSBOWLvCD4='


   # The encrypted values will be used in our configuration structure
   # The following structure defines the 3 instances: default, dev and secret
   instances = {
       "general": {
       },
       "instances": {
           "_default": {
             "ETOOLKIT_PROMPT": "(%i)",
             "ETOOLKIT_SENSITIVE": ["DB_CONNECTION", "ETOOLKIT_TEST_PASSWORD"]
           },
           "dev": {
               "ETOOLKIT_PARENT": "_default",
               "PYTHONPATH": ":/home/user/.pythonpath",
               "DB_CONNECTION": "enc-val$2$RAgDei59tUvDAkrBmxROqRaV/NxNFEI2eJIOP7sG/b8=$yse7zawHCzQCU31sZj4oJYLGonz1M7oqHqCilXLHkywa9nMPALypmVzi3QekekYuLeb5XVTmmp84NHoPn1M052otoRHSp+TMPsqBPRabfriIKEK4XQ=="
           },
           "secret": {
               "ETOOLKIT_PARENT": "_default",
               "GNUPGHOME": "%h/private/.gnupg",
               "ETOOLKIT_TEST_PASSWORD": "enc-val$2$RCSZqq9pWrRDoCVYVHopyu1LzaJGfv8roVviqrLTBxM=$+YYrZbwTBuG0Pl+WMQrvxLUtq5j8qYuQqzoIwgoGt7AaWZCJz+E7qoDeg3wke70ST8U="
           }
       }
   }

   secret_instance = etoolkit.EtoolkitInstance('secret', instances)

   # fetch the variables before the processing stage (calling get_environ())
   # since raw_env_variables is a dict, it can be modified (f.i. .update())
   secret_instance.raw_env_variables

   secret_instance.master_password = 'The very secret passwd'  # or perhaps using getpass
   env_vars = secret_instance.get_environ()
   print(env_vars['ETOOLKIT_TEST_PASSWORD'])  # outputs: 'secret1'
   
   secret_instance.env_to_str(env_vars)  # prints all values, with the exception of 'ETOOLKIT_TEST_PASSWORD'

   # set the env. variables.
   os.environ.update(env_vars)
   ```


### Tips

When starting a new interactive process (f.i. bash), the process will
in turn invoke its startup script (f.i. *~/.bashrc*).  
Avoid redefining the env. variables that have just been set by *etoolkit*!

If you want your shell prompt to display the name of the loaded instance, you
can set a new env. variable (f.i. "ETOOLKIT_PROMPT" as shown in the sample
configuration above) and then add the following at the bottom of your startup
file (f.i. ~/.bashrc):

   ```bash
   if [ -n "$ETOOLKIT_PROMPT" ]; then
       export PS1="$ETOOLKIT_PROMPT$PS1"
   fi
   ```

A quick and dirty bash completion for available instances can be set at the
bottom of your bash startup file:

   ```bash
   complete -W '$(compgen -W "$(etoolkit -l)")' etoolkit
   ```

A complete bash completion script for *etoolkit* can be found here:
[https://github.com/blackm0re/etoolkit/blob/master/completion/etoolkit.bash](https://github.com/blackm0re/etoolkit/blob/master/completion/etoolkit.bash)


## Changelog

A complete changelog can be found at:
[https://github.com/blackm0re/etoolkit/blob/master/CHANGELOG.md](https://github.com/blackm0re/etoolkit/blob/master/CHANGELOG.md)


## Support and contributing

*etoolkit* is hosted on GitHub: https://github.com/blackm0re/etoolkit


## Author

Simeon Simeonov - sgs @ LiberaChat


## [License](https://github.com/blackm0re/etoolkit/blob/master/LICENSE)

Copyright (C) 2021-2024 Simeon Simeonov
All rights reserved.

[Licensed](https://github.com/blackm0re/etoolkit/blob/master/LICENSE) under the
GNU General Public License v3.0 or later.
SPDX-License-Identifier: GPL-3.0-or-later
