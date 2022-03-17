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

Apart from Python >= 3.7, the only requirement is
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

   # ... or using layman (obsolete)
   layman -a sgs

   emerge dev-python/etoolkit
   ```


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

Listing all available instances defined in the configuration file and then
loading a specific instance can be achieved by:

   ```bash
   etoolkit --list
   etoolkit <instance-name>
   ```

*etoolkit* will prompt for the master password the first time it encounters
and encrypted value. Once provided the master password will be used to decrypt
the rest of the encrypted values.

When all values are fetched from a given instance (and its parents) and then
decrypted, they are further processed by replacing macros with their
corresponding values. Currently the following macros are supported:

- **%h** - the home directory of the user running *etoolkit* (~/)

- **%i** - the names of the instance that is about to be loaded

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
   etoolkit.EtoolkitInstance.encrypt('the very secret passwd', 'secret1')
   # Out: 'enc-val$1$Y/TBb1F3siHTw6qZg9ERzZfA8PLPf2CwGSQLpu9jYWw=$FT5tS9o+ABvsxogIXpJim16Gz5SVtV8='

   etoolkit.EtoolkitInstance.encrypt('the very secret passwd', 'secret2')
   # Out: 'enc-val$1$vIBcoCNiYrsDLtF41uLuSEnppBjhliD0B8jwcBJcj/c=$KwOGe/y1dlxktDaCnJPIVNuaQ4Q7yNo='


   # The encrypted values will be used in our configuration structure
   # The following structure defines the 3 instances: default, dev and secret
   instances = {
       "general": {
       },
       "instances": {
           "default": {
               "ETOOLKIT_PROMPT": "(%i)"
           },
           "dev": {
               "ETOOLKIT_PARENT": "default",
               "PYTHONPATH": ":/home/user/.pythonpath",
               "DB_CONNECTION": "enc-val$1$Y/TBb1F3siHTw6qZg9ERzZfA8PLPf2CwGSQLpu9jYWw=$FT5tS9o+ABvsxogIXpJim16Gz5SVtV8="
           },
           "secret": {
               "ETOOLKIT_PARENT": "default",
               "ETOOLKIT_SENSITIVE": ["PASSWORD"],
               "GNUPGHOME": "%h/private/.gnupg",
               "PASSWORD": "enc-val$1$vIBcoCNiYrsDLtF41uLuSEnppBjhliD0B8jwcBJcj/c=$KwOGe/y1dlxktDaCnJPIVNuaQ4Q7yNo="
           }
       }
   }


   dev_instance = etoolkit.EtoolkitInstance('dev', instances)

   # fetch the variables before the processing stage (calling get_environ())
   # since raw_env_variables is a dict, it can be modified (f.i. .update())
   dev_instance.raw_env_variables

   dev_instance.master_password = 'the very secret passwd'  # or perhaps using getpass
   env_vars = dev_instance.get_env()
   print(env_vars['PASSWORD'])  # outputs: 'secret2'
   
   inst.dump_env(env_vars)  # prints all values, with the exception of 'PASSWORD'

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

Copyright (C) 2021-2022 Simeon Simeonov
All rights reserved.

[Licensed](https://github.com/blackm0re/etoolkit/blob/master/LICENSE) under the
GNU General Public License v3.0 or later.
SPDX-License-Identifier: GPL-3.0-or-later
