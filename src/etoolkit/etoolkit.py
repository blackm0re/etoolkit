# etoolkit
# Copyright (C) 2021-2024 Simeon Simeonov

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""The main module of the etoolkit package"""

import base64
import getpass
import hashlib
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MIN_ENCRYPTED_VALUE_LENGTH = 32


class EtoolkitInstanceError(Exception):
    """EtoolkitInstanceError - Generic exceptions related to instances"""


class EtoolkitInstance:
    """A basic class representing a single instance"""

    def __init__(self, name: str, data: dict):
        """
        :param name: Instance name
        :type name: str

        :param data: .etoolkit.json alike dict
        :type data: dict
        """
        self._name = name
        self._parent = None
        self._raw_env_variables = {}
        self._sensitive_env_variables = []
        self._master_password = None
        self._master_password_hash = None
        self._prompt_func = None  # function to use when prompting for input
        try:
            self._instance_data = data['instances'][name]
        except KeyError as err:
            raise EtoolkitInstanceError(f'Unknown instance "{name}"') from err
        if self._instance_data.get('ETOOLKIT_PARENT'):
            self._parent = EtoolkitInstance(
                self._instance_data['ETOOLKIT_PARENT'], data
            )
            self._raw_env_variables.update(self._parent.raw_env_variables)
            self._sensitive_env_variables.extend(
                self._parent.sensitive_env_variables
            )
        if self._instance_data.get('ETOOLKIT_SENSITIVE'):
            if not isinstance(self._instance_data['ETOOLKIT_SENSITIVE'], list):
                raise EtoolkitInstanceError(
                    '"ETOOLKIT_SENSITIVE" must be a list'
                )
            self._sensitive_env_variables.extend(
                self._instance_data['ETOOLKIT_SENSITIVE']
            )
        self._raw_env_variables.update(self._instance_data)
        # remove non env. variable data
        self._raw_env_variables.pop('ETOOLKIT_PARENT', None)
        self._raw_env_variables.pop('ETOOLKIT_SENSITIVE', None)
        if 'general' in data and 'MASTER_PASSWORD_HASH' in data['general']:
            self._master_password_hash = data['general'][
                'MASTER_PASSWORD_HASH'
            ]

    @property
    def master_password(self) -> str:
        """master_password-property"""
        if self._master_password is not None:
            return self._master_password
        return None if self._parent is None else self._parent.master_password

    @master_password.setter
    def master_password(self, value):
        """master_password-property setter"""
        self._master_password = value
        if self._parent is not None and self._parent.master_password is None:
            self._parent.master_password = value

    @property
    def master_password_hash(self) -> str:
        """master_password_hash-property"""
        return self._master_password_hash

    @master_password_hash.setter
    def master_password_hash(self, value):
        """master_password_hash-property setter"""
        self._master_password_hash = value

    @property
    def name(self) -> str:
        """name-property"""
        return self._name

    @property
    def prompt_func(self):
        """prompt_func-property"""
        return self._prompt_func

    @prompt_func.setter
    def prompt_func(self, value):
        """prompt_func-property setter"""
        self._prompt_func = value
        if self._parent is not None and self._parent.prompt_func is None:
            # will be set even if None
            self._parent.prompt_func = value

    @property
    def raw_env_variables(self) -> dict:
        """raw_env_variables-property"""
        return self._raw_env_variables

    @property
    def sensitive_env_variables(self) -> list:
        """sensitive_env_variables-property"""
        return self._sensitive_env_variables

    @staticmethod
    def confirm_password_prompt(
        password_hash: str = None, confirm: bool = True
    ) -> str:
        """
        Prompts for master password and then for confirmation if `confirm` True

        :param password_hash: Hash to compare with instead of confirm
        :type password_hash: str

        :param confirm: Confirm the password (and see if there is a match)
        :type confirm: bool

        :return: Password provided by the user
        :rtype: str
        """
        try:
            while True:
                pass1 = getpass.getpass('Type master password: ')
                if password_hash:
                    if EtoolkitInstance.password_matches(pass1, password_hash):
                        return pass1
                    print('Wrong password')
                    continue
                if confirm:
                    pass2 = getpass.getpass('Confirm master password: ')
                    if not pass1 or pass1 != pass2:
                        print('The passwords are either empty or do not match')
                        continue
                return pass1.strip()
        except Exception as e:
            raise EtoolkitInstanceError('Prompt error') from e

    @staticmethod
    def decrypt(password: str, edata: str) -> str:
        """
        Decrypts `edata` using `password`.

        `edata` is in the following format:
        enc-val$`version-num`$`bas64-salt`$`base64-encrypted_data`

        :param password: The password to generate the key with
        :type password: str

        :param edata: The data to be decrypted
        :type edata: str

        :return: The output string / decrypted data
        :rtype: str
        """
        # check for supported versions
        if not edata.startswith(('enc-val$1$', 'enc-val$2$')):
            raise EtoolkitInstanceError(
                f'Unsupported encryption format: {edata}'
            )
        try:
            salt, data = (base64.b64decode(t) for t in edata[10:].split('$'))
            nonce = salt[:12]
            aesgcm = AESGCM(
                hashlib.scrypt(
                    password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32
                )
            )

            # decrypt
            data = aesgcm.decrypt(nonce, data, salt)

            if edata.startswith('enc-val$2$'):
                # exclusively for the v2 data format:
                # padding_length_bytes(2 bytes) data padding (between 0 and 32)

                # extract padding_length_bytes
                if data[:2] == b'-1' or data[:2] == b'--':
                    data = data[2:]
                else:
                    data = data[2 : -int(data[:2].decode())]

            return data.decode()
        except InvalidTag as e:
            raise EtoolkitInstanceError(
                f'Invalid tag when decrypting: {edata}'
            ) from e
        except Exception as e:
            raise EtoolkitInstanceError(
                f'Error when decrypting: {edata}'
            ) from e

    @staticmethod
    def encrypt(password: str, data: str) -> str:
        """
        Encrypts `data` using `password`.

        Version 2 of the etoolkit encryption format

        The output string is in the following format:
        enc-val$`version-num`$`bas64-salt`$`base64-encrypted_data`

        :param password: The password to generate the key with
        :type password: str

        :param data: The data to be encrypted
        :type data: str

        :return: The output string
        :rtype: str
        """
        data_bytes = data.encode()
        if len(data_bytes) < MIN_ENCRYPTED_VALUE_LENGTH:
            padding_length = MIN_ENCRYPTED_VALUE_LENGTH - len(data_bytes)
            rnd_bytes = os.urandom(32 + padding_length)
            salt = rnd_bytes[:32]
            aesgcm = AESGCM(
                hashlib.scrypt(
                    password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32
                )
            )
            nonce = rnd_bytes[:12]
            padding_bytes = rnd_bytes[32:]
            # padding_length_bytes is always 2 bytes
            padding_length_bytes = f'{padding_length:02d}'.encode()
            edata = aesgcm.encrypt(
                nonce, padding_length_bytes + data_bytes + padding_bytes, salt
            )
        else:
            salt = os.urandom(32)
            aesgcm = AESGCM(
                hashlib.scrypt(
                    password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32
                )
            )
            nonce = salt[:12]
            padding_length_bytes = b'-1'  # no padding used 2 bytes "sign"
            edata = aesgcm.encrypt(
                nonce, padding_length_bytes + data_bytes, salt
            )
        return (
            f'enc-val$2${base64.b64encode(salt).decode()}$'
            f'{base64.b64encode(edata).decode()}'
        )

    @staticmethod
    def get_new_password_hash(password: str) -> str:
        """
        Returns a complete password hash based on `password`

        This password hash is *not* used as a key when encrypting / decrypting
        but only for optional check if a correct master password is provided.

        :param password: The plaintext password
        :type password: str

        :return: The hashed version of `password`
        :rtype: str
        """
        hash_algo = 'sha256'
        iterations = 500000
        salt = os.urandom(32)
        key = hashlib.pbkdf2_hmac(
            hash_algo, password.encode('utf-8'), salt, iterations
        )
        return (
            f'pbkdf2_{hash_algo}${iterations}$'
            f'{base64.b64encode(salt).decode()}$'
            f'{base64.b64encode(key).decode()}'
        )

    @staticmethod
    def parse_value(value, macros: dict):
        """
        Returns the value with all macros replaced by their values

        If `value` is not of type 'str' simply return `value`

        :param value: A simple value
        :type value: object

        :param macros: Macros mapping
        :type macros: dict

        :return: New value with all macros replaced by their values
        :rtype: object
        """
        if not isinstance(value, str):
            return value
        for key, val in macros.items():
            value = value.replace(key, val)
        return value

    @staticmethod
    def password_matches(password: str, password_hash: str) -> bool:
        """
        Checks `password` agains s stored password hash

        Hash format: pbkdf2_hashalgo$ietarations$salt-base64$key-base64

        :param password: password
        :type password: str

        :param password_hash: The pbkdf2_hmac password hash
        :type password_hash: str

        :return: True if the password matches or password_hash is None,
        :rtype: bool
        """
        if password_hash is None:
            return True
        # format: pbkdf2_hashalgo$ietarations$salt-base64$key-base64
        try:
            tokens = password_hash.split('$')
            key = hashlib.pbkdf2_hmac(
                tokens[0].split('_')[1],
                password.encode('utf-8'),
                base64.b64decode(tokens[2]),
                int(tokens[1]),
            )
            return key == base64.b64decode(tokens[3])
        except Exception:
            return False

    @staticmethod
    def reencrypt(password: str, new_password: str, edata: str) -> str:
        """
        Re-encrypts `edata` using `password` and `new_password`.

        Version 2 of the etoolkit encryption format

        `edata` is in the following format:
        enc-val$`version-num`$`bas64-salt`$`base64-encrypted_data`

        :param password: The password to decrypt `edata` with
        :type password: str

        :param new_password: The password to re-encrypt the plain-text with
        :type new_password: str

        :param edata: The data to be re-encrypted
        :type edata: str

        :return: The new encrypted string string
        :rtype: str
        """
        return EtoolkitInstance.encrypt(
            new_password, EtoolkitInstance.decrypt(password, edata)
        )

    def env_to_str(self, env: dict) -> str:
        """
        Returns a printable str. representation of the environment dict

        :param env: The environment dict
        :type env: dict

        :return: Printable representation of the environment dict
        :rtype: str
        """
        env_str = ''
        for key, value in env.items():
            if key in self._sensitive_env_variables:
                env_str += f'{key}: ***{os.linesep}'
                continue
            env_str += f'{key}: {value}{os.linesep}'
        return env_str

    def get_environ(self) -> dict:
        """
        Generates a new environ dict

        :return: New environment dict with all macros replaced by their values
        :rtype: dict
        """
        macros = {
            '%h': os.path.expanduser('~'),
            '%i': self.name,
            '%u': getpass.getuser(),
        }
        new_env = {}
        for key, value in sorted(
            self._raw_env_variables.items(), key=lambda x: x[0]
        ):
            if not value:
                # perhaps unset instead of skipping?
                continue
            if isinstance(value, str) and '%p' in value:
                macros['%p'] = (
                    self._parent.get_environ().get(key, '')
                    if self._parent is not None
                    else ''
                )
            if isinstance(value, str) and value.startswith('enc-val$'):
                value = self._decrypt_value(value)
            if isinstance(value, str) and value.endswith(':'):
                # if 'value' ends with ':', append the existing value of
                # os.environ[key] after the value of 'value'
                new_env[key] = self.parse_value(
                    value, macros
                ) + os.environ.get(key, '')
            elif isinstance(value, str) and value.startswith(':'):
                # if 'value' starts with ':', append after the existing value
                # of os.environ[key]
                new_env[key] = os.environ.get(key, '') + self.parse_value(
                    value, macros
                )
            else:
                # completely overwrite the existing value of os.environ[key]
                new_env[key] = self.parse_value(value, macros)
        return new_env

    def get_full_name(self, delimiter: str = '') -> str:
        """
        Returns the entire instance inheritence path separated by `delimiter`

        The format is:
        `grandparent-name`<delimiter>`parent-name`<delimiter>`instance-name`

        :param delimiter: Delimiter to separate parent instance names by
        :type delimiter: str

        :return: Path in case this instance has parent, instance.name otherwise
        :rtype: str
        """
        if self._parent is None:
            return self.name
        return self._parent.get_full_name(delimiter) + delimiter + self.name

    def get_reencrypted_instance_data(
        self, new_password: str, password: str = None
    ) -> dict:
        """
        Returns new instance data (dict) containing new encrypted values

        Each encrypted value in this instance is decrypted using `password`
        and then encrypted again using `new_password`

        If `password` is None, master_password is not set earlier for this
        instance and 'ETOOLKIT_MASTER_PASSWORD' is not set,
        the prompt function will be called

        :param new_password: The password to reencrypt with
        :type new_password: str

        :param password: The password to decrypt current encrypted values with
        :type password: str or None

        :return: New instance data
        :rtype: dict
        """
        if password is None:
            password = self._master_password

        if password is None and self._prompt_func is None:
            password = os.environ.get('ETOOLKIT_MASTER_PASSWORD')
            if password is None:
                raise EtoolkitInstanceError(
                    'Neither password or prompt function set'
                )

        if password is None:
            password = self._prompt_func(
                self._master_password_hash, confirm=False
            )

        new_data = dict(self._instance_data)
        for key, value in self._instance_data.items():
            if isinstance(value, str) and value.startswith('enc-val$'):
                new_data[key] = self.reencrypt(password, new_password, value)

        return new_data

    def _decrypt_value(self, evalue: str) -> str:
        """
        Decrypts an encrypted value using the master password

        The method prompts for the master password when it encounters its
        first encrypted value since the creation of its EtoolkitInstance
        object

        `evalue` is in the following format:
        enc-val$`version-num`$`bas64-salt`$`base64-encrypted_data`

        :param evalue: Encrypted value to be decrypted
        :type evalue: str

        :return: Decrypted value
        :rtype: str
        """
        if self._master_password is None:
            if self._prompt_func is None:
                if (
                    mp_from_env := os.environ.get('ETOOLKIT_MASTER_PASSWORD')
                ) is None:
                    raise EtoolkitInstanceError(
                        'Neither password or prompt function set'
                    )
                self.master_password = mp_from_env
            else:
                # use master_password setter in order to propagate to parent
                self.master_password = self._prompt_func(
                    self._master_password_hash, confirm=False
                )
        return self.decrypt(self._master_password, evalue)
