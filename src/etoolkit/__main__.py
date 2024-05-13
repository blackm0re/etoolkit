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
"""
CLI entry point for the etoolkit package

Examples
--------
python -m etoolkit -h

python -m etoolkit -p

"""

import argparse
import errno
import getpass
import io
import json
import logging
import os
import subprocess
import sys

import etoolkit

DEFAULT_LOG_FORMAT = '%(levelname)s: %(message)s'
DEFAULT_LOG_LEVEL = logging.WARNING

logger = logging.getLogger(__name__)


class EtoolkitCLIHandler:
    """
    Helper class used for handleing the growing amount of arguments

    This class consists mostly of interactive methods and is not intended as
    a part of the etoolkit API
    """

    def __init__(self, args: argparse.Namespace, config_dict: dict):
        """
        :param args: The parsed argparse arguments sent by the caller
        :type args: argparse.Namespace

        :param config_dict: The config file structure
        :type config_dict: dict
        """
        self._args = args
        self._config_dict = config_dict

        self._password_hash = None
        if 'general' in config_dict:
            self._password_hash = config_dict['general'].get(
                'MASTER_PASSWORD_HASH'
            )

        self._password_from_env = os.environ.get('ETOOLKIT_MASTER_PASSWORD')

    def decrypt_value(self):
        """
        Interactive method for decrypting value(s)

        Prompts for master key password and then prompts for a value to decrypt

        The decrypted value is printed to stdout
        """
        pipe_input = None
        if not os.isatty(sys.stdin.fileno()):
            pipe_input = sys.stdin.read().strip()

        if (
            self._args.master_password_prompt
            or self._password_from_env is None
        ):
            password = self._password_prompt()
        else:
            password = self._password_from_env

        if pipe_input:
            # the input came from stdin. No need to prompt
            print(
                'Decrypted value: '
                f'{etoolkit.EtoolkitInstance.decrypt(password, pipe_input)}'
            )
            return
        while True:
            try:
                value = input('Value: ')
                print(
                    'Decrypted value: '
                    f'{etoolkit.EtoolkitInstance.decrypt(password, value)}'
                )
                if not self._args.multiple_values:
                    break
            except KeyboardInterrupt:
                print(os.linesep)
                break
        return

    def encrypt_value(self):
        """
        Interactive method for encrypting value(s)

        Prompts for master key password and then prompts for a value to encrypt

        The encrypted value is printed to stdout
        """
        pipe_input = None
        if not os.isatty(sys.stdin.fileno()):
            pipe_input = sys.stdin.read().strip()

        if (
            self._args.master_password_prompt
            or self._password_from_env is None
        ):
            password = self._password_prompt_confirm()
        else:
            password = self._password_from_env

        if pipe_input:
            # the input came from stdin. No need to prompt
            print(
                'Encrypted value: '
                f'{etoolkit.EtoolkitInstance.encrypt(password, pipe_input)}'
            )
            return

        while True:
            try:
                if self._args.echo:
                    value = input('Value: ')
                else:
                    value = getpass.getpass('Value: ')
                print(
                    'Encrypted value: '
                    f'{etoolkit.EtoolkitInstance.encrypt(password, value)}'
                )
                if not self._args.multiple_values:
                    break
            except KeyboardInterrupt:
                print(os.linesep)
                break
        return

    def generate_master_password_hash(self):
        """
        Interactive method for generating password hash

        Prompts for master key password and then for confirmation

        The generated hash is printed to stdout
        """
        phash = etoolkit.EtoolkitInstance.get_new_password_hash(
            etoolkit.EtoolkitInstance.confirm_password_prompt()
        )
        print(f'Master password hash: {phash}')

    def list(self):
        """Lists all instances defined in the config file"""

        for instance_name in sorted(
            filter(
                lambda s: not s.startswith('_'),
                self._config_dict.get('instances', {}).keys(),
            )
        ):
            print(instance_name)

    def load_instance(self):
        """Loads a single specified instance from the config file"""

        inst = etoolkit.EtoolkitInstance(
            self._args.instance, self._config_dict
        )

        if (
            self._args.master_password_prompt
            or self._password_from_env is None
        ):
            inst.prompt_func = (
                etoolkit.EtoolkitInstance.confirm_password_prompt
            )

        env = inst.get_environ()

        if self._args.dump_output:
            print(inst.env_to_str(env))

        os.environ.update(env)

        if self._args.spawn:
            subprocess.run(self._args.spawn.split(), check=False)
        else:
            subprocess.run(
                os.environ.get('SHELL', 'bash').split(), check=False
            )

    def reencrypt(self):
        """
        Interactive method that prints new configuration data (JSON) to stdout

        Prompts for master key password and then for a new password,
        which may be the same as the current password

        All existing encrypted values are decrypted using the current password
        and then encrypted with the new password
        """
        print('(Current password) ', end='', flush=True)
        if (
            self._args.master_password_prompt
            or self._password_from_env is None
        ):
            password = self._password_prompt()
        else:
            password = self._password_from_env

        print('(New password) ', end='', flush=True)
        new_password = etoolkit.EtoolkitInstance.confirm_password_prompt()

        if self._args.reencrypt != 'all':
            # re-encrypt a single instance
            inst = etoolkit.EtoolkitInstance(
                self._args.reencrypt, self._config_dict
            )
            print(
                json.dumps(
                    inst.get_reencrypted_instance_data(new_password, password),
                    indent=4,
                )
            )
            return

        # re-encrypt all
        new_config_dict = dict(self._config_dict)
        if (
            'general' in new_config_dict
            and 'MASTER_PASSWORD_HASH' in new_config_dict['general']
        ):
            new_config_dict['general']['MASTER_PASSWORD_HASH'] = (
                etoolkit.EtoolkitInstance.get_new_password_hash(new_password)
            )

        for instance_name in self._config_dict['instances']:
            inst = etoolkit.EtoolkitInstance(instance_name, self._config_dict)
            new_config_dict['instances'][instance_name] = (
                inst.get_reencrypted_instance_data(new_password, password)
            )
        print(json.dumps(new_config_dict, indent=4))

    def _password_prompt(self) -> str:
        """
        Wrapper for EtoolkitInstance.confirm_password_prompt(confirm=False)
        """
        return etoolkit.EtoolkitInstance.confirm_password_prompt(
            self._password_hash, False
        )

    def _password_prompt_confirm(self) -> str:
        """
        Wrapper for EtoolkitInstance.confirm_password_prompt(confirm=True)
        """
        return etoolkit.EtoolkitInstance.confirm_password_prompt(
            self._password_hash
        )


def main(inargs=None):
    """main entry point"""

    parser = argparse.ArgumentParser(
        prog=__package__,
        epilog=(
            f'%(prog)s {etoolkit.__version__} by Simeon Simeonov '
            '(sgs @ LiberaChat)'
        ),
        description='The following options are available',
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        'instance',
        metavar='<instance>',
        nargs='?',
        type=str,
        help='The instance to be loaded',
    )
    group.add_argument(
        '-d',
        '--decrypt-value',
        dest='decrypt_value',
        action='store_true',
        required=False,
        help=(
            'Prompt for master password & value to decrypt, '
            'display the decrypted value and exit'
        ),
    )
    group.add_argument(
        '-e',
        '--encrypt-value',
        dest='encrypt_value',
        action='store_true',
        required=False,
        help=(
            'Prompt for master password & value to encrypt, '
            'display the encrypted value and exit'
        ),
    )
    group.add_argument(
        '-l',
        '--list',
        dest='list',
        action='store_true',
        required=False,
        help='List all defined instances',
    )
    group.add_argument(
        '-p',
        '--generate-master-password-hash',
        dest='password_hash',
        action='store_true',
        required=False,
        help='Prompt for master password, display the generated hash and exit',
    )
    group.add_argument(
        '-r',
        '--reencrypt',
        metavar='<instance | all>',
        type=str,
        default='',
        dest='reencrypt',
        required=False,
        help=(
            'Prompt for current master password, new master password and '
            're-encrypt either all encrypted values or only those for a '
            'given instance'
        ),
    )
    parser.add_argument(
        '-c',
        '--config-file',
        metavar='<path>',
        type=str,
        default=os.path.expanduser(
            os.environ.get('ETOOLKIT_CONFIG', '~/.etoolkit.json')
        ),
        dest='config_file',
        help='JSON config file (default: ~/.etoolkit.json)',
    )
    parser.add_argument(
        '-E',
        '--echo',
        dest='echo',
        action='store_true',
        help='Display the value to be encrypted (used together with -e)',
    )
    parser.add_argument(
        '-m',
        '--multiple-values',
        dest='multiple_values',
        action='store_true',
        help=(
            'Prompt for more than one value when '
            'encrypting / decrypting until terminated '
            '(Ctrl+C) (used together with -d / -e)'
        ),
    )
    parser.add_argument(
        '-P',
        '--master-password-prompt',
        dest='master_password_prompt',
        action='store_true',
        help=(
            'Force prompt for the master password even if the env. variable '
            '"ETOOLKIT_MASTER_PASSWORD" is set'
        ),
    )
    parser.add_argument(
        '-q',
        '--no-output',
        dest='dump_output',
        action='store_false',
        default=True,
        help='Do not print environment variables to stdout',
    )
    parser.add_argument(
        '-s',
        '--spawn',
        metavar='<path>',
        type=str,
        default='',
        dest='spawn',
        help='Spawn another process than $SHELL',
    )
    parser.add_argument(
        '-v',
        '--version',
        action='version',
        version=f'%(prog)s {etoolkit.__version__}',
        help='Display program-version and exit',
    )
    args = parser.parse_args(inargs)
    try:
        with io.open(args.config_file, encoding='utf-8') as fp:
            config_dict = json.load(fp)
    except FileNotFoundError as err:
        # do not raise exception if config-file is missing for:
        # - decrypting value
        # - encrypting value
        # - password hash generation
        if args.password_hash or args.decrypt_value or args.encrypt_value:
            logger.warning(
                'Configuration file %s is missing, although not required '
                'by the provided parameters',
                args.config_file,
            )
            config_dict = {}
        else:
            logger.error('Configuration file %s is missing', args.config_file)
            raise SystemExit(errno.EIO) from err
    except Exception as exp:
        logger.exception('Unable to parse %r', args.config_file)
        raise SystemExit(errno.EIO) from exp
    try:
        etoolkit_cli_handler = EtoolkitCLIHandler(args, config_dict)
        if args.decrypt_value:
            etoolkit_cli_handler.decrypt_value()
            sys.exit(0)
        if args.encrypt_value:
            etoolkit_cli_handler.encrypt_value()
            sys.exit(0)
        if args.password_hash:
            etoolkit_cli_handler.generate_master_password_hash()
            sys.exit(0)
        if args.list:
            etoolkit_cli_handler.list()
            sys.exit(0)
        if args.reencrypt:
            etoolkit_cli_handler.reencrypt()
            sys.exit(0)

        etoolkit_cli_handler.load_instance()
    except KeyboardInterrupt:
        logger.debug('KeyboardInterrupt')
        print(os.linesep)
        sys.exit(0)
    except etoolkit.EtoolkitInstanceError as err:
        logger.error('EtoolkitInstanceError: %s', err)
        sys.exit(1)
    except subprocess.CalledProcessError as err:
        logger.error('Unable to spawn shell process: %s', err)
        sys.exit(1)
    except Exception:
        logger.exception('Unexpected exception')
        sys.exit(1)


if __name__ == '__main__':
    logging.basicConfig(level=DEFAULT_LOG_LEVEL, format=DEFAULT_LOG_FORMAT)
    main()
