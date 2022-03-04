# etoolkit
# Copyright (C) 2021-2022 Simeon Simeonov

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

Examples:
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
import sys

import etoolkit

DEFAULT_LOG_FORMAT = "%(levelname)s: %(message)s"
DEFAULT_LOG_LEVEL = logging.WARNING

logger = logging.getLogger(__name__)


def decrypt_value(args: argparse.Namespace, config: dict):
    """
    Interactive function for decrypting value(s)

    Prompts for master key password and then prompts for a value to decrypt

    The decrypted value is printed to stdout

    :param args: The arguments sent by the caller
    :type args: arparse.Namespace

    :param config: The config dict sent by the caller
    :type config: dict
    """
    password_hash = None
    pipe_input = None
    if not os.isatty(sys.stdin.fileno()):
        pipe_input = sys.stdin.read().strip()
    if 'general' in config:
        password_hash = config['general'].get('MASTER_PASSWORD_HASH')

    if (
        args.master_password_prompt
        or os.environ.get('ETOOLKIT_MASTER_PASSWORD') is None
    ):
        password = etoolkit.EtoolkitInstance.confirm_password_prompt(
            password_hash, False
        )
    else:
        password = os.environ.get('ETOOLKIT_MASTER_PASSWORD')

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
            if not args.multiple_values:
                break
        except KeyboardInterrupt:
            print(os.linesep)
            break
    return


def encrypt_value(args: argparse.Namespace, config: dict):
    """
    Interactive function for encrypting value(s)

    Prompts for master key password and then prompts for a value to encrypt

    The encrypted value is printed to stdout

    :param args: The arguments sent by the caller
    :type args: arparse.Namespace

    :param config: The config dict sent by the caller
    :type config: dict
    """
    password_hash = None
    pipe_input = None
    if not os.isatty(sys.stdin.fileno()):
        pipe_input = sys.stdin.read().strip()
    if 'general' in config:
        password_hash = config['general'].get('MASTER_PASSWORD_HASH')

    if (
        args.master_password_prompt
        or os.environ.get('ETOOLKIT_MASTER_PASSWORD') is None
    ):
        password = etoolkit.EtoolkitInstance.confirm_password_prompt(
            password_hash
        )
    else:
        password = os.environ.get('ETOOLKIT_MASTER_PASSWORD')

    if pipe_input:
        # the input came from stdin. No need to prompt
        print(
            'Encrypted value: '
            f'{etoolkit.EtoolkitInstance.encrypt(password, pipe_input)}'
        )
        return
    while True:
        try:
            if args.echo:
                value = input('Value: ')
            else:
                value = getpass.getpass('Value: ')
            print(
                'Encrypted value: '
                f'{etoolkit.EtoolkitInstance.encrypt(password, value)}'
            )
            if not args.multiple_values:
                break
        except KeyboardInterrupt:
            print(os.linesep)
            break
    return


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
        with io.open(args.config_file, 'r', encoding='utf-8') as fp:
            config_dict = json.load(fp)
    except FileNotFoundError as e:
        # do not raise exception if config-file is missing for:
        # - decrypting value
        # - encrypting value
        # - password hash generation
        if args.password_hash or args.decrypt_value or args.encrypt_value:
            logger.warning(
                "Configuration file %s is missing, although not required "
                "by the provided parameters",
                args.config_file,
            )
            config_dict = {}
        else:
            logger.error("Configuration file %s is missing", args.config_file)
            raise SystemExit(errno.EIO) from e
    except Exception as e:
        logger.error("Unable to parse %r: %s", args.config_file, e)
        raise SystemExit(errno.EIO) from e
    try:
        if args.decrypt_value:
            decrypt_value(args, config_dict)
            sys.exit(0)
        if args.encrypt_value:
            encrypt_value(args, config_dict)
            sys.exit(0)
        if args.password_hash:
            master_password = (
                etoolkit.EtoolkitInstance.confirm_password_prompt()
            )
            phash = etoolkit.EtoolkitInstance.get_new_password_hash(
                master_password
            )
            print(f'Master password hash: {phash}')
            sys.exit(0)
        if args.list:
            for instance_name in sorted(
                config_dict.get('instances', {}).keys()
            ):
                print(instance_name)
            sys.exit(0)

        inst = etoolkit.EtoolkitInstance(args.instance, config_dict)
        inst.prompt_func = etoolkit.EtoolkitInstance.confirm_password_prompt
        env = inst.get_environ()

        if args.dump_output:
            inst.dump_env(env)

        os.environ.update(env)

        if args.spawn:
            os.system(args.spawn)
        else:
            os.system(os.getenv('SHELL', 'bash'))
    except KeyboardInterrupt:
        logger.debug('KeyboardInterrupt')
        print(os.linesep)
        sys.exit(0)
    except etoolkit.EtoolkitInstanceError as e:
        logger.error('EtoolkitInstanceError: %s', e)
        sys.exit(1)
    except Exception as e:
        logger.error('Unexpected exception: %s', e)
        sys.exit(1)


if __name__ == '__main__':
    logging.basicConfig(level=DEFAULT_LOG_LEVEL, format=DEFAULT_LOG_FORMAT)
    main()
