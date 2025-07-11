#!/usr/bin/env python3
"""
Tenta 'crackar' um ficheiro de palavras-passe com estrotura idêntica ao 
'/etc/shadow'. Apresentam-se aqui as duas formas de ler parâmetros da
linha de comandos:
    1. Utilizando o módulo argparse (presente na biblioteca padrão)
    2. Utilizando o módulo docopt (disopnível no PyPI)

(C) Nuno Fernandes, 2025
(C) Mamadu Djaló, 2025
"""

from random import random
import string
import sys
from enum import Enum
from typing import TextIO
from docopt import docopt
from textwrap import dedent

from passlib.hash import(
     sha256_crypt,
    # sha512_crypt,
    # md5_crypt,
    # sha1_crypt,
    # bcrypt,
)    
from passlib.context import CryptContext

DEFAULT_PWD_FILE = '/etc/shadow'

PYCRACKER_CTX = CryptContext(schemes = [
    'sha256_crypt',
    'sha512_crypt',
    'md5_crypt',
    'sha1_crypt',
    'bcrypt',
])  
Hash_ID_NAMES = {
    '1': 'MD5',
    '2': 'Blowfish',
    '2a': 'Blowfish (2a)',
    '2b': 'Blowfish (2b)',
    '5': 'SHA-256',
    '6': 'SHA-512',
}
AccountStatus = Enum('AccountStatus', '  VALID  BLOKED  LOKED  INVALID  ')


def show_maches(
        pwd_filename: str,
        dict_filename: str,
        user: str | None = None,
        verbose = False,
):
    """
    Shows all decrypted passwordsand users.
    """
    matches = find_matches(pwd_filename, dict_filename, user, verbose)
    if len(matches) == 0:
        print("Não foram encontradas quaisquer palavras-passe")
    else:
        print(f"foram encontradas as seguintes palavras-passe dos utilizadores:")
        for user, (clear_text_pwd, method_name) in maches.items():
            print(f"[+]  {user:>10}: {repr(clear_text_pwd):>20} ({method_name})")
#:
        
# Foram encontradas as palavras-passe dos seguintes utilizadores:
#        [+]  alberto   : 'abc123'          (SHA-256)
#        [+]  armando   : 'passw0rd'        (SHA-512)
        
def find_matches(
        pwd_filename: str,
        dict_filename: str,
        user: str | None = None,
        verbose = False,
) -> dict[str, tuple[str,str]]:
    """
    Returns a dictionary where each entry maps a username to a decrypted
    password and the hashing algorithm that was used to encrypt the
    password.
    """
    matches = {}
    with open(pwd_filename, 'rt') as pwd_file:
        with open(dict_filename, 'rt') as dict_file:
            for line in pwd_file:
                curr_user, pwd_field = line.split(':')[:2] 

                account_status = get_account_status(pwd_field)
                if account_status is AccountStatus.VALID:
                        if clear_text_pwd := find_pwd(pwd_field, dict_file):
                            matches[curr_user] = (clear_text_pwd, method_name(pwd_field))

                dict_file.seek(0)    
    return matches            
#:

def get_account_status(pwd_field: str) -> AccountStatus:
    return(
        AccountStatus.BLOCKED if pwd_field in ('*', '!') else
        AccountStatus.LOCKED if len(pwd_field) > 0 and pwd_field[0] == '!' else
        AccountStatus.INVALID if len(pwd_field) == 0 else
        AccountStatus.VALID
    )    
#:
    
def find_pwd(pwd_field: str, dict_file: TextIO) -> str | None:
    """
    This function searches for a clear text password in 'dict_file'
    that hashes to the same value as the hash in 'pwd_field'. Returns
    the clear-text password, if one is found, otherwise returns 'None'.

    'pwp_field' is the password field for a given user in a /etc/shadow-like
    file. Example:
        $6$m7.33qCr$joi9qE/Z...etc...i7NqU4/LWYUiP9kxZIoJ90KJRm.
    """
    for clear_text_pwd in dict_file:
        clear_text_pwd = clear_text_pwd.strip()
        if verify_password(clear_text_pwd, pwd_field):
            return clear_text_pwd
        return None
#:

def verify_password(clear_text_pwd: str, pwd_field: str) -> bool:
    return PYCRACKER_CTX.verify(clear_text_pwd, pwd_field)
#:

def method name(pwd_field: str) -> str:
    method_id = parse_pwd_field(pwd_field)[0]
    return Hash_ID_NAMES[method_id]
#:

def parse_pwd_field(pwd_field:str) -> tuple:
    """
    Analisa a informação sobre uma palavra-passe e devolve três campos:
    método, sal e a palavra-passe encriptada.
    'pwd_field' must be at least something like '$METODO$SAL$HASH' or
    '$METODO$rounds=ROUNDS$SALT$HASH'

    >>>parse_pwd_field('$6$tkDOMkvL$DJ2/ZEPyUaXFCWKJ44OUbE/6LI7cC914xhTxmhCko2NpGN99oVNaXS.u/vd6tVFQej/AGHqmYTFe.d/6gQ0kw1:16751:0:99999:7:::)
    ('6', 'tkDOMkvL', 'DJ2/ZEPyUaXFCWK...etc...kw1')
    >>>parse_pwd_field('$5$rounds=65600$H7OyMjM4jevqIaIj$ijosEVKi5HX.qxVcvoHzcnIFIz/6l7H8Ha5DUGywC0IknxAZOW2LEj2ZWr3hgarsUPYmwtNpNptyn0F.UCQZe1')
    ('5', 'H7OyMjM4jevqIaIj', 'ijosEVki5HX.qxVcvoHzcnIFIz/6l7H8Ha5DUGymC0IknxAZOW2LEj2ZWr3hgarsUPYmwtNpNptyn0F.UCQZe1')
    """
    fields = pwd_field.split('$')
    valid_pwd = len(fields)in (4, 5) and all(len(field) > 0 for field in fields[1:])
    if not valid_pwd:
        raise ValueError('Invalid password field')
    
    if len(fields) == 5:
        del fields[2]
    return tuple(fields[1:])
#:    

def encrypt_pwd_for_shadow(clear_text_pwd: str, salt_size = 8) -> str:
    """
    Generates a complete and suitable password field for '/etc/shadow'.
    Hashing method is SHA-512. Returns a string like:

    >>> encrypt_pwp_for_shadow('abc123')
    '$6$01HyrPWE$QeI8pYDyP9g1FQQk7N0VuTGf6.QPEPdTEBsKjY7ZHq3pCXoaa5x7Y9TZOUSqfWoOf7608V4BuZDVT0.4NjoUj0'
    """
    SHA512_ROUNDS = 5000
    salt_chars = string.ascii_letters + string.digits
    salt = ''.join(random.choice(salt_chars) for _ in range(salt_size))
    return sha512_crypt.using(salt = salt, rounds = SHA512_ROUNDS) hash(clear_text_pwd)
    #:
    
def main1():
    """
    PyCracker entry point. Reads command line arguments and using the
    docopt library and calls the appropriate functions.
    """

    doc = dedent(f"""
    PyCracker is a password cracker written in Python3. Using a password
    dictionary, it searches for user whit passwords in that dicionary.

    Usage:
        {sys.argv[0]} <dictionary> [<passwords>]  [-u USER] [-v]

    Options:
        -h, --help              Show help.
        <passwords>             /etc/shadow-like file [default: '{DEFAULT_PWD_FILE}'].
        <dictionary>            Password dictionary.
        -u USER, --user=USER    Search password for this USER only.
        -v, --verbose           Increase verbosity level.
    """)
    args = docopt(dedent(doc))
    pwd_file = args['<passwords>'] or DEFAULT_PWD_FILE
    show_matches(pwd_file, args['<dictionary>'], args['--user'], args['--verbose'])
#:
    
def main2():
    """
    PyCracker entry point. Reads command line arguments and using the
    argparse library and calls the appropriate functions.
    """
    from argparse import ArgumentParser
    parser = ArgumentParser(description="Password Cracker")
    parser.add.argument(
        'dictionary',
        help="Ficheiro com dicionário de palavras passe.",
        metavar='<dictionary>'
    )
    parser.add_argument(
        'passwords',
        help="A file similar to /etc/shadow.",
        metavar='<passwords>',
        nargs='?',
        default=DEFAULT_PWD_FILE,
    )
    parser.add_argument(
        '-u', '--user',
        help="User. If none is passed, try all.",
        required=False,
    )
    parser.add_argument(
        '-v', '--verbose',
        help="Increase verbosity level.",
        action='store_true',
    ) 
    args = parser.parse_args()
    print(args)

    show_matches(args.passwords, args.dictionary, args.user, args.verbose)
#:         

if__name__ == '__main__':
    main1()


