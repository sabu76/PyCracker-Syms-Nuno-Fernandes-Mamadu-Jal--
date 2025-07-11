 #!/usr/bin/env python3
"""
vamos agora fazer um programa para detectar ficheiros com 'semelhança'. através  da linha de 
comando, o seu programa recebe um caminho para uma directorio o 'disco' essa directoria procurando
por ficheiros que apresentem uma determinada semelhança. no final exibe uma listagem com os grupos 
de ficheiros semelhantes.


(c) Mamadu Aliu Djalo
(c) Nuno Fernandes
"""

import os
import pprint
import re
import hashlib

 
from docopt import docopt


def main():
    doc ="""
Retuns all duplicate files in the given folder

Usage:
    sym.py [-c] [-n] [-e] [-r PATTERN] [DIR_PATH]

options:
     DIR_PATH                       start directory [default: .]
    -c, --contents                  search files with the sane binary content
    -n, --name                      search files with the sane name
    -e, --extension                 search files whith the sane extension
    -r PATTERN, --regex=PATTERN     search files using a regular expression
"""
    args =docopt(doc)
     #print(args)

    dir_path = '.' if args['DIR_PATH'] is None else args['DIR_PATH']

    if args['--contents']:
        print("BY CONTENTS")
        show_groups(group_files_by_contents(dir_path))
        print("_____________________________________________")
#:
    if args['--name']:
        print("BY NAME")
        show_groups(group_files_by_name(dir_path))
        print("_____________________________________________")
    
    print()

    if args['--extension']:
        print("BY EXTENSION")
        show_groups(group_files_by_extension(dir_path)) 
        print("_____________________________________________")

print()

if args['--regex']:
   print("BY REGEX")
   regex = args['--regex']
   show_groups({regex:search_files_by_regex(dir_path,regex)}) 
   print("_____________________________________________")
#:
        
def show_groups(duplicates: dict):
    for filename,paths in duplicates.items():
        if len(paths)> 1: 
          print(filename)
        for path in paths:
            print(f'   {path}')
        print()
#:
def group_files_by_contents(dir_path)-> dict [str, list]:
    groups ={}
    for curr_dir, _,filename in os.walk(dir_path):
        for filename in filename:
            filepath = os.path.join(curr_dir, filename)
            hash = hashlib.file_digest(open(filepath, 'rb'),'md5').hexdigest()
            if hash not in groups:
                groups[hash]=[]
            groups[hash].append(os.path.join(curr_dir.filename))
    return groups
#:
def group_files_by_name(dir_path)-> dict [str, list]:
    groups ={}
    for curr_dir, _,filename in os.walk(dir_path):
        for filename in filename:
            if filename not in groups:
                groups[filename]=[]
            groups[filename].append(os.path.join(curr_dir.filename))
    return groups

def group_files_by_extension(dir_path)-> dict[str,list[str]]:
    groups ={}
    for curr_dir, _,filename in os.walk(dir_path):
        for filename in filename:
            _,ext = os.path.splitext(filename)
            if filename not in groups:
                groups[ext]=[]
            groups[ext].append(os.path.join(curr_dir.filename))
    return groups
#:

def search_files_by_regex(dir_path, regex: str)-> list[str]:
    found_filenames=[]
    for curr_dir, _,filenames in os.walk(dir_path):
        for filename in filenames:
            if re.search(regex, filename):
                found_filenames.append(os.path.join(curr_dir, filename))
        return found_filenames
#:

if __name__== '__main__':
     main()