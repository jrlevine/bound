#!/usr/bin/env python3

import argparse
import io
import sys
import json
import requests

parser = argparse.ArgumentParser(description='Turn PSL into DNS')
parser.add_argument('-d', action='store_true', help="debug info");
parser.add_argument('--pub', action='store_true', help="public only");
parser.add_argument('--upload', action='store_true', help="store into DNS zone");
parser.add_argument('--config', type=str, help="config file", default='pslconfig.txt');
parser.add_argument('file', type=str, help="Input file");
args = parser.parse_args();

debug = args.d

if args.upload:
    # write to a string then store in DNS via API
    with open(args.config, "r") as f:
        config = dict( l.strip().split(maxsplit=1) for l in f if l[:1] not in ('#','\n','') )
    fo = io.StringIO()
else:
    fo = sys.stdout

root = {}
with open(args.file) as f:
    for line in f:
        exclude = False

        if args.pub and 'END ICANN DOMAINS' in line:
            print("; only public names included", file=fo)
            break

        if line.startswith('//') or line.strip() == '':
            continue

        if line.startswith('!'):           # exception
            exclude = True
            line = line[1:]
        d = tuple(reversed(line.strip().encode('idna').decode().split('.')))
        p = root
        for l in d:                     # walk up the labels
            if l not in p:
                p[l] = dict()
            p = p[l]
        p['!'] = exclude

def donode(name, p, skip=None, pbound=None):
    exclude = None
    bound = False
    if pbound:
        if skip:
            me = f"{name}.{skip}.{pbound}"
            label = f"{name}.{skip}._bound.{pbound}"
        else:
            me = f"{name}.{pbound}"
            label = f"{name}._bound.{pbound}"
    else:
        me = name
        label = f"_bound.{name}"

    if '!' in p:
        exclude = p['!']
        bound = True

    nl = [ n for n in iter(p) if n != '!' ]
    nl.sort()
    if bound:
        if name == '*':
            if debug:
                print(f";* {label} {skip} {pbound}", file=fo)
            print(f'{label} IN TXT "bound=1 . . {me}"', file=fo)
        else:
            if debug:
                print(f"; {label} {skip} {pbound}", file=fo)
            if exclude:
                print(f'{label} IN TXT "bound=1  NOBOUND . {me}"', file=fo)
                print(f'*.{label} IN TXT "bound=1  NOBOUND . {me}"', file=fo)
            else:
                print(f'*.{label} IN TXT "bound=1  . . {me}"', file=fo)
        for n in nl:
            donode(n, p[n], None, me)
    else:
        if debug:
            print(f';x {label} {skip} {pbound}', file=fo)
        if pbound:
            if skip:
                nskip = f"{name}.{skip}"
            else:
                nskip = name
        else:
            pbound = name
            nskip = None
        for n in nl:
            donode(n, p[n], nskip, pbound)

#if debug:
#    print(root)

for n in iter(root):
    donode(n, root[n])

if args.upload:
    d = {
        "request": "full",
        "domain": config['zone'],
        "bextra": fo.getvalue(),
        'apikey': config['apikey']
    }
    r = requests.post(config['url'], json=d)
    if r.status_code == 200:
        print("loaded to",config['zone'])
    else:
        print("zone update failed code ",r.status_code)
        exit(1)
