#!/usr/bin/env python3

import argparse
import io
import sys
import json
import requests

parser = argparse.ArgumentParser(description='Turn PSL into DNS')
parser.add_argument('-d', action='store_true', help="debug info");
parser.add_argument('--dump', action='store_true', help="dump tree of names");
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
# make the file into a tree of dicts
# each dict is a name, if it had a PSL line the dict has a '!' entry
# saying whether it was regular or excluded

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


        domain = line.strip().encode('idna').decode()
        d = tuple(reversed(domain.split('.')))

        p = root

        for l in d:                     # walk up the labels
            if l not in p:
                p[l] = dict()
            p = p[l]
        p['!'] = exclude

def donode(label, p, parent=[], pbound=0):
    """
    process a node recursively
    label: current name
    p: name's dict of subnames
    parent: list of parent labels
    pbound: number of labels in previous boundary
    """

    name =  [label]+parent              # name as a list
    me = ".".join(name)                 # name as a string
    lbound = 1+pbound

    # label for this boundary
    if label == '*':        # don't do double star
        bname = name
    else:
        bname = ['*']+name
    blabel = ".".join(bname[:-lbound]) + "._bound." + ".".join(bname[-lbound:])

    exclude = None
    bound = False

    if '!' in p:
        exclude = p['!']
        bound = True

    # next bound
    if bound:
        if debug:
            print(f"; {name} {exclude} {pbound}", file=fo)
        if exclude:
            print(f'{blabel} IN TXT "bound=1 NOBOUND . {me}"', file=fo)
        else:
            print(f'{blabel} IN TXT "bound=1 . . {me}"', file=fo)
        nextbound = len(name)
    else:
        nextbound = pbound

    # now recurse
    ll = [ n for n in iter(p) if n != '!' ] # label list
    ll.sort()

    for nl in ll:
        donode(nl, p[nl], name, nextbound)

if args.dump:
    print(root)

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
