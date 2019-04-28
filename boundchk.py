#!/usr/bin/env python3

import argparse
import sys
import dns.resolver

parser = argparse.ArgumentParser(description='Check DNS boundary')
parser.add_argument('-d', action='store_true', help="debug info");
parser.add_argument('--base', type=str, help="base domain", default='bound.services.net');
parser.add_argument('names', type=str, nargs='+', help="Names to check");
args = parser.parse_args();

debug = args.d
base = args.base

res = dns.resolver.Resolver()

for name in args.names:
    if debug:
        print("check",name)
    nl = name.split('.')

    spoint = 1                          # split point for _bound
    opoint = 0                          # org domain boundary
    bounds = []

    while spoint < len(nl):             # avoid endless loop
        a = nl[:-spoint]
        b = nl[-spoint:]
        p = f"{'.'.join(a)}._bound.{'.'.join(b)}.{base}."
        if debug:
            print("try", spoint, p)
        try:
            q = res.query(p, 'txt')
        except (dns.resolver.NXDOMAIN, dns.exception.Timeout, dns.resolver.NoAnswer) as err:
            if debug:
                print("failed", err)
            break
        txtrec = None
        for qr in q:
            t = "".join(x.decode() for x in qr.strings)
            if t.startswith('bound=1'):
                txtrec = t
                break

        if not txtrec:                  # no more
            break

        (tag, fl, ty, dom) = txtrec.split()
        if debug:
            print("got",tag,fl,ty,dom)

        if fl == '.':
            flags = ()
        else:
            flags = set(fl.split(','))
        if ty == '.':
            types = ()
        else:
            types = set(ty.split(','))

        nspoint = 1+len(dom.split('.'))

        if 'NOBOUND' not in flags and nspoint <= len(nl):
            d = '.'.join(nl[1-nspoint:])
            if debug:
                print("bound at",d)
            bounds.append(d)
            opoint = nspoint

        if nspoint == spoint:
            if debug:
                print("done", spoint)
            break
        spoint = nspoint

    print("suffixes for",name)
    for b in bounds:
        print("  ",b)

    if opoint:
        print("org domain for",name,"is", '.'.join(nl[-opoint-1:]))
    else:
        print("no org domain for",name)
