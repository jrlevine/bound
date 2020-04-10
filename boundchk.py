#!/usr/bin/env python3

import dns.resolver

class Boundchk:
    def __init__(self, base=None, debug=False):
        self.base = base
        self.debug = debug
        self.res = dns.resolver.Resolver()

    def check(self, name):
        """
        check boundaries for name
        returns ([bounds], orgdomain)
        """

        nl = name.split('.')

        spoint = 1                          # split point for _bound
        opoint = 0                          # org domain boundary
        isvanity = False
        bounds = []

        while spoint < len(nl):             # avoid endless loop
            a = nl[:-spoint]
            b = nl[-spoint:]
            p = f"{'.'.join(a)}._bound.{'.'.join(b)}.{self.base}."
            if self.debug:
                print("try", spoint, p)
            try:
                q = self.res.query(p, 'txt')
            except (dns.resolver.NXDOMAIN, dns.exception.Timeout, dns.resolver.NoAnswer) as err:
                if self.debug:
                    print("failed", err)
                break

            txtrec = None
            for qr in q:
                t = tuple(x.decode() for x in qr.strings)
                if len(t) >= 4 and t[0] == 'bound=1':
                    txtrec = t
                    break

            if not txtrec:                  # no more
                break

            (tag, fl, ty, dom) = txtrec[:4] # allow trailing junk
            if self.debug:
                print("got",tag,fl,ty,dom)

            if fl == '.':
                flags = ()
            else:
                flags = set(fl.split(','))
            if ty == '.':
                types = ()
            else:
                types = set(ty.split(','))

            if dom == '.':
                nspoint = 1
                isvanity = True
            else:
                nspoint = 1+len(dom.split('.'))

            if 'NOBOUND' not in flags and nspoint <= len(nl):
                if nspoint == 1:        # vanity
                    d = "."
                else:
                    d = '.'.join(nl[1-nspoint:])
                if self.debug:
                    print("bound at",nspoint,d)
                bounds.append(d)
                opoint = nspoint

            if nspoint == spoint:
                if self.debug:
                    print("done", spoint)
                break
            spoint = nspoint

        if opoint:
            orgdomain = '.'.join(nl[-opoint:])
        else:
            orgdomain = None
        return (bounds, orgdomain)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Check DNS boundary')
    parser.add_argument('-d', action='store_true', help="debug info");
    parser.add_argument('--base', type=str, help="base domain", default='bound.services.net');
    parser.add_argument('names', type=str, nargs='+', help="Names to check");
    args = parser.parse_args();

    b = Boundchk(base=args.base, debug=args.d)
    for name in args.names:
        (bl, od) = b.check(name)

        print("Boundaries for",name)
        for bb in bl:
            print("  ",bb)
        print("Org domain",od)
        print()
