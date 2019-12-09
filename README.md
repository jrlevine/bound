# bound
DNS boundary zone creation and lookup

This is intended to implement <https://datatracker.ietf.org/doc/draft-levine-dbound-dns/>.

psltodns.py reads a file in PSL format and creates DNS records.  It also can read a list
of single registrant vanity TLDs (aka brand TLDs) and adjust the DNS records appropriately.

boundchk.py takes domain names and reports boundaries under them and their organizational domains, either as a command line program or a callable function

For testing, the zone bound.services.net has a translated version of the public part of
the Mozilla PSL annotated with the single registrant TLDs in vanity.txt.

