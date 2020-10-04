# make various boundary files

psldns:	public_suffix_list.dat.txt vanity.txt
	./psltodns.py --shadow --vanity vanity.txt public_suffix_list.dat.txt > $@

pslupload::
	./psltodns.py --shadow --vanity vanity.txt --upload public_suffix_list.dat.txt
