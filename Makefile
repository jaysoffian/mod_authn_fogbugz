.libs/mod_authn_fogbugz.so: mod_authn_fogbugz.c
	/usr/sbin/apxs -a -c $<

install:
	sudo /usr/sbin/apxs -i -a -c mod_authn_fogbugz.c
