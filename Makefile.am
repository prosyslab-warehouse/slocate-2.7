
bin_PROGRAMS = slocate

if SL_FTS
slocate_SOURCES = main.c link.c misc.c sl_fts.c
else
slocate_SOURCES = main.c link.c misc.c
endif

INSTALL = install -c
#CFLAGS = -g3

install-exec-hook:
if FREEBSD
	-/usr/sbin/pw groupadd slocate	
else
	-/usr/sbin/groupadd slocate
endif	
	$(INSTALL) -d $(DESTDIR)$(datadir)/slocate
	chown root.slocate $(DESTDIR)$(bindir)/slocate
	chown root.slocate $(DESTDIR)$(datadir)/slocate
	chmod 2755 $(DESTDIR)$(bindir)/slocate
	chmod 0750 $(DESTDIR)$(datadir)/slocate
	-ln -f -s $(DESTDIR)$(bindir)/slocate $(DESTDIR)$(bindir)/updatedb
	-ln -f -s $(DESTDIR)$(bindir)/slocate $(DESTDIR)$(bindir)/locate
if CRON
	$(mkinstalldirs) $(DESTDIR)/etc/cron.daily/
	$(INSTALL) -m 755 slocate.cron $(DESTDIR)/etc/cron.daily/slocate
else
	./install-cron.sh
	
endif
	$(INSTALL) -m 644 doc/slocate.1.linux.gz $(DESTDIR)$(mandir)/man1/slocate.1.gz
	$(INSTALL) -m 644 doc/updatedb.1.gz $(DESTDIR)$(mandir)/man1/updatedb.1.gz
	-ln -f -s $(DESTDIR)$(mandir)/man1/slocate.1.gz $(DESTDIR)$(mandir)/man1/locate.1.gz

uninstall:
	rm -f $(DESTDIR)$(bindir)/locate
	rm -f $(DESTDIR)$(bindir)/slocate
	rm -f $(DESTDIR)$(bindir)/updatedb
	rm -f $(DESTDIR)$(mandir)/man1/locate.1.gz
	rm -f $(DESTDIR)$(mandir)/man1/slocate.1.gz
	rm -f $(DESTDIR)$(mandir)/man1/updatedb.1.gz
if CRON
	rm -f $(DESTDIR)/etc/cron.daily/slocate
else
	grep -v "slocate\|updatedb" /etc/crontab >/etc/crontab.slocate
	mv /etc/crontab.slocate /etc/crontab
endif
	rm -f $(DESTDIR)$(datadir)slocate/*
	-rmdir $(DESTDIR)$(datadir)slocate
if FREEBSD
	-/usr/sbin/pw groupdel slocate
else
	-/usr/sbin/groupdel slocate
endif
