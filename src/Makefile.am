moduledir = $(libdir)/security
module_LTLIBRARIES = pam_gnupg.la
pam_gnupg_la_SOURCES = pam_gnupg.c
pam_gnupg_la_LIBADD = -lpam
pam_gnupg_la_LDFLAGS = -module -avoid-version

install-data-hook:
	rm -f $(DESTDIR)$(moduledir)/pam_gnupg.la
