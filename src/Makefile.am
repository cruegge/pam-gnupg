module_LTLIBRARIES = pam_gnupg.la
pam_gnupg_la_SOURCES = pam_gnupg.c
pam_gnupg_la_LIBADD = -lpam
pam_gnupg_la_LDFLAGS = -module -avoid-version
pam_gnupg_la_CPPFLAGS = -DPAM_GNUPG_HELPER='"$(libexecdir)/pam_gnupg_helper"'

libexec_PROGRAMS = pam_gnupg_helper
pam_gnupg_helper_SOURCES = helper.c

install-data-hook:
	rm -f $(DESTDIR)$(moduledir)/pam_gnupg.la
