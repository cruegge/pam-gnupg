all: pam_gnupg.so

pam_gnupg.so: pam_gnupg.c
	gcc -Wall -fPIC -DPIC -shared -rdynamic -o pam_gnupg.so pam_gnupg.c
