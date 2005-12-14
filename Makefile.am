## Process this file with automake to produce Makefile.in
# Copyright (C) 2000, 2001, 2002, 2003, 2004, 2005 Free Software Foundation
#
# Author: Nikos Mavroyanopoulos
#
# This file is part of GNUTLS.
#
# This file is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This file is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this file; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

DISTCHECK_CONFIGURE_FLAGS = --enable-gtk-doc

SUBDIRS = gl 
if NETTLE
SUBDIRS += nettle
endif
SUBDIRS += crypto includes lib libextra src doc tests

ACLOCAL_AMFLAGS = -I m4 -I gl/m4

ChangeLog:
	cvs2cl --tags --utc --fsf --FSF --usermap .cvsusers -I ChangeLog -I .cvs
	cat .cvscopying >> ChangeLog

htmldir = ../www-$(PACKAGE)

release:
	rm -f ChangeLog
	make ChangeLog
	cvs commit -m "" ChangeLog
	make dist
	gpg -b $(distdir).tar.bz2
	gpg --verify $(distdir).tar.bz2.sig
	scp $(distdir).tar.bz2{,.sig} igloo.linux.gr:~ftp/pub/gnutls/devel/
	ssh igloo.linux.gr 'cd ~ftp/pub/gnutls/devel/ && sha1sum *.tar.gz *.tar.bz2 > CHECKSUMS'
	cp -v $(distdir).tar.bz2{,.sig} $(htmldir)/releases/
	cd $(htmldir) && cvs add -kb releases/$(distdir).tar.bz2{,.sig} && \
		cvs commit -m "Update." releases/

indent:
	indent -i4 -kr `ls {lib,lib/x509,libextra,libextra/openpgp,src}/*.{c,h} | grep -v -- -gaa`
