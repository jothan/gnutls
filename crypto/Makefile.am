## Process this file with automake to produce Makefile.in
# Copyright (C) 2004, 2005 Simon Josefsson
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

AM_CPPFLAGS = @LIBGCRYPT_CFLAGS@ @NETTLE_CFLAGS@

noinst_LTLIBRARIES = libgc.la

libgc_la_SOURCES = gc.h pkcs5.c
libgc_la_LIBADD = @LIBGCRYPT_LIBS@ @NETTLE_LIBS@

if NETTLE
libgc_la_SOURCES += gc-nettle.c
libgc_la_SOURCES += tommath.h tommath_class.h tommath_superclass.h	\
	bncore.o bn_mp_init.o bn_mp_clear.o bn_mp_exch.o bn_mp_grow.o	\
	bn_mp_shrink.o bn_mp_clamp.o bn_mp_zero.o bn_mp_set.o		\
	bn_mp_set_int.o bn_mp_init_size.o bn_mp_copy.o			\
	bn_mp_init_copy.o bn_mp_abs.o bn_mp_neg.o bn_mp_cmp_mag.o	\
	bn_mp_cmp.o bn_mp_cmp_d.o bn_mp_rshd.o bn_mp_lshd.o		\
	bn_mp_mod_2d.o bn_mp_div_2d.o bn_mp_mul_2d.o bn_mp_div_2.o	\
	bn_mp_mul_2.o bn_s_mp_add.o bn_s_mp_sub.o			\
	bn_fast_s_mp_mul_digs.o bn_s_mp_mul_digs.o			\
	bn_fast_s_mp_mul_high_digs.o bn_s_mp_mul_high_digs.o		\
	bn_fast_s_mp_sqr.o bn_s_mp_sqr.o bn_mp_add.o bn_mp_sub.o	\
	bn_mp_karatsuba_mul.o bn_mp_mul.o bn_mp_karatsuba_sqr.o		\
	bn_mp_sqr.o bn_mp_div.o bn_mp_mod.o bn_mp_add_d.o		\
	bn_mp_sub_d.o bn_mp_mul_d.o bn_mp_div_d.o bn_mp_mod_d.o		\
	bn_mp_expt_d.o bn_mp_addmod.o bn_mp_submod.o bn_mp_mulmod.o	\
	bn_mp_sqrmod.o bn_mp_gcd.o bn_mp_lcm.o bn_fast_mp_invmod.o	\
	bn_mp_invmod.o bn_mp_reduce.o bn_mp_montgomery_setup.o		\
	bn_fast_mp_montgomery_reduce.o bn_mp_montgomery_reduce.o	\
	bn_mp_exptmod_fast.o bn_mp_exptmod.o bn_mp_2expt.o		\
	bn_mp_n_root.o bn_mp_jacobi.o bn_reverse.o bn_mp_count_bits.o	\
	bn_mp_read_unsigned_bin.o bn_mp_read_signed_bin.o		\
	bn_mp_to_unsigned_bin.o bn_mp_to_signed_bin.o			\
	bn_mp_unsigned_bin_size.o bn_mp_signed_bin_size.o bn_mp_xor.o	\
	bn_mp_and.o bn_mp_or.o bn_mp_rand.o				\
	bn_mp_montgomery_calc_normalization.o				\
	bn_mp_prime_is_divisible.o bn_prime_tab.o bn_mp_prime_fermat.o	\
	bn_mp_prime_miller_rabin.o bn_mp_prime_is_prime.o		\
	bn_mp_prime_next_prime.o bn_mp_dr_reduce.o			\
	bn_mp_dr_is_modulus.o bn_mp_dr_setup.o bn_mp_reduce_setup.o	\
	bn_mp_toom_mul.o bn_mp_toom_sqr.o bn_mp_div_3.o			\
	bn_s_mp_exptmod.o bn_mp_reduce_2k.o bn_mp_reduce_is_2k.o	\
	bn_mp_reduce_2k_setup.o bn_mp_reduce_2k_l.o			\
	bn_mp_reduce_is_2k_l.o bn_mp_reduce_2k_setup_l.o		\
	bn_mp_radix_smap.o bn_mp_read_radix.o bn_mp_toradix.o		\
	bn_mp_radix_size.o bn_mp_fread.o bn_mp_fwrite.o			\
	bn_mp_cnt_lsb.o bn_error.o bn_mp_init_multi.o			\
	bn_mp_clear_multi.o bn_mp_exteuclid.o bn_mp_toradix_n.o		\
	bn_mp_prime_random_ex.o bn_mp_get_int.o bn_mp_sqrt.o		\
	bn_mp_is_square.o bn_mp_init_set.o bn_mp_init_set_int.o		\
	bn_mp_invmod_slow.o bn_mp_prime_rabin_miller_trials.o		\
	bn_mp_to_signed_bin_n.o bn_mp_to_unsigned_bin_n.o
endif

if LIBGCRYPT
libgc_la_SOURCES += gc-libgcrypt.c
endif

noinst_LTLIBRARIES += libutils.la
libutils_la_SOURCES = utils.h utils.c

test_gc_LDADD = libutils.la libgc.la

TESTS = test-gc
check_PROGRAMS = $(TESTS)
