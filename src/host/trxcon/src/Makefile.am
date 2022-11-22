AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOCODING_CFLAGS) \
	$(LIBOSMOGSM_CFLAGS) \
	$(LIBOSMOGPRSRLCMAC_CFLAGS) \
	$(NULL)


noinst_LTLIBRARIES = libl1sched.la

libl1sched_la_SOURCES = \
	sched_lchan_common.c \
	sched_lchan_pdtch.c \
	sched_lchan_desc.c \
	sched_lchan_xcch.c \
	sched_lchan_tchf.c \
	sched_lchan_tchh.c \
	sched_lchan_rach.c \
	sched_lchan_sch.c \
	sched_mframe.c \
	sched_clck.c \
	sched_prim.c \
	sched_trx.c \
	$(NULL)

libl1sched_la_LIBADD = \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOCODING_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(NULL)


noinst_LTLIBRARIES += libl1gprs.la

libl1gprs_la_SOURCES = \
	gprs.c \
	$(NULL)

libl1gprs_la_LIBADD = \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOGPRSRLCMAC_LIBS) \
	$(NULL)


noinst_LTLIBRARIES += libtrxcon.la

libtrxcon_la_SOURCES = \
	trxcon_inst.c \
	trxcon_fsm.c \
	trxcon_shim.c \
	l1ctl.c \
	$(NULL)

libtrxcon_la_LIBADD = \
	libl1sched.la \
	libl1gprs.la \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(NULL)


if ENABLE_L1GPRS_TEST
noinst_PROGRAMS = l1gprs_test

l1gprs_test_SOURCES = \
	l1ctl_server.c \
	l1gprs_test.c \
	logging.c \
	$(NULL)

l1gprs_test_LDADD = \
	libl1gprs.la \
	$(NULL)
endif


bin_PROGRAMS = trxcon

trxcon_SOURCES = \
	l1ctl_server.c \
	trxcon_main.c \
	logging.c \
	trx_if.c \
	$(NULL)

trxcon_LDADD = \
	libtrxcon.la \
	$(NULL)
