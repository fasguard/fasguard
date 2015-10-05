AUTOMAKE_OPTIONS = \
	1.6 \
	foreign \
	subdir-objects \
	parallel-tests \
	-Wall \
	-Wno-extra-portability

ACLOCAL_AMFLAGS = -I m4 -I build-aux

AM_CPPFLAGS =

AM_CFLAGS = \
	-Wall \
	-Wextra \
	-g

AM_CXXFLAGS = \
	-Wall \
	-Wextra \
	-g

BUILT_SOURCES =
CLEANFILES =
EXTRA_DIST =
TESTS =
bin_PROGRAMS =
include_HEADERS =
lib_LTLIBRARIES =
noinst_PROGRAMS =

AM_CPPFLAGS += \
	-isystem $(top_srcdir)/include

noinst_PROGRAMS += \
	resources_generator

resources_generator_SOURCES = \
	resources/resources_generator.c

LIBFASGUARDLIB_AD_TX_RESOURCES = \
	$(srcdir)/resources/fasguard_stix_incident_footer \
	$(srcdir)/resources/fasguard_stix_incident_header \
	$(srcdir)/resources/fasguard_stix_package_footer \
	$(srcdir)/resources/fasguard_stix_package_header \
	$(srcdir)/resources/fasguard_stix_packet_data_footer \
	$(srcdir)/resources/fasguard_stix_packet_data_header \
	$(srcdir)/resources/fasguard_stix_packet_footer \
	$(srcdir)/resources/fasguard_stix_packet_header \
	$(srcdir)/resources/fasguard_stix_packet_keyword_link_type_fmt \
	$(srcdir)/resources/fasguard_stix_packet_keyword_prob_attack_fmt \
	$(srcdir)/resources/fasguard_stix_packet_keywords_footer \
	$(srcdir)/resources/fasguard_stix_packet_keywords_header \
	$(srcdir)/resources/fasguard_stix_packet_timestamp_timefmt

EXTRA_DIST += \
	$(LIBFASGUARDLIB_AD_TX_RESOURCES)

resources.c: resources_generator $(LIBFASGUARDLIB_AD_TX_RESOURCES)
	$(AM_V_GEN)./resources_generator \
		--include "\"resources.h\"" \
		$(LIBFASGUARDLIB_AD_TX_RESOURCES) \
		> resources.c \
		|| { \
			mv -f resources.c resources.c.fail; \
			exit 1; \
			}

resources.h: resources_generator $(LIBFASGUARDLIB_AD_TX_RESOURCES)
	$(AM_V_GEN)./resources_generator \
		--header \
		$(LIBFASGUARDLIB_AD_TX_RESOURCES) \
		> resources.h \
		|| { \
			mv -f resources.h resources.h.fail; \
			exit 1; \
			}

BUILT_SOURCES += \
	resources.h

CLEANFILES += \
	resources.c \
	resources.c.fail \
	resources.h \
	resources.h.fail

lib_LTLIBRARIES += \
	libfasguardlib-ad-tx.la

include_HEADERS += \
	include/fasguardlib-ad-tx.h

libfasguardlib_ad_tx_la_SOURCES = \
	src/attack.c \
	src/macros.h \
	src/option.c

nodist_libfasguardlib_ad_tx_la_SOURCES = \
	resources.c \
	resources.h

libfasguardlib_ad_tx_la_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	-I$(builddir)/include

libfasguardlib_ad_tx_la_LDFLAGS = \
	-version-info 0:0:0

.PHONY: doc
doc: doc/Doxyfile
	doxygen doc/Doxyfile

clean-local: clean-local-doc
.PHONY: clean-local-doc
clean-local-doc:
	rm -rf doc/html doc/latex
