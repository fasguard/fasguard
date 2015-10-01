bin_PROGRAMS += \
	src/makebloom

src_makebloom_SOURCES = \
	src/makebloom.cpp

src_makebloom_LDADD = \
	$(LDADD_LIBFASGUARDFILTER)
