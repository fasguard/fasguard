# Simple makefile (GNU) for building FASGuard components.  This makefile
# makes no attempt to be smart and figure out what steps have already
# been completed -- it always rebuilds a component (and its
# dependencies) from scratch.
#
# Interesting targets:
#   * all: build all components (same as specifying no targets)
#   * clean: nuke the $(pwd).build directory
#   * <component>: build just the component named <component> and its
#     dependencies


# components (dependencies are specified after the 'all' target below)
components := \
	fasguard-ad-host-peering \
	fasguardlib-ad-tx

# default target goes first
all: $(components)
.PHONY: all

# component dependencies go here
fasguard-ad-host-peering: fasguardlib-ad-tx

# handy macros
quote = '$(subst ','\'',$(1))'#'
top = $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
builddir = $(top).build
builddir_q = $(call quote,$(builddir))
instdir = $(builddir)/INSTALL
cppflags = -I$(instdir)/include $(CPPFLAGS)
cppflags_q = $(call quote,$(cppflags))
ldflags = -L$(instdir)/lib $(LDFLAGS)
ldflags_q = $(call quote,$(ldflags))
sep = ======================================================================
set_log_functions = \
	log() { printf %s\\n "$$*"; } && \
	error() { log "ERROR: $$@" >&2; } && \
	fatal() { error "$$@"; exit 1; } && \
	try() { "$$@" || fatal "'$$@' failed"; } && \
	biglog() { log '$(sep)'; log "$$@"; log '$(sep)'; }

# clean only nukes the *.build directory
.PHONY: clean
clean:
	! [ -d $(builddir_q) ] || chmod -R u+rw $(builddir_q)
	rm -rf $(builddir_q)

# rule for building a component
.PHONY: $(components)
$(components):
	@$(set_log_functions) && \
	c=$(call quote,$@) && \
	biglog "$${c}: START" && \
	cdir=$(call quote,$(top))/$${c} && \
	autogen=$${cdir}/autogen.sh && \
	{ [ -f "$${autogen}" ] || fatal "$${autogen} missing"; } && \
	cbuilddir=$(builddir_q)/$${c} && \
	mkdir -p "$${cbuilddir}" && \
	cd "$${cbuilddir}" && \
	biglog "$${c}: autogen.sh" && \
	"$${autogen}" && \
	biglog "$${c}: configure" && \
	"$${cdir}"/configure \
		--prefix=$(call quote,$(instdir)) \
		CPPFLAGS=$(cppflags_q) \
		LDFLAGS=$(ldflags_q) \
		&& \
	biglog "$${c}: make distcheck" && \
	env \
		CPPFLAGS=$(cppflags_q) \
		LDFLAGS=$(ldflags_q) \
		make distcheck && \
	biglog "$${c}: make install" && \
	make install && \
	biglog "$${c}: FINISH"
