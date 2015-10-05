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
	fasguard-pcap \
	fasguardlib-ad-tx \
	fasguardlib-filter \
	signature-extraction/ASG

# default target goes first
all: $(components)
.PHONY: all

# component dependencies go here
fasguard-ad-host-peering: fasguardlib-ad-tx
signature-extraction/ASG: fasguardlib-filter

# handy macros
quote = '$(subst ','\'',$(1))'#'
top = $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
builddir = $(top).build
builddir_q = $(call quote,$(builddir))
helpmsg = $(builddir)/helpmsg.txt
helpmsg_q = $(call quote,$(helpmsg))
instdir = $(builddir)/INSTALL
instdir_q = $(call quote,$(instdir))
incdir = $(instdir)/include
incdir_q = $(call quote,$(incdir))
libdir = $(instdir)/lib
libdir_q = $(call quote,$(libdir))
cppflags = -I$(incdir) $(CPPFLAGS)
cppflags_q = $(call quote,$(cppflags))
ldflags = -L$(libdir) $(LDFLAGS)
ldflags_q = $(call quote,$(ldflags))
sep = ======================================================================
set_log_functions = \
	pecho() { printf %s\\n "$$*"; } && \
	log() { pecho "$$@"; } && \
	error() { log "ERROR: $$@" >&2; } && \
	fatal() { error "$$@"; exit 1; } && \
	try() { "$$@" || fatal "'$$@' failed"; } && \
	biglog() { log '$(sep)'; log "$$@"; log '$(sep)'; }

# clean only nukes the *.build directory
.PHONY: clean
clean:
	! [ -d $(builddir_q) ] || chmod -R u+rw $(builddir_q)
	rm -rf $(builddir_q)

.PHONY: init_helpmsg
init_helpmsg:
	@rm -f $(helpmsg_q)

# rule for building a component
.PHONY: $(components)
$(components): init_helpmsg
	@$(set_log_functions) && \
	c=$(call quote,$@) && \
	biglog "$${c}: START" && \
	cdir=$(call quote,$(top))/$${c} && \
	cbuilddir=$(builddir_q)/$${c} && \
	python_component=false && \
	mkdir -p $(instdir_q) && \
	mkdir -p "$${cbuilddir}" && \
	cd "$${cbuilddir}" && \
	autogen=$${cdir}/autogen.sh && \
	! [ -f "$${autogen}" ] || { \
		biglog "$${c}: autogen.sh" && \
		"$${autogen}"; \
	} && \
	configure=$${cdir}/configure && \
	! [ -f "$${configure}" ] || { \
		biglog "$${c}: configure" && \
		"$${configure}" \
			--prefix=$(instdir_q) \
			CPPFLAGS=$(cppflags_q) \
			LDFLAGS=$(ldflags_q) \
			&& \
		biglog "$${c}: make distcheck" && \
		env \
			CPPFLAGS=$(cppflags_q) \
			LDFLAGS=$(ldflags_q) \
			make distcheck && \
		biglog "$${c}: make install" && \
		make install; \
	} && \
	setuppy=$${cdir}/setup.py && \
	! [ -f "$${setuppy}" ] || { \
		python_component=true && \
		fullname=$$("$${setuppy}" --fullname) && \
		biglog "$${c}: setup.py sdist" && \
		( \
			cd "$${cdir}" && \
			./setup.py \
				egg_info --egg-base "$${cbuilddir}" \
				sdist --formats=bztar \
					--dist-dir "$${cbuilddir}"/dist \
		) && \
		biglog "$${c}: virtualenv" && \
		[ -f $(instdir_q)/bin/activate ] || { \
			mkdir -p $(instdir_q) && \
			virtualenv --system-site-packages $(instdir_q); \
		} && \
		. $(instdir_q)/bin/activate && \
		biglog "$${c}: pip install" && \
		pip install \
			--global-option build_ext \
			--global-option -I$(incdir_q) \
			--global-option -L$(libdir_q) \
			--global-option -R$(libdir_q) \
			./dist/"$${fullname}".tar.bz2; \
	} && \
	biglog "$${c}: FINISH" && \
	[ -f $(helpmsg_q) ] && ! "$${python_component}" || { \
		pecho "Installed in: "$(instdir_q) >$(helpmsg_q) && \
		! "$${python_component}" || { \
			pecho "That directory is a Python virtualenv." && \
			pecho "To use the virtualenv, run:" && \
			pecho "    . "$(instdir_q)"/bin/activate"; \
		} >>$(helpmsg_q); \
	} && \
	while IFS= read -r line; do log "$${line}"; done <$(helpmsg_q)

components_clean := $(foreach c,$(components),clean-$(c)) clean-INSTALL
.PHONY: $(components_clean)
$(components_clean):
	@$(set_log_functions) && \
	c=$(call quote,$@) && c=$${c#clean-} && d=$(builddir_q)/$${c} && \
	log "deleting $${c} ($${d})..." && \
	{ ! [ -d "$${d}" ] || chmod -R u+rw "$${d}"; } && \
	rm -rf "$${d}"
