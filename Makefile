# Keep the Makefile POSIX-compliant.  We currently allow hyphens in
# target names, but that may change in the future.
#
# See https://pubs.opengroup.org/onlinepubs/9699919799/utilities/make.html.
.POSIX:

# Don't name this macro "GO", because GNU Make apparenly makes it an
# exported environment variable with the literal value of "${GO:-go}",
# which is not what we need.  Use a dot in the name to make sure that
# users don't have an environment variable with the same name.
#
# See https://unix.stackexchange.com/q/646255/105635.
GO.MACRO = $${GO:-go}
GOPROXY = https://goproxy.cn|https://proxy.golang.org|direct

RACE = 0
VERBOSE = 0

ENV = env\
	GO="$(GO.MACRO)"\
	GOPROXY='$(GOPROXY)'\
	RACE='$(RACE)'\
	VERBOSE='$(VERBOSE)'\

# Keep the line above blank.

# Keep this target first, so that a naked make invocation triggers
# a full check.
check: lint test

lint:
	$(GO.MACRO) vet ./...
	nilness ./...
	staticcheck ./...

test:
	$(GO.MACRO) test --race ./...
