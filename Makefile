short_ver = $(shell git describe --abbrev=0 2>/dev/null || echo 0.0.1)
long_ver = $(shell git describe --long 2>/dev/null || echo $(short_ver)-0-unknown-g`git describe --always`)

SOURCES := \
	src/main/java/io/aiven/kafka/auth/AivenAclAuthorizer.java \
	src/main/java/io/aiven/kafka/auth/AivenAclEntry.java \
	pom.xml \
	aiven-kafka-auth.spec

all: rpm

build-dep:
	sudo dnf install -y --allowerasing --best \
		java-1.8.0-openjdk-devel \
		maven \
		git rpmdevtools

clean:
	$(RM) -rf rpm/ rpmbuild/

rpm: $(SOURCES)
	mkdir -p rpmbuild/
	git archive --output=rpmbuild/aiven-kafka-auth-rpm-src.tar --prefix=aiven-kafka-auth-$(short_ver)/ HEAD
	rpmbuild -bb aiven-kafka-auth.spec \
	    --define '_topdir $(CURDIR)/rpmbuild' \
	    --define '_sourcedir $(CURDIR)/rpmbuild' \
	    --define 'major_version $(short_ver)' \
	    --define 'minor_version $(subst -,.,$(subst $(short_ver)-,,$(long_ver)))'
	mkdir -p "$@/"
	cp "$(CURDIR)/rpmbuild/RPMS/noarch"/*.rpm "$@/"

test:
	mvn -B test
