Name: aiven-kafka-auth
Version: %{major_version}
Release: %{minor_version}%{?dist}
Summary: Aiven Kafka Auth Module
Group: Applications/Internet
License: ASL 2.0
URL: https://aiven.io/
Source0: aiven-kafka-auth-rpm-src.tar
BuildArch: noarch
BuildRequires: java, maven
Requires: java
Packager: Heikki Nousiainen <htn@aiven.io>

%description
Aiven Kafka Auth Module

%prep
%setup

%build
mvn test
mvn -DauthorizerVersion=%{major_version} package

%install
%{__mkdir_p} %{buildroot}/opt/kafka/libs
install target/aiven-kafka-auth-%{version}.jar %{buildroot}/opt/kafka/libs/aiven-kafka-auth-%{version}.jar

%files
/opt/kafka/libs/aiven-kafka-auth-%{version}.jar

%changelog
* Fri Jun 27 2016 Heikki Nousiainen <htn@aiven.io>
- First build
