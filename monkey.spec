%define webroot /var/www/monkey
%define prefix /usr
%define bindir /usr/bin
%define sysconf /etc/monkey
%define logdir /var/log/monkey
%define plugdir /usr/lib/monkey

Name: monkey
Version: 0.11.0
Release: 1%{?dist}
Summary: A fast and lightweight web server for Linux
Group: System Environment/Daemons
License: GPLv2+
URL: http://www.monkey-project.com
Source: http://www.monkey-project.com/releases/0.11/%{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires: gettext
Requires(pre): shadow-utils

%description
Monkey is a fast and lightweight web server for Linux. It has been
designed to be very scalable with low memory and CPU consumption, the
perfect solution for embedded and high production environments.

%prep
%setup -q

%build
export CFLAGS=%{optflags}
./configure \
	--prefix=%{prefix} \
	--bindir=%{bindir} \
	--sysconfdir=%{sysconf} \
	--datadir=%{webroot} \
	--logdir=%{logdir} \
	--plugdir=%{plugdir}
make %{?_smp_mflags}

%install
rm -rf %{buildroot}
install -d %{buildroot}/usr/share/doc
install -d %{buildroot}%{logdir}

make install DESTDIR=%{buildroot}

%find_lang %{name}

%clean
rm -rf %{buildroot}

%pre
getent group monkey  > /dev/null || groupadd -r monkey
getent passwd monkey > /dev/null || \
  useradd -r -g monkey -d %{webroot} -s /sbin/nologin \
	  -c "Monkey HTTP Daemon" monkey
exit 0

%post
sed -i 's/User nobody/User monkey/g' /etc/monkey/monkey.conf

%files -f %{name}.lang
%defattr(-,root,root)
%doc README LICENSE ChangeLog*
%attr(644,root,root) %{_sysconfdir}/monkey/*
%{_bindir}/*
%{_libdir}/*
%{_datadir}/*
%{webroot}/*
%{logdir}
%defattr(-, monkey, monkey, 0750)
%{_localstatedir}/log/monkey

%changelog
* Thu Jul 08 2010 Eduardo Silva <edsiper at, gmail.com> 0.11.0-1
- Initial rpm package for Fedora 13
