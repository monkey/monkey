%define webroot /var/www/monkey
%define prefix /usr
%define bindir /usr/bin
%define sysconf /etc/monkey
%define logdir /var/log/monkey
%define plugdir /usr/lib/monkey

Summary: A fast and lightweight web server for Linux
Name: monkey
Version: 0.11.0
Packager: Eduardo Silva <edsiper@gmail.com>
Release: 1%{dist}
License: GPLv2+
Group: System Environment/Daemons
Source: http://www.monkey-project.com/releases/0.11/%{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-buildroot
URL: http://www.monkey-project.com

%description
Monkey is a really fast and lightweight Web Server for Linux. It has been 
designed to be very scalable with low memory and CPU consumption, the perfect
solution for embedded and high production environments. 

%prep
%setup
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

%pre
/usr/sbin/useradd -s /sbin/nologin -M -r -d %{webroot} \
	-c "Monkey HTTP Daemon" monkey &>/dev/null ||: 

%post
sed -i 's/User nobody/User monkey/g' /etc/monkey/monkey.conf

%install
rm -rf %{buildroot}
install -d %{buildroot}/usr/share/doc
install -d %{buildroot}%{logdir}

make DESTDIR=%{buildroot} install

%clean
rm -rf %{buildroot}

%files 
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
