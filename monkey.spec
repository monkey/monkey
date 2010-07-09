%define branch 0.11
%define webroot /var/www/monkey
%define prefix /usr
%define bindir /usr/bin
%define sysconf /etc/monkey
%define logdir /var/log/monkey
%define plugdir /usr/lib/monkey

Summary: Monkey is a Fast and Lightweight Web Server for Linux
Name: monkey
Version: 0.11.0
Packager: Eduardo Silva <edsiper@gmail.com>
Release: 1%{dist}
License: GPL
Group: System Environment/Daemons
Source: http://www.monkey-project.com/releases/%{branch}/%{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root
URL: http://www.monkey-project.com

%description
Monkey is a really fast and lightweight Web Server for Linux. It has been 
designed to be very scalable with low memory and CPU consumption, the perfect
solution for embedded and high production environments. 

%prep
%setup
%build
export CFLAGS=$RPM_OPT_FLAGS
./configure \
	--prefix=%{prefix} \
	--bindir=%{bindir} \
	--sysconfdir=%{sysconf} \
	--datadir=%{webroot} \
	--logdir=%{logdir} \
	--plugdir=%{plugdir}

make

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

%changelog
* Thu Jul 08 2010 Eduardo Silva <edsiper at, gmail.com> 0.11.0-1
- Initial rpm package for Fedora 13
