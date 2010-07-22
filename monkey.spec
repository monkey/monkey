Name: monkey
Version: 0.11.0
Release: 2%{?dist}
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
	--prefix=%{_prefix} \
	--bindir=%{_bindir} \
	--sysconfdir=%{_sysconf}/%{name} \
	--datadir=%{_var}/www/%{name} \
	--logdir=%{_var}/log/%{name} \
	--plugdir=%{_libexecdir}/%{name}

make %{?_smp_mflags}

%install
rm -rf %{buildroot}
install -d %{buildroot}%{_var}/log/%{name}

make install DESTDIR=%{buildroot}

%{__sed} -i 's/User nobody/User monkey/g' \
	 %{buildroot}%{_sysconf}/%{name}/monkey.conf

%find_lang %{name}

%clean
rm -rf %{buildroot}

%pre
getent group monkey  > /dev/null || groupadd -r monkey
getent passwd monkey > /dev/null || \
  useradd -r -g monkey -d %{webroot} -s /sbin/nologin \
	  -c "Monkey HTTP Daemon" monkey
exit 0

%files -f %{name}.lang
%defattr(-,root,root)
%doc README LICENSE ChangeLog*
%attr(644,root,root) %config(noreplace) %{_sysconfdir}/%{name}/monkey.conf
%attr(644,root,root) %config(noreplace) %{_sysconfdir}/%{name}/monkey.mime
%attr(644,root,root) %{_sysconfdir}/%{name}/plugins
%attr(644,root,root) %{_sysconfdir}/%{name}/sites
%{_bindir}/banana
%{_bindir}/monkey
%dir %{_var}/www/%{name}
%attr(0750, monkey, monkey) %ghost %{_localstatedir}/log/%{name}

%changelog
* Thu Jul 22 2010  Horst H. von Brand <vonbrand@inf.utfsm.cl> - 0.11.0-2
- First cut at cleaning up specfile according to Fedora guidelines

* Thu Jul 08 2010  Eduardo Silva <edsiper at gmail.com> 0.11.0-1
- Initial rpm package for Fedora 13
