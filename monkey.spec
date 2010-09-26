Name: monkey
Version: 0.12.0
Release: 2%{?dist}
Summary: A fast and lightweight web server for Linux
Group: System Environment/Daemons
License: GPLv2+
URL: http://www.monkey-project.com
Source: http://www.monkey-project.com/releases/0.12/%{name}-%{version}.tar.gz
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
./configure \
	--prefix=%{_prefix} \
	--bindir=%{_bindir} \
	--sysconfdir=%{_sysconfdir}/%{name} \
	--datadir=%{_var}/www/%{name} \
	--logdir=%{_var}/log/%{name} \
	--plugdir=%{_libexecdir}/%{name}


make %{?_smp_mflags}


%install
rm -rf %{buildroot}
install -d %{buildroot}%{_var}/log/%{name}

make install DESTDIR=%{buildroot}

%{__sed} -i 's/User nobody/User monkey/g' \
	 %{buildroot}/etc/%{name}/monkey.conf

%clean
rm -rf %{buildroot}


%pre
getent group monkey  > /dev/null || groupadd -r monkey
getent passwd monkey > /dev/null || \
  useradd -r -g monkey -d %{_var}/www/%{name}  -s /sbin/nologin \
	  -c "Monkey HTTP Daemon" monkey
exit 0


%files 
%defattr(-,root,root)
%doc README LICENSE ChangeLog*
%attr(644,root,root) %config(noreplace) %{_sysconfdir}/%{name}/monkey.conf
%attr(644,root,root) %config(noreplace) %{_sysconfdir}/%{name}/monkey.mime
%attr(644,root,root) %{_sysconfdir}/%{name}/plugins
%attr(644,root,root) %{_sysconfdir}/%{name}/plugins.load
%attr(644,root,root) %{_sysconfdir}/%{name}/sites
%attr(700,root,root) %{_bindir}
%attr(700,root,root) %{_prefix}/cgi-bin
%attr(644,root,root) %{_libexecdir}
%attr(700,monkey,monkey) %{_var}/www/%{name}
%attr(0750, monkey, monkey) %{_var}/log/%{name}


%postun
cat   %{_var}/log/%{name}/monkey.pid  | xargs kill -9 > /dev/null 2>&1
rm    %{_var}/log/%{name}/*pid > /dev/null 2>&1
rmdir %{_var}/log/%{name} > /dev/null 2>&1
rmdir %{_sysconfdir}/%{name} > /dev/null 2>&1
userdel monkey


%changelog
* Thu Aug 24 2010  Antonio Salles <antonio@salles.clcl> - 0.11.1-2
- Spec rebuild. Now it work fine with Fedora.

* Thu Jul 22 2010  Horst H. von Brand <vonbrand@inf.utfsm.cl> - 0.11.0-2
- First cut at cleaning up specfile according to Fedora guidelines

* Thu Jul 08 2010  Eduardo Silva <edsiper at gmail.com> 0.11.0-1
- Initial rpm package for Fedora 13
