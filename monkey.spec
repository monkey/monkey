Name: monkey
Version: 1.5.6
Release: 1%{?dist}
Summary: A fast and lightweight web server for Linux
Group: System Environment/Daemons
License: Apache License v2.0
URL: http://www.monkey-project.com
Source: http://www.monkey-project.com/releases/1.5/%{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

#BuildRequires: gettext
#Requires(pre): shadow-utils


%description
Monkey is a fast and lightweight web server for Linux. It has been
designed to be very scalable with low memory and CPU consumption, the
perfect solution for embedded and high production environments.

%package devel
Summary: Developement files for Monkey.

%description devel
The monkey-devel package contains the header files and libraries needed
to develop programs that use the monkey shared-library and/or plugins for
the monkey web server.

%prep
%setup -q


%build
./configure \
	--prefix=%{_prefix} \
	--bindir=%{_bindir} \
	--libdir=%{_libdir} \
	--mandir=%{_mandir} \
	--incdir=%{_prefix}/include/monkey/ \
	--sysconfdir=%{_sysconfdir}/%{name} \
	--datadir=%{_var}/www/%{name} \
	--logdir=%{_var}/log/%{name} \
	--plugdir=%{_libexecdir}/%{name} \
	--enable-shared \
	--debug \
	--safe-free

make %{?_smp_mflags}


%install
rm -rf %{buildroot}
install -d %{buildroot}%{_var}/log/%{name}
install -d %{buildroot}%{_var}/lock/%{name}
install -d %{buildroot}%{_sysconfdir}/init.d

make install DESTDIR=%{buildroot}

%{__sed} -i 's/User nobody/User monkey/g' \
	 %{buildroot}/etc/%{name}/monkey.conf
	 
%{__sed} -i '/PidFile /c\    PidFile /var/lock/monkey/monkey.pid' \
     %{buildroot}/etc/%{name}/monkey.conf

mv %{buildroot}%{_bindir}/banana %{buildroot}%{_sysconfdir}/init.d

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
%config(noreplace) %{_sysconfdir}/%{name}/monkey.conf
%config(noreplace) %{_sysconfdir}/%{name}/monkey.mime
%{_sysconfdir}/%{name}/plugins
%{_sysconfdir}/%{name}/plugins.load
%{_sysconfdir}/%{name}/sites
%{_bindir}/*
%{_sysconfdir}/init.d/banana
%{_libexecdir}
%attr(755,monkey,monkey) %{_var}/www/%{name}
%attr(0750, monkey, monkey) %{_var}/log/%{name}
%attr(0750, monkey, monkey) %{_var}/lock/%{name}

# Manpages
%{_mandir}/man1/banana.1.gz
%{_mandir}/man1/monkey.1.gz

# Libraries
%{_libdir}/libmonkey.so.1.5


%files devel
%defattr(-,root,root)

# Header files
%{_prefix}/include/monkey/libmonkey.h
%{_prefix}/include/monkey/MKPlugin.h
%{_prefix}/include/monkey/mk_cache.h
%{_prefix}/include/monkey/mk_clock.h
%{_prefix}/include/monkey/mk_config.h
%{_prefix}/include/monkey/mk_connection.h
%{_prefix}/include/monkey/mk_env.h
%{_prefix}/include/monkey/mk_epoll.h
%{_prefix}/include/monkey/mk_file.h
%{_prefix}/include/monkey/mk_header.h
%{_prefix}/include/monkey/mk_http.h
%{_prefix}/include/monkey/mk_http_status.h
%{_prefix}/include/monkey/mk_info.h
%{_prefix}/include/monkey/mk_iov.h
%{_prefix}/include/monkey/mk_lib.h
%{_prefix}/include/monkey/mk_limits.h
%{_prefix}/include/monkey/mk_linuxtrace.h
%{_prefix}/include/monkey/mk_list.h
%{_prefix}/include/monkey/mk_macros.h
%{_prefix}/include/monkey/mk_memory.h
%{_prefix}/include/monkey/mk_method.h
%{_prefix}/include/monkey/mk_mimetype.h
%{_prefix}/include/monkey/mk_plugin.h
%{_prefix}/include/monkey/mk_rbtree.h
%{_prefix}/include/monkey/mk_rbtree_augmented.h
%{_prefix}/include/monkey/mk_request.h
%{_prefix}/include/monkey/mk_scheduler.h
%{_prefix}/include/monkey/mk_server.h
%{_prefix}/include/monkey/mk_signals.h
%{_prefix}/include/monkey/mk_socket.h
%{_prefix}/include/monkey/mk_string.h
%{_prefix}/include/monkey/mk_user.h
%{_prefix}/include/monkey/mk_utils.h
%{_prefix}/include/monkey/mk_kernel.h
%{_prefix}/include/monkey/mk_vhost.h
%{_prefix}/include/monkey/monkey.h

# Manpages
%{_mandir}/man3/mklib_callback_set.3.gz
%{_mandir}/man3/mklib_config.3.gz
%{_mandir}/man3/mklib_init.3.gz
%{_mandir}/man3/mklib_mimetype_add.3.gz
%{_mandir}/man3/mklib_mimetype_list.3.gz
%{_mandir}/man3/mklib_scheduler_worker_info.3.gz
%{_mandir}/man3/mklib_start.3.gz
%{_mandir}/man3/mklib_stop.3.gz
%{_mandir}/man3/mklib_vhost_config.3.gz
%{_mandir}/man3/mklib_vhost_list.3.gz
%{_mandir}/man3/monkey-api.3.gz

# Libraries
%{_libdir}/libmonkey.so
%{_libdir}/pkgconfig/monkey.pc


%postun
cat    %{_var}/lock/%{name}/monkey.pid* | xargs kill -9 > /dev/null 2>&1
rm -rf %{_var}/lock/%{name} > /dev/null 2>&1
rmdir  %{_var}/log/%{name} > /dev/null 2>&1
rmdir  %{_sysconfdir}/%{name} > /dev/null 2>&1


%changelog
* Fri Aug 07 2015 Sylvain Mesnage <sylvain.mesnage@free.fr> - 1.5.6-1
- Fixed the spec file permissions and packaging of devel/non-devel files.

* Sun Dec 22 2013 Eduardo Silva <edsiper@gmail.com> - 1.4.0-1
- Testing new spec file for v1.4

* Thu Aug 24 2010  Antonio Salles <antonio@salles.clcl> - 0.11.1-2
- Spec rebuild. Now it work fine with Fedora.

* Thu Jul 22 2010  Horst H. von Brand <vonbrand@inf.utfsm.cl> - 0.11.0-2
- First cut at cleaning up specfile according to Fedora guidelines

* Thu Jul 08 2010  Eduardo Silva <edsiper at gmail.com> 0.11.0-1
- Initial rpm package for Fedora 13

