%define deftclver 8.3.1
%define tclver %(rpm -q tcl --queryformat '%%{version}' 2> /dev/null || echo %{deftclver})

Summary: Simple, fast Tcl server side scripting for Apache.
Name: mod_dtcl
Version: 0.11.5
Release: 1
Copyright: Freely distributable and usable
Group: System Environment/Daemons
Source:	http://tcl.apache.org/mod_dtcl/download/%{name}-%{version}.tar.gz
URL: http://tcl.apache.org/mod_dtcl/
Packager: Simon Greaves <Simon.Greaves@bigfoot.com>
BuildRoot: %{_tmppath}/%{name}-root
Requires: webserver, tcl = %{tclver}
BuildPrereq: apache-devel, tcl
Prereq: tcl

%description
Server side Tcl scripting for Apache.

The mod_dtcl Apache module enables the use of Tcl as an HTML-embedded
scripting language, similar to PHP. It is fast, light, and lets you
use the extensive codebase of existing Tcl code, on the web.

%prep
%setup -n %{name}
sed -e 's/^INC=.*/INC=\/usr\/include\/apache/' \
    -e 's/^APACHE=.*/APACHE=\/usr\/sbin/' \
	< builddtcl.sh > rpm-builddtcl.sh

%build
sh ./rpm-builddtcl.sh shared

%install
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT%{_libdir}/apache
install -c -s -m755 mod_dtcl.so $RPM_BUILD_ROOT%{_libdir}/apache/

%clean
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%doc README README.RedHat README.debug STATUS VERSION docs tests contrib
%{_libdir}/apache/mod_dtcl.so

%changelog
* Wed Aug  1 2001 Simon Greaves <Simon.Greaves@bigfoot.com>
- mod_dtcl-0.11.1 packaged.

* Wed May  2 2001 Simon Greaves <Simon.Greaves@bigfoot.com>
- slight tweaks for mod_dtcl-0.10.1.

* Fri Mar 16 2001 Simon Greaves <Simon.Greaves@bigfoot.com>
- mod_dtcl-0.9.3-1 packaged.
