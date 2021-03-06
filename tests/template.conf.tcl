# \$Id\$
# Minimal config file for testing

# Parsed by makeconf.tcl

ServerType standalone

ServerRoot "$CWD"

PidFile "$CWD/httpd.pid"

# ScoreBoardFile "$CWD/apache_runtime_status"

ResourceConfig "$CWD/srm.conf"
AccessConfig "$CWD/access.conf"

Timeout 300

MaxRequestsPerChild 100

$LOADMODULES

LoadModule dtcl_module $CWD/../mod_dtcl[info sharedlibextension]

Port 8080

ServerName localhost

DocumentRoot "$CWD"

<Directory "$CWD">
Options All MultiViews 
AllowOverride All
Order allow,deny
Allow from all
</Directory>

<IfModule mod_dir.c>
DirectoryIndex index.html
</IfModule>

AccessFileName .htaccess

HostnameLookups Off

ErrorLog $CWD/error_log

LogLevel debug

LogFormat "%h %l %u %t \\"%r\\" %>s %b \\"%{Referer}i\\" \\"%{User-Agent}i\\"" combined
CustomLog "$CWD/access_log" combined

<IfModule mod_mime.c>
AddLanguage en .en
AddLanguage it .it
AddLanguage es .es
AddType application/x-httpd-tcl .ttml
AddType application/x-dtcl-tcl .tcl
</IfModule>
