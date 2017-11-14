# fingerprint

Create a fingerprint of a host environment based on RPM packages installed and PHP configuration.

## Usage
By default, `fingerprint` will return a single SHA1 hash that represents the inspected environment details:

```
[root@core-01 fingerprint]# ./fingerprint
bb2ddd3245aa3eace1d613fda554a63651b07b8b
```

If you wish to see what differs between two hosts, then the verbose mode will show each source of fingerprint data, the SHA1 hash for that source and the raw data extracted. This is suitable for diffing between hosts to find where they diverge.

```
[root@core-01 fingerprint]# ./fingerprint -verbose
bb2ddd3245aa3eace1d613fda554a63651b07b8b
rpm
acl#2.2.52-11.fc24
audit-libs#2.5.2-1.fc24
basesystem#11-2.fc24
bash#4.3.42-5.fc24
bash-completion#1:2.3-1.fc24
binutils#2.26.1-1.fc24
bzip2-libs#1.0.6-20.fc24
ca-certificates#2016.2.7-1.0.fc24
chkconfig#1.7-2.fc24
coreutils#8.25-5.fc24
coreutils-common#8.25-5.fc24
cpp#6.1.1-2.fc24
cracklib#2.9.6-2.fc24
cracklib-dicts#2.9.6-2.fc24
crypto-policies#20151104-2.gitf1cba5f.fc24
cryptsetup-libs#1.7.1-1.fc24
curl#7.47.1-4.fc24
cyrus-sasl-lib#2.1.26-26.2.fc24
dbus#1:1.11.2-1.fc24
dbus-libs#1:1.11.2-1.fc24
deltarpm#3.6-15.fc24
device-mapper#1.02.122-1.fc24
device-mapper-libs#1.02.122-1.fc24
diffutils#3.3-13.fc24
dnf#1.1.9-2.fc24
dnf-conf#1.1.9-2.fc24
dnf-yum#1.1.9-2.fc24
e2fsprogs#1.42.13-4.fc24
e2fsprogs-libs#1.42.13-4.fc24
elfutils-default-yama-scope#0.166-2.fc24
elfutils-libelf#0.166-2.fc24
elfutils-libs#0.166-2.fc24
emacs-filesystem#1:25.0.94-1.fc24
expat#2.1.1-1.fc24
fedora-release#24-1
fedora-repos#24-1
file-libs#5.25-6.fc24
filesystem#3.2-37.fc24
fipscheck#1.4.1-10.fc24
fipscheck-lib#1.4.1-10.fc24
gawk#4.1.3-3.fc24
gcc#6.1.1-2.fc24
gdbm#1.11-7.fc24
git-core#2.7.5-1.fc24
glib2#2.48.1-1.fc24
glibc#2.23.1-7.fc24
glibc-all-langpacks#2.23.1-7.fc24
glibc-common#2.23.1-7.fc24
glibc-devel#2.23.1-7.fc24
glibc-headers#2.23.1-7.fc24
gmp#1:6.1.0-2.fc24
gnupg2#2.1.11-3.fc24
gnutls#3.4.12-1.fc24
go-srpm-macros#2-6.fc24
golang#1.6.4-3.fc24
golang-bin#1.6.4-3.fc24
golang-src#1.6.4-3.fc24
gpgme#1.4.3-7.fc24
grep#2.25-1.fc24
gzip#1.6-10.fc24
hawkey#0.6.3-2.fc24
info#6.1-2.fc24
iptables#1.4.21-16.fc24
isl#0.14-5.fc24
kernel-headers#4.11.12-100.fc24
keyutils-libs#1.5.9-8.fc24
kmod#22-4.fc24
kmod-libs#22-4.fc24
krb5-libs#1.14.1-6.fc24
less#481-5.fc24
libacl#2.2.52-11.fc24
libarchive#3.1.2-17.fc24
libassuan#2.4.2-2.fc24
libattr#2.4.47-16.fc24
libblkid#2.28-2.fc24
libcap#2.24-9.fc24
libcap-ng#0.7.7-4.fc24
libcom_err#1.42.13-4.fc24
libcomps#0.1.7-4.fc24
libcurl#7.47.1-4.fc24
libdb#5.3.28-14.fc24
libdb-utils#5.3.28-14.fc24
libedit#3.1-14.20150325cvs.fc24
libfdisk#2.28-2.fc24
libffi#3.1-9.fc24
libgcc#6.1.1-2.fc24
libgcrypt#1.6.4-2.fc24
libgnome-keyring#3.12.0-6.fc24
libgomp#6.1.1-2.fc24
libgpg-error#1.21-2.fc24
libidn#1.32-2.fc24
libksba#1.3.4-1.fc24
libmetalink#0.1.2-9.fc24
libmnl#1.0.3-11.fc24
libmount#2.28-2.fc24
libmpc#1.0.2-5.fc24
libnetfilter_conntrack#1.0.4-6.fc24
libnfnetlink#1.0.1-8.fc24
libnghttp2#1.7.1-1.fc24
libpsl#0.13.0-1.fc24
libpwquality#1.3.0-4.fc24
librepo#1.7.18-2.fc24
libreport-filesystem#2.7.1-1.fc24
libseccomp#2.3.1-0.fc24
libsecret#0.18.5-1.fc24
libselinux#2.5-3.fc24
libsemanage#2.5-2.fc24
libsepol#2.5-3.fc24
libsmartcols#2.28-2.fc24
libsolv#0.6.20-3.fc24
libss#1.42.13-4.fc24
libssh2#1.7.0-5.fc24
libsss_idmap#1.13.4-3.fc24
libsss_nss_idmap#1.13.4-3.fc24
libstdc++#6.1.1-2.fc24
libtasn1#4.8-1.fc24
libunistring#0.9.4-3.fc24
libutempter#1.1.6-8.fc24
libuuid#2.28-2.fc24
libverto#0.2.6-6.fc24
libxkbcommon#0.5.0-4.fc24
libxml2#2.9.3-3.fc24
lua#5.3.2-3.fc24
lz4#r131-2.fc24
lzo#2.08-8.fc24
mpfr#3.1.5-1.fc24
ncurses#6.0-5.20160116.fc24
ncurses-base#6.0-5.20160116.fc24
ncurses-libs#6.0-5.20160116.fc24
nettle#3.2-2.fc24
npth#1.2-3.fc24
nspr#4.12.0-1.fc24
nss#3.23.0-1.2.fc24
nss-softokn#3.23.0-1.0.fc24
nss-softokn-freebl#3.23.0-1.0.fc24
nss-sysinit#3.23.0-1.2.fc24
nss-tools#3.23.0-1.2.fc24
nss-util#3.23.0-1.0.fc24
openldap#2.4.44-1.fc24
openssh#7.2p2-14.fc24
openssh-clients#7.2p2-14.fc24
openssl-libs#1:1.0.2h-1.fc24
p11-kit#0.23.2-2.fc24
p11-kit-trust#0.23.2-2.fc24
pam#1.2.1-5.fc24
pcre#8.38-11.fc24
php-cli#5.6.31-1.fc24
php-common#5.6.31-1.fc24
php-pecl-jsonc#1.3.10-1.fc24
pinentry#0.9.7-2.fc24
pkgconfig#1:0.29-2.fc24
popt#1.16-7.fc24
python3#3.5.1-7.fc24
python3-dnf#1.1.9-2.fc24
python3-hawkey#0.6.3-2.fc24
python3-iniparse#0.4-19.fc24
python3-libcomps#0.1.7-4.fc24
python3-librepo#1.7.18-2.fc24
python3-libs#3.5.1-7.fc24
python3-pip#8.0.2-1.fc24
python3-pygpgme#0.3-15.fc24
python3-setuptools#20.1.1-1.fc24
python3-six#1.10.0-2.fc24
qrencode-libs#3.4.2-6.fc24
readline#6.3-8.fc24
rootfiles#8.1-19.fc24
rpm#4.13.0-0.rc1.27.fc24
rpm-build-libs#4.13.0-0.rc1.27.fc24
rpm-libs#4.13.0-0.rc1.27.fc24
rpm-plugin-selinux#4.13.0-0.rc1.27.fc24
rpm-plugin-systemd-inhibit#4.13.0-0.rc1.27.fc24
rpm-python3#4.13.0-0.rc1.27.fc24
rsync#3.1.2-4.fc24
sed#4.2.2-15.fc24
setup#2.10.1-1.fc24
shadow-utils#2:4.2.1-8.fc24
shared-mime-info#1.6-1.fc24
sqlite-libs#3.11.0-3.fc24
sssd-client#1.13.4-3.fc24
system-python-libs#3.5.1-7.fc24
systemd#229-8.fc24
systemd-libs#229-8.fc24
tzdata#2016d-1.fc24
ustr#1.0.4-21.fc24
util-linux#2.28-2.fc24
vim-minimal#2:7.4.1718-1.fc24
xkeyboard-config#2.17-2.fc24
xz-libs#5.2.2-2.fc24
zlib#1.2.8-10.fc24
91b63c60a90bcece5adcfb20ff41587562666c1c
php

phpinfo()
PHP Version => 5.6.31

Build Date => Jul  6 2017 05:26:56
Server API => Command Line Interface
Virtual Directory Support => disabled
Configuration File (php.ini) Path => /etc
Loaded Configuration File => /etc/php.ini
Scan this dir for additional .ini files => /etc/php.d
Additional .ini files parsed => /etc/php.d/20-bz2.ini,
/etc/php.d/20-calendar.ini,
/etc/php.d/20-ctype.ini,
/etc/php.d/20-curl.ini,
/etc/php.d/20-exif.ini,
/etc/php.d/20-fileinfo.ini,
/etc/php.d/20-ftp.ini,
/etc/php.d/20-gettext.ini,
/etc/php.d/20-iconv.ini,
/etc/php.d/20-phar.ini,
/etc/php.d/20-sockets.ini,
/etc/php.d/20-tokenizer.ini,
/etc/php.d/40-json.ini

PHP API => 20131106
PHP Extension => 20131226
Zend Extension => 220131226
Zend Extension Build => API220131226,NTS
PHP Extension Build => API20131226,NTS
Debug Build => no
Thread Safety => disabled
Zend Signal Handling => disabled
Zend Memory Manager => enabled
Zend Multibyte Support => disabled
IPv6 Support => enabled
DTrace Support => enabled

Registered PHP Streams => https, ftps, compress.zlib, php, file, glob, data, http, ftp, compress.bzip2, phar
Registered Stream Socket Transports => tcp, udp, unix, udg, ssl, sslv3, tls, tlsv1.0, tlsv1.1, tlsv1.2
Registered Stream Filters => zlib.*, string.rot13, string.toupper, string.tolower, string.strip_tags, convert.*, consumed, dechunk, bzip2.*, convert.iconv.*

This program makes use of the Zend Scripting Language Engine:
Zend Engine v2.6.0, Copyright (c) 1998-2016 Zend Technologies


 _______________________________________________________________________


Configuration

bz2

BZip2 Support => Enabled
Stream Wrapper support => compress.bzip2://
Stream Filter support => bzip2.decompress, bzip2.compress
BZip2 Version => 1.0.6, 6-Sept-2010

calendar

Calendar support => enabled

Core

PHP Version => 5.6.31

Directive => Local Value => Master Value
allow_url_fopen => On => On
allow_url_include => Off => Off
always_populate_raw_post_data => 0 => 0
arg_separator.input => & => &
arg_separator.output => & => &
asp_tags => Off => Off
auto_append_file => no value => no value
auto_globals_jit => On => On
auto_prepend_file => no value => no value
browscap => no value => no value
default_charset => UTF-8 => UTF-8
default_mimetype => text/html => text/html
disable_classes => no value => no value
disable_functions => no value => no value
display_errors => Off => Off
display_startup_errors => Off => Off
doc_root => no value => no value
docref_ext => no value => no value
docref_root => no value => no value
enable_dl => Off => Off
enable_post_data_reading => On => On
error_append_string => no value => no value
error_log => no value => no value
error_prepend_string => no value => no value
error_reporting => 22527 => 22527
exit_on_timeout => Off => Off
expose_php => On => On
extension_dir => /usr/lib64/php/modules => /usr/lib64/php/modules
file_uploads => On => On
highlight.comment => <font style="color: #FF8000">#FF8000</font> => <font style="color: #FF8000">#FF8000</font>
highlight.default => <font style="color: #0000BB">#0000BB</font> => <font style="color: #0000BB">#0000BB</font>
highlight.html => <font style="color: #000000">#000000</font> => <font style="color: #000000">#000000</font>
highlight.keyword => <font style="color: #007700">#007700</font> => <font style="color: #007700">#007700</font>
highlight.string => <font style="color: #DD0000">#DD0000</font> => <font style="color: #DD0000">#DD0000</font>
html_errors => Off => Off
ignore_repeated_errors => Off => Off
ignore_repeated_source => Off => Off
ignore_user_abort => Off => Off
implicit_flush => On => On
include_path => .:/usr/share/pear:/usr/share/php => .:/usr/share/pear:/usr/share/php
input_encoding => no value => no value
internal_encoding => no value => no value
log_errors => On => On
log_errors_max_len => 1024 => 1024
mail.add_x_header => On => On
mail.force_extra_parameters => no value => no value
mail.log => no value => no value
max_execution_time => 0 => 0
max_file_uploads => 20 => 20
max_input_nesting_level => 64 => 64
max_input_time => -1 => -1
max_input_vars => 1000 => 1000
memory_limit => 128M => 128M
open_basedir => no value => no value
output_buffering => 0 => 0
output_encoding => no value => no value
output_handler => no value => no value
post_max_size => 8M => 8M
precision => 14 => 14
realpath_cache_size => 16K => 16K
realpath_cache_ttl => 120 => 120
register_argc_argv => On => On
report_memleaks => On => On
report_zend_debug => Off => Off
request_order => GP => GP
sendmail_from => no value => no value
sendmail_path => /usr/sbin/sendmail -t -i => /usr/sbin/sendmail -t -i
serialize_precision => 17 => 17
short_open_tag => Off => Off
SMTP => localhost => localhost
smtp_port => 25 => 25
sql.safe_mode => Off => Off
sys_temp_dir => no value => no value
track_errors => Off => Off
unserialize_callback_func => no value => no value
upload_max_filesize => 2M => 2M
upload_tmp_dir => no value => no value
user_dir => no value => no value
user_ini.cache_ttl => 300 => 300
user_ini.filename => .user.ini => .user.ini
variables_order => GPCS => GPCS
xmlrpc_error_number => 0 => 0
xmlrpc_errors => Off => Off
zend.detect_unicode => On => On
zend.enable_gc => On => On
zend.multibyte => Off => Off
zend.script_encoding => no value => no value

ctype

ctype functions => enabled

curl

cURL support => enabled
cURL Information => 7.47.1
Age => 3
Features
AsynchDNS => Yes
CharConv => No
Debug => No
GSS-Negotiate => No
IDN => Yes
IPv6 => Yes
krb4 => No
Largefile => Yes
libz => Yes
NTLM => Yes
NTLMWB => Yes
SPNEGO => Yes
SSL => Yes
SSPI => No
TLS-SRP => No
Protocols => dict, file, ftp, ftps, gopher, http, https, imap, imaps, ldap, ldaps, pop3, pop3s, rtsp, scp, sftp, smb, smbs, smtp, smtps, telnet, tftp
Host => x86_64-redhat-linux-gnu
SSL Version => NSS/3.22.2 Basic ECC
ZLib Version => 1.2.8
libSSH Version => libssh2/1.7.0

date

date/time support => enabled
"Olson" Timezone Database Version => 0.system
Timezone Database => internal
PHP Warning:  Unknown: It is not safe to rely on the system's timezone settings. You are *required* to use the date.timezone setting or the date_default_timezone_set() function. In case you used any of those methods and you are still getting this warning, you most likely misspelled the timezone identifier. We selected the timezone 'UTC' for now, but please set date.timezone to select your timezone. in Unknown on line 0
Default timezone => UTC

Directive => Local Value => Master Value
date.default_latitude => 31.7667 => 31.7667
date.default_longitude => 35.2333 => 35.2333
date.sunrise_zenith => 90.583333 => 90.583333
date.sunset_zenith => 90.583333 => 90.583333
date.timezone => no value => no value

ereg

Regex Library => Bundled library enabled

exif

EXIF Support => enabled
EXIF Version => 1.4 $Id: 1c8772f76be691b7b3f77ca31eb788a2abbcefe5 $
Supported EXIF Version => 0220
Supported filetypes => JPEG,TIFF

Directive => Local Value => Master Value
exif.decode_jis_intel => JIS => JIS
exif.decode_jis_motorola => JIS => JIS
exif.decode_unicode_intel => UCS-2LE => UCS-2LE
exif.decode_unicode_motorola => UCS-2BE => UCS-2BE
exif.encode_jis => no value => no value
exif.encode_unicode => ISO-8859-15 => ISO-8859-15

fileinfo

fileinfo support => enabled
version => 1.0.5
libmagic => 517

filter

Input Validation and Filtering => enabled
Revision => $Id: 5b79667bd9a68977a9b4f7505223a8e216e04908 $

Directive => Local Value => Master Value
filter.default => unsafe_raw => unsafe_raw
filter.default_flags => no value => no value

ftp

FTP support => enabled

gettext

GetText Support => enabled

hash

hash support => enabled
Hashing Engines => md2 md4 md5 sha1 sha224 sha256 sha384 sha512 ripemd128 ripemd160 ripemd256 ripemd320 whirlpool tiger128,3 tiger160,3 tiger192,3 tiger128,4 tiger160,4 tiger192,4 snefru snefru256 gost gost-crypto adler32 crc32 crc32b fnv132 fnv1a32 fnv164 fnv1a64 joaat haval128,3 haval160,3 haval192,3 haval224,3 haval256,3 haval128,4 haval160,4 haval192,4 haval224,4 haval256,4 haval128,5 haval160,5 haval192,5 haval224,5 haval256,5

iconv

iconv support => enabled
iconv implementation => glibc
iconv library version => 2.23

Directive => Local Value => Master Value
iconv.input_encoding => no value => no value
iconv.internal_encoding => no value => no value
iconv.output_encoding => no value => no value

json

json support => enabled
json version => 1.3.10
JSON-C version (bundled) => 0.11

libxml

libXML support => active
libXML Compiled Version => 2.9.4
libXML Loaded Version => 20903
libXML streams => enabled

mhash

MHASH support => Enabled
MHASH API Version => Emulated Support

openssl

OpenSSL support => enabled
OpenSSL Library Version => OpenSSL 1.0.2h-fips  3 May 2016
OpenSSL Header Version => OpenSSL 1.0.2k-fips  26 Jan 2017
Openssl default config => /etc/pki/tls/openssl.cnf

Directive => Local Value => Master Value
openssl.cafile => no value => no value
openssl.capath => no value => no value

pcntl

pcntl support => enabled

pcre

PCRE (Perl Compatible Regular Expressions) Support => enabled
PCRE Library Version => 8.38 2015-11-23

Directive => Local Value => Master Value
pcre.backtrack_limit => 1000000 => 1000000
pcre.recursion_limit => 100000 => 100000

Phar

Phar: PHP Archive support => enabled
Phar EXT version => 2.0.2
Phar API version => 1.1.1
SVN revision => $Id: 780be432570e80dd34c1a9c217ef87ade22bf136 $
Phar-based phar archives => enabled
Tar-based phar archives => enabled
ZIP-based phar archives => enabled
gzip compression => enabled
bzip2 compression => enabled
Native OpenSSL support => enabled


Phar based on pear/PHP_Archive, original concept by Davey Shafik.
Phar fully realized by Gregory Beaver and Marcus Boerger.
Portions of tar implementation Copyright (c) 2003-2009 Tim Kientzle.
Directive => Local Value => Master Value
phar.cache_list => no value => no value
phar.readonly => On => On
phar.require_hash => On => On

readline

Readline Support => enabled
Readline library => EditLine wrapper

Directive => Local Value => Master Value
cli.pager => no value => no value
cli.prompt => \b \>  => \b \>

Reflection

Reflection => enabled
Version => $Id: 5f15287237d5f78d75b19c26915aa7bd83dee8b8 $

session

Session Support => enabled
Registered save handlers => files user
Registered serializer handlers => php_serialize php php_binary

Directive => Local Value => Master Value
session.auto_start => Off => Off
session.cache_expire => 180 => 180
session.cache_limiter => nocache => nocache
session.cookie_domain => no value => no value
session.cookie_httponly => Off => Off
session.cookie_lifetime => 0 => 0
session.cookie_path => / => /
session.cookie_secure => Off => Off
session.entropy_file => /dev/urandom => /dev/urandom
session.entropy_length => 32 => 32
session.gc_divisor => 1000 => 1000
session.gc_maxlifetime => 1440 => 1440
session.gc_probability => 1 => 1
session.hash_bits_per_character => 5 => 5
session.hash_function => 0 => 0
session.name => PHPSESSID => PHPSESSID
session.referer_check => no value => no value
session.save_handler => files => files
session.save_path => no value => no value
session.serialize_handler => php => php
session.upload_progress.cleanup => On => On
session.upload_progress.enabled => On => On
session.upload_progress.freq => 1% => 1%
session.upload_progress.min_freq => 1 => 1
session.upload_progress.name => PHP_SESSION_UPLOAD_PROGRESS => PHP_SESSION_UPLOAD_PROGRESS
session.upload_progress.prefix => upload_progress_ => upload_progress_
session.use_cookies => On => On
session.use_only_cookies => On => On
session.use_strict_mode => Off => Off
session.use_trans_sid => 0 => 0

sockets

Sockets Support => enabled

SPL

SPL support => enabled
Interfaces => Countable, OuterIterator, RecursiveIterator, SeekableIterator, SplObserver, SplSubject
Classes => AppendIterator, ArrayIterator, ArrayObject, BadFunctionCallException, BadMethodCallException, CachingIterator, CallbackFilterIterator, DirectoryIterator, DomainException, EmptyIterator, FilesystemIterator, FilterIterator, GlobIterator, InfiniteIterator, InvalidArgumentException, IteratorIterator, LengthException, LimitIterator, LogicException, MultipleIterator, NoRewindIterator, OutOfBoundsException, OutOfRangeException, OverflowException, ParentIterator, RangeException, RecursiveArrayIterator, RecursiveCachingIterator, RecursiveCallbackFilterIterator, RecursiveDirectoryIterator, RecursiveFilterIterator, RecursiveIteratorIterator, RecursiveRegexIterator, RecursiveTreeIterator, RegexIterator, RuntimeException, SplDoublyLinkedList, SplFileInfo, SplFileObject, SplFixedArray, SplHeap, SplMinHeap, SplMaxHeap, SplObjectStorage, SplPriorityQueue, SplQueue, SplStack, SplTempFileObject, UnderflowException, UnexpectedValueException

standard

Dynamic Library Support => enabled
Path to sendmail => /usr/sbin/sendmail -t -i

Directive => Local Value => Master Value
assert.active => 1 => 1
assert.bail => 0 => 0
assert.callback => no value => no value
assert.quiet_eval => 0 => 0
assert.warning => 1 => 1
auto_detect_line_endings => 0 => 0
default_socket_timeout => 60 => 60
from => no value => no value
url_rewriter.tags => a=href,area=href,frame=src,input=src,form=fakeentry => a=href,area=href,frame=src,input=src,form=fakeentry
user_agent => no value => no value

tokenizer

Tokenizer Support => enabled

zlib

ZLib Support => enabled
Stream Wrapper => compress.zlib://
Stream Filter => zlib.inflate, zlib.deflate
Compiled Version => 1.2.8
Linked Version => 1.2.8

Directive => Local Value => Master Value
zlib.output_compression => Off => Off
zlib.output_compression_level => -1 => -1
zlib.output_handler => no value => no value

Additional Modules

Module Name

b6c9eb47e3245dd1ef0f409530adbdc917fd10a4
```
