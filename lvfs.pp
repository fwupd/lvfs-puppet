file { '/var/www':
    ensure   => 'directory',
}
file { '/var/www/lvfs':
    ensure   => 'directory',
    owner    => 'uwsgi',
    group    => 'uwsgi',
    require  => [ File['/var/www'], Package['uwsgi'] ],
}
vcsrepo { '/var/www/lvfs/admin':
    ensure   => latest,
    provider => git,
    revision => $lvfs_revision,
    source   => 'https://github.com/hughsie/lvfs-website.git',
    user     => 'uwsgi',
    group    => 'uwsgi',
    require  => [ File['/var/www/lvfs'], Package['uwsgi']],
}
file { '/mnt/firmware/deleted':
    ensure   => 'directory',
    owner    => 'uwsgi',
    group    => 'uwsgi',
    require  => [ Vcsrepo['/var/www/lvfs/admin'], Package['uwsgi'] ],
}
file { '/var/www/lvfs/admin/hwinfo':
    ensure   => 'directory',
    owner    => 'uwsgi',
    group    => 'uwsgi',
    require  => [ Vcsrepo['/var/www/lvfs/admin'], Package['uwsgi'] ],
}
file { '/mnt/firmware/downloads':
    ensure   => 'directory',
    owner    => 'uwsgi',
    group    => 'uwsgi',
    require  => [ File['/var/www/lvfs'], Package['uwsgi'] ],
}
file { '/mnt/firmware/shards':
    ensure   => 'directory',
    owner    => 'uwsgi',
    group    => 'uwsgi',
    require  => [ File['/var/www/lvfs'], Package['uwsgi'] ],
}
file { '/var/www/lvfs/backup':
    ensure  => 'directory',
    owner   => 'uwsgi',
    group   => 'uwsgi',
    require  => [ File['/var/www/lvfs'], Package['uwsgi'] ],
}
file { '/var/www/lvfs/admin/lvfs/custom.cfg':
    ensure  => 'file',
    owner   => 'uwsgi',
    group   => 'uwsgi',
    content => "# Managed by Puppet, DO NOT EDIT
import os
DEBUG = False
PROPAGATE_EXCEPTIONS = True
SECRET_KEY = '${lvfs_secret_key}'
SECRET_PASSWORD_SALT = '${secret_password_salt}'
SECRET_ADDR_SALT = '${secret_addr_salt}'
SECRET_VENDOR_SALT = '${secret_vendor_salt}'
HOST_NAME = '${server_fqdn}'
ADMIN_EMAIL = '${admin_email}'
PREFERRED_URL_SCHEME = 'https'
APP_NAME = 'lvfs'
IP = '${server_ip}'
PORT = 80
DOWNLOAD_DIR = '/mnt/firmware/downloads'
UPLOAD_DIR = '/var/www/lvfs/admin/uploads'
RESTORE_DIR = '/mnt/firmware/deleted'
SHARD_DIR = '/mnt/firmware/shards'
HWINFO_DIR = '/var/www/lvfs/admin/hwinfo'
CERTTOOL = 'flatpak run --command=certtool --filesystem=/tmp --filesystem=/var/www/lvfs/pkcs7 org.freedesktop.fwupd'
KEYRING_DIR = '/var/www/lvfs/.gnupg'
SQLALCHEMY_DATABASE_URI = 'postgresql://${dbusername}:${dbpassword}@${dbserver}/lvfs'
SQLALCHEMY_TRACK_MODIFICATIONS = False
SQLALCHEMY_ENGINE_OPTIONS = {
    'pool_pre_ping': True,
    'pool_recycle': 300,
}
SESSION_COOKIE_SECURE = ${using_ssl}
REMEMBER_COOKIE_SECURE = ${using_ssl}
MAIL_SERVER = '${mail_server}'
MAIL_PORT = '${mail_port}'
MAIL_USE_TLS = True
MAIL_USE_SSL = False
MAIL_USERNAME = '${mail_username}'
MAIL_PASSWORD = '${mail_password}'
MAIL_DEFAULT_SENDER = ('LVFS Admin Team', '${mail_sender}')
CELERY_BROKER_URL = 'redis://localhost:6379/0'
CELERY_RESULT_BACKEND = 'redis://localhost:6379/0'
",
    require => [ File['/var/www/lvfs'], Package['uwsgi'], Vcsrepo['/var/www/lvfs/admin'] ],
}

# python deps are installed using requirements.txt where possible
package { 'bsdtar':
    ensure => installed,
}
package { 'git':
    ensure => installed,
}
package { 'python3-psutil':
    ensure => installed,
}
package { 'python3-pip':
    ensure => installed,
}
package { 'python3-virtualenv':
    ensure => installed,
}
package { 'cairo-gobject-devel':
    ensure => installed,
}
package { 'gobject-introspection-devel':
    ensure => installed,
}
exec { 'virtualenv_create':
    command     => '/usr/bin/virtualenv-3 /var/www/lvfs/admin/env',
    refreshonly => true,
    require     => [ Package['python3-virtualenv'] ],
}
exec { 'pip_requirements_install':
    command     => '/var/www/lvfs/admin/env/bin/pip3 install -r /var/www/lvfs/admin/requirements.txt',
    path        => '/usr/bin',
    refreshonly => true,
    require     => [ Vcsrepo['/var/www/lvfs/admin'], Package['python3-pip'], Exec['virtualenv_create'] ],
}

# required for the PKCS#7 support
package { 'gnutls-utils':
    ensure => installed,
}

cron { 'shards-hardlink':
    command => 'rdfind -makehardlinks true -makesymlinks false /mnt/firmware/shards >> /var/log/uwsgi/lvfs-hardlink.log 2>&1',
    user    => 'uwsgi',
    minute  => 0,
    hour    => 3,
    require => Vcsrepo['/var/www/lvfs/admin'],
}
package { 's3cmd':
    ensure => installed,
}
cron { 's3cmd-downloads':
    command => 's3cmd sync /mnt/firmware/downloads s3://lvfs >> /var/log/uwsgi/lvfs-downloads.log 2>&1',
    user    => 'root',
    minute  => 0,
    hour    => 4,
}

# set up the database
package { 'postgresql-server':
  ensure => installed,
}
package { 'postgresql-devel':
  ensure => installed,
}

# use uWSGI
package { 'uwsgi-plugin-python36':
    ensure => installed,
}
package { 'uwsgi':
    ensure => installed,
}
file { '/var/log/uwsgi':
    ensure   => 'directory',
    owner    => 'uwsgi',
    group    => 'uwsgi',
    require  => Package['uwsgi'],
}
file { '/etc/tmpfiles.d/uwsgi.conf':
    ensure => "file",
    content => "D /run/uwsgi 0770 uwsgi uwsgi -",
    require => Package['uwsgi'],
}

file { '/etc/uwsgi.d/lvfs.ini':
    ensure   => "file",
    owner    => 'uwsgi',
    group    => 'uwsgi',
    content => "# Managed by Puppet, DO NOT EDIT
[uwsgi]
chdir = /var/www/lvfs/admin
virtualenv = /var/www/lvfs/admin/env
module = lvfs:app
plugins = python36
uid = uwsgi
gid = uwsgi
socket = /run/uwsgi/%n.socket
chmod-socket = 660
logto = /var/log/uwsgi/%n.log
stats = 127.0.0.1:9191
processes = 4
buffer-size = 65536
enable-threads = true
harakiri = 180
lazy-apps = true
",
    require => Package['uwsgi'],
}
service { 'uwsgi':
    ensure => 'running',
    enable => true,
    require => [ Package['uwsgi'], File['/etc/uwsgi.d/lvfs.ini'] ],
}

exec { 'nginx-uwsgi-membership':
    unless  => '/bin/grep -q "uwsgi\\S*nginx" /etc/group',
    command => '/sbin/usermod -aG uwsgi nginx',
    require => Package['uwsgi'],
}

# start nginx load balancer
package { 'nginx':
    ensure => installed,
}
file { '/etc/nginx/nginx.conf':
    ensure => "file",
    content => "# Managed by Puppet, DO NOT EDIT
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log;
pid /run/nginx.pid;

events {
    worker_connections 1024;
}

http {
    log_format  main  '\$remote_addr - \$remote_user [\$time_local] \"\$request\" '
                      '\$status \$body_bytes_sent \"\$http_referer\" '
                      '\"\$http_user_agent\" \"\$http_x_forwarded_for\"';

    access_log  /var/log/nginx/access.log  main;

    sendfile            on;
    tcp_nopush          on;
    tcp_nodelay         on;
    keepalive_timeout   65;
    types_hash_max_size 2048;

    include             /etc/nginx/mime.types;
    default_type        application/octet-stream;

    include /etc/nginx/conf.d/*.conf;

    server {
        listen       80 default_server;
        listen       [::]:80 default_server;

        server_name  ${server_fqdn};
        root         /usr/share/nginx/html;
        client_max_body_size 80M;

        # only allow http:// URIs
        if (\$scheme != \"https\") {
            return 301 https://\$server_name\$request_uri;
        }

        # the www is not required
        if (\$host ~ '^www\.') {
            return 301 https://\$server_name\$request_uri;
        }

        # old REST routes
        rewrite ^/lvfs/device/(.*)\$ https://fwupd.org/lvfs/devices/\$1 permanent;

        # support SSL using Let's Encrypt
        listen       443 ssl;
        ssl_certificate /etc/letsencrypt/live/${server_fqdn}/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/${server_fqdn}/privkey.pem;
        include /etc/letsencrypt/options-ssl-nginx.conf;
        ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;
        location /.well-known/ {
            alias /var/www/.well-known/;
        }

        location /flower/ {
            rewrite ^/flower/(.*)\$ /\$1 break;
            proxy_pass http://localhost:5555;
            proxy_set_header Host \$host;
        }

        # Prevent browsers from incorrectly detecting non-scripts as scripts
        # https://wiki.mozilla.org/Security/Guidelines/Web_Security#X-Content-Type-Options
        add_header X-Content-Type-Options nosniff;

        # Prevents external sites from embedding this site in an iframe
        # https://wiki.mozilla.org/Security/Guidelines/Web_Security#X-Frame-Options
        add_header X-Frame-Options DENY;

        # Block pages from loading when they detect reflected XSS attacks
        # https://wiki.mozilla.org/Security/Guidelines/Web_Security#X-XSS-Protection
        add_header X-XSS-Protection \"1; mode=block\";

        # Restrict the Referer header to preserve the users privacy
        # https://wiki.mozilla.org/Security/Guidelines/Web_Security#Referrer_Policy
        add_header Referrer-Policy same-origin;

        # Block site from being framed with X-Frame-Options
        # https://wiki.mozilla.org/Security/Guidelines/Web_Security#X-Frame-Options
        add_header X-Frame-Options DENY;

        # Only connect to this site via HTTPS
        # https://wiki.mozilla.org/Security/Guidelines/Web_Security#HTTP_Strict_Transport_Security
        add_header Strict-Transport-Security \"max-age=63072000; includeSubDomains; preload\";

        # Block pages from loading when they detect reflected XSS attacks
        # https://wiki.mozilla.org/Security/Guidelines/Web_Security#Content_Security_Policy
        add_header Content-Security-Policy \"default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://stackpath.bootstrapcdn.com https://code.jquery.com https://cdnjs.cloudflare.com; img-src 'self' data:; style-src 'self' 'unsafe-inline' https://stackpath.bootstrapcdn.com https://fonts.googleapis.com https://use.fontawesome.com; font-src 'self' https://fonts.gstatic.com https://use.fontawesome.com; frame-ancestors 'none'\";

        # Load configuration files for the default server block.
        include /etc/nginx/default.d/*.conf;

        location /static/ {
            alias /var/www/lvfs/admin/lvfs/static/;
        }
        location /uploads/ {
            alias /var/www/lvfs/admin/uploads/;
        }
        location /downloads/firmware.xml.gz {
            alias /mnt/firmware/downloads/firmware.xml.gz;
            expires 20m;
        }
        location /downloads/firmware.xml.gz.asc {
            alias /mnt/firmware/downloads/firmware.xml.gz.asc;
            expires 20m;
        }
        location / {
            uwsgi_read_timeout 180s;
            uwsgi_send_timeout 180s;
            uwsgi_pass unix:///run/uwsgi/lvfs.socket;
            include uwsgi_params;
        }

        error_page 404 /404.html;
            location = /40x.html {
        }

        error_page 500 502 503 504 /50x.html;
            location = /50x.html {
            alias /var/www/lvfs/admin/lvfs/templates/50x.html;
        }
    }
}
",
    require => [ Package['nginx'], Vcsrepo['/var/www/lvfs/admin'] ],
}
service { 'nginx':
    ensure => 'running',
    enable => true,
    require => [ Package['nginx'], Package['uwsgi'] ],
}
package { 'rdfind':
    ensure => installed,
}

# allow monitoring server
package { 'munin':
    ensure => installed,
}
package { 'munin-plugins-ruby':
    ensure => installed,
}
service { 'munin-node':
    ensure   => 'running',
    enable   => true,
    require  => Package["munin"],
}
package { 'httpd-tools':
    ensure => installed,
}
exec { "munin-htpasswd":
    command     => "/usr/bin/htpasswd -cb /etc/munin/munin-htpasswd ${munin_username} ${munin_password}",
    unless      => "/usr/bin/test -s /etc/munin/munin-htpasswd",
    require     => [ Package["munin"], Package['httpd-tools'] ],
}
file { '/etc/munin/conf.d/local.conf':
    ensure => "file",
    content => "# Managed by Puppet, DO NOT EDIT
[www.fwupd.org]
    address 127.0.0.1
    use_node_name yes
",
    require => Package['munin'],
}
file { '/etc/nginx/default.d/munin.conf':
    ensure => "file",
    content => "# Managed by Puppet, DO NOT EDIT
location /munin/static/ {
    alias /etc/munin/static/;
    expires modified +1w;
}

location /munin/ {
    auth_basic Restricted;
    auth_basic_user_file /etc/munin/munin-htpasswd;
    alias /var/www/html/munin/;
    expires modified +310s;
}
",
    require => Package['nginx'],
}


# celery
package { 'redis':
    ensure => installed,
}
service { 'redis':
    ensure   => 'running',
    enable   => true,
    require  => Package["redis"],
}
file { '/etc/tmpfiles.d/celery.conf':
    ensure => "file",
    content => "# Managed by Puppet, DO NOT EDIT
d /var/run/celery 0755 uwsgi uwsgi -
d /var/log/celery 0755 uwsgi uwsgi -
",
    require => Exec['pip_requirements_install'],
}
file { '/etc/conf.d':
    ensure   => 'directory',
}
file { '/var/run/celery':
    ensure   => 'directory',
    owner    => 'uwsgi',
    group    => 'uwsgi',
    require  => Package['uwsgi'],
}
file { '/var/log/celery':
    ensure   => 'directory',
    owner    => 'uwsgi',
    group    => 'uwsgi',
    require  => Package['uwsgi'],
}
file { '/etc/conf.d/celery':
    ensure => "file",
    content => "# Managed by Puppet, DO NOT EDIT
# Name of nodes to start
CELERYD_NODES=\"w1\"

# Absolute or relative path to the 'celery' command:
CELERY_BIN=\"/var/www/lvfs/admin/env/bin/celery\"

# App instance to use
CELERY_APP=\"lvfs.celery\"

# How to call manage.py
CELERYD_MULTI=\"multi\"

# How to call manage.py
CELERYD_QUEUES=\"metadata,firmware,celery,yara\"

# Extra command-line arguments to the worker
#CELERYD_OPTS=\"--time-limit=300 --concurrency=8\"

# - %n will be replaced with the first part of the nodename.
# - %I will be replaced with the current child process index
#   and is important when using the prefork pool to avoid race conditions.
CELERYD_PID_FILE=\"/var/run/celery/%n.pid\"
CELERYD_LOG_FILE=\"/var/log/celery/%n%I.log\"
CELERYD_LOG_LEVEL=\"INFO\"

# you may wish to add these options for Celery Beat
CELERYBEAT_PID_FILE=\"/var/run/celery/beat.pid\"
CELERYBEAT_SCHEDULE=\"/var/run/celery/beat-schedule\"
CELERYBEAT_LOG_FILE=\"/var/log/celery/beat.log\"
",
    require => [ File['/etc/conf.d'], Vcsrepo['/var/www/lvfs/admin'] ],
}
file { '/etc/systemd/system/celery.service':
    ensure => "file",
    content => "# Managed by Puppet, DO NOT EDIT
[Unit]
Description=Celery Service
After=network.target

[Service]
Type=forking
User=uwsgi
Group=uwsgi
EnvironmentFile=/etc/conf.d/celery
WorkingDirectory=/var/www/lvfs/admin
ExecStart=/bin/sh -c '\${CELERY_BIN} multi start \${CELERYD_NODES} \
  -A \${CELERY_APP} \
  --pidfile=\${CELERYD_PID_FILE} \
  --queues=\${CELERYD_QUEUES} \
  --logfile=\${CELERYD_LOG_FILE} \
  --loglevel=\${CELERYD_LOG_LEVEL} \
  \${CELERYD_OPTS}'
ExecStop=/bin/sh -c '\${CELERY_BIN} multi stopwait \${CELERYD_NODES} \
  --pidfile=\${CELERYD_PID_FILE}'
ExecReload=/bin/sh -c '\${CELERY_BIN} multi restart \${CELERYD_NODES} \
  -A \${CELERY_APP} --pidfile=\${CELERYD_PID_FILE} \
  --logfile=\${CELERYD_LOG_FILE} --loglevel=\${CELERYD_LOG_LEVEL} \${CELERYD_OPTS}'

[Install]
WantedBy=multi-user.target
",
    require => [ Exec['pip_requirements_install'], Package['uwsgi'] ],
}
service { 'celery':
    ensure   => 'running',
    enable   => true,
    require  => File["/etc/systemd/system/celery.service"],
}

file { '/etc/systemd/system/celerybeat.service':
    ensure => "file",
    content => "# Managed by Puppet, DO NOT EDIT
[Unit]
Description=Celery Beat Service
After=network.target

[Service]
Type=simple
User=uwsgi
Group=uwsgi
EnvironmentFile=/etc/conf.d/celery
WorkingDirectory=/var/www/lvfs/admin
ExecStart=/bin/sh -c '\${CELERY_BIN} beat \
  -A \${CELERY_APP} \
  --pidfile=\${CELERYBEAT_PID_FILE} \
  --logfile=\${CELERYBEAT_LOG_FILE} \
  --loglevel=\${CELERYD_LOG_LEVEL} \
  --schedule=\${CELERYBEAT_SCHEDULE}'

[Install]
WantedBy=multi-user.target
",
    require => [ Exec['pip_requirements_install'], Package['uwsgi'] ],
}
service { 'celerybeat':
    ensure   => 'running',
    enable   => true,
    require  => File["/etc/systemd/system/celerybeat.service"],
}

file { '/etc/systemd/system/flower.service':
    ensure => "file",
    content => "# Managed by Puppet, DO NOT EDIT
[Unit]
Description=Flower celery UI
After=network.target

[Service]
Type=simple
User=uwsgi
Group=uwsgi
EnvironmentFile=/etc/conf.d/celery
WorkingDirectory=/var/www/lvfs/admin
ExecStart=/bin/sh -c '\${CELERY_BIN} flower -A \${CELERY_APP}'

[Install]
WantedBy=multi-user.target
",
    require => [ Exec['pip_requirements_install'], Package['uwsgi'] ],
}
file { '/var/www/lvfs/admin/flowerconfig.py':
    ensure => "file",
    content => "# Managed by Puppet, DO NOT EDIT
broker = 'redis://localhost:6379/0'
url_prefix = '/flower/'
basic_auth = ['${munin_username}:${munin_password}']
persistent = True
",
    require => Vcsrepo['/var/www/lvfs/admin'],
}
service { 'flower':
    ensure   => 'running',
    enable   => true,
    require  => File["/etc/systemd/system/flower.service"],
}

# logrotate
package { 'logrotate':
    ensure => installed,
}
file { '/etc/logrotate.d/uwsgi':
    ensure => "file",
    content => "# Managed by Puppet, DO NOT EDIT
\"/var/log/uwsgi/*.log\" {
    copytruncate
    monthly
    dateext
    rotate 3650
    compress
    delaycompress
    notifempty
    missingok
    sharedscripts
    create 777 root root
    postrotate
        systemctl restart uwsgi >/dev/null 2>&1
    endscript
}
",
    require => Package['logrotate'],
}

# antivirus
package { 'clamav-update':
    ensure => installed,
}
package { 'clamav':
    ensure => installed,
}
exec { 'uwsgi virusgroup membership':
    unless => "/bin/getent group virusgroup|/bin/cut -d: -f4|/bin/grep -q uwsgi",
    command => "/usr/sbin/usermod -a -G virusgroup uwsgi",
    require => Package['uwsgi'],
}
file { '/etc/clamd.d/scan.conf':
    ensure => "file",
    content => "# Managed by Puppet, DO NOT EDIT
LogSyslog yes
LocalSocket /var/run/clamd.scan/clamd.sock
LocalSocketGroup virusgroup
FixStaleSocket yes
User clamscan
DetectPUA yes
DisableCertCheck yes
ScanSWF no
ScanMail no
ScanPartialMessages no
ScanArchive yes
MaxFileSize 100M
MaxEmbeddedPE 100M
",
    require => Package['clamav'],
}
service { 'clamd@scan':
    ensure => 'running',
    enable => true,
    require => [ Package['clamav'], File['/etc/clamd.d/scan.conf'] ],
}

# fixes permissions after a key has been imported
file { '/var/www/lvfs/.gnupg':
    ensure   => 'directory',
    owner    => 'uwsgi',
    group    => 'uwsgi',
    require  => File['/var/www/lvfs'],
}
exec { 'gnupg-uwsgi-chown':
    command  => "/bin/chown -R uwsgi:uwsgi /var/www/lvfs/.gnupg/",
    require  => File['/var/www/lvfs/.gnupg'],
}
