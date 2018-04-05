#!/bin/bash


if [ "$1" != "local" ] && [ "$1" != "ci" ]; then
    echo "Usage ./contrib/startTestServer.sh local|ci"
    exit 1
fi

IS_CONTINUOUS_INTEGRATION=false;
if [ "$1" == "ci" ]; then
    IS_CONTINUOUS_INTEGRATION=true;
fi

set -ea

function finish {
    rm -rf .public
    if [ -n "$PID" ]; then
        kill $PID
        export PID=
    fi
    if [ -n "$ISPID" ]; then
        kill $ISPID
        export ISPID=
    fi
}
trap finish EXIT SIGINT SIGTERM ERR

# if [ "$IS_CONTINUOUS_INTEGRATION" == true ]; then
    echo "installing npm and composer for asmodeenet_sso_js."
    rm -rf target
    npm install
    if [ ! -d "./asmodeenet_platform/identity-server" ]; then
        mkdir -p ./asmodeenet_platform/identity-server
    fi
    cd ./asmodeenet_platform/identity-server
    ret=$(find ./ -type f -iname .gitignore)
    if [ "" == "${ret}" ]; then
        git clone git@github.com:daysofwonder/identity-server.git ./
        git checkout master
    else
        git reset --hard master
    fi
    curl -s -z composer.phar -o composer.phar http://getcomposer.org/composer.phar
    php composer.phar --no-ansi --no-interaction install
    cd -
# fi

# Start IdentityServer
echo "generate .env and .env.acceptance"
cat <<'EOF' >./asmodeenet_platform/identity-server/.env.acceptance
DBADMIN_USER="dbadmin"
DBADMIN_PASSWORD="v3rys3cr3t"
DB_USER="dbforum"
DB_PASSWORD="tro1o1o1"

RATELIMIT_BUCKETS="ratelimit-acceptance.json"
CDN_ROOT="http://localhost:8209"
# BASE_ASSETS_PATH=http://cdn.asmodee.net/is/

# Rate Limit -> 1000 requests/hour per user (or IP)
RATELIMIT_LIMIT=1000000000
RATELIMIT_WINDOW="1h"

MOCK_EMAIL="true"
SITE="http://localhost:8209"
RESTAPI_BASEURL="http://localhost:8108"
APPLICATION_ENV="localtest"
SERVER_NAME=local_acceptance_test
EMAIL_SENDER="registration@asmodee.net,Asmodee.net"

# Add it for staging/prod env data
# mailhog default in the db VM
# SMTP_HOST="192.168.5.35"
# SMTP_PORT="1025"
# MAILHOG_HOST="192.168.5.35"
# MAILHOG_PORT="8025"
# RATELIMIT_LIMIT=100000000000
# AWS_ACCESS_KEY=""
# AWS_SECRET=""
# SENDGRID_SMTP_HOST="192.168.5.35"
# SENDGRID_SMTP_PORT="1025"
# EMAIL_SENDER="registration@asmodee.net,Asmodee.net"
EOF

if [ "$IS_CONTINUOUS_INTEGRATION" == true ]; then
    cat <<'EOF' >>./asmodeenet_platform/identity-server/.env.acceptance
DB_DSN="mysql:dbname=acceptance_asnet_sso_js;host=localhost"
REDIS_DSN="redis://127.0.0.1/?password=v3rys3cr3t"
EOF
else
    cat <<'EOF' >>./asmodeenet_platform/identity-server/.env.acceptance
DB_DSN="mysql:dbname=acceptance_asnet_sso_js;host=192.168.5.35"
REDIS_DSN="redis://192.168.5.35/?password=v3rys3cr3t&database=2"
EOF
fi

cd ./asmodeenet_platform/identity-server/
if [ -f ".env" ]; then
    rm .env
fi
ln -sf .env.acceptance .env
cd -

echo "generate openid-configuration"
cat ./asmodeenet_platform/identity-server/public/.well-known/openid-configuration.test | sed -e 's/localhost:8010/localhost:8209/' > ./asmodeenet_platform/identity-server/public/.well-known/openid-configuration

if [ -f asmodeenet_platform/identity-server/vendor/daysofwonder/db-migrations/projects/asnet/db_data.sql.bckup ]; then
    cp asmodeenet_platform/identity-server/vendor/daysofwonder/db-migrations/projects/asnet/db_data.sql.bckup asmodeenet_platform/identity-server/vendor/daysofwonder/db-migrations/projects/asnet/db_data.sql
fi

cp asmodeenet_platform/identity-server/vendor/daysofwonder/db-migrations/projects/asnet/db_data.sql asmodeenet_platform/identity-server/vendor/daysofwonder/db-migrations/projects/asnet/db_data.sql.bckup

cat contrib/extra_data_e2e.sql >> asmodeenet_platform/identity-server/vendor/daysofwonder/db-migrations/projects/asnet/db_data.sql

mkdir -p asmodeenet_platform/identity-server/contrib/db

source asmodeenet_platform/identity-server/.env.acceptance

cd asmodeenet_platform/identity-server/
echo "make reset-db"
make reset-db

echo "make assets-dev"
make assets-dev

cd -

echo "prepare autoload"
# mkdir -p ./asmodeenet_platform/identity-server/.public
cp ./asmodeenet_platform/identity-server/public/index.php ./asmodeenet_platform/identity-server/public/index.php.backup
cat <<'EOF' >./asmodeenet_platform/identity-server/public/index.php
<?php

// This is a gross hack to allow running under apache on production
// under a folder inside an existing apache webroot
$_SERVER['SCRIPT_NAME'] = '/index.php';

// load our vendor libraries + setup our own PSR4 autoload
require_once __DIR__ . '/../vendor/autoload.php';

require __DIR__ . '/../src/bootstrap.php';
EOF

exit 0
