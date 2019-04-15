#!/bin/bash


if [ "$1" != "local" ] && [ "$1" != "ci" ]; then
    echo "Usage ./contrib/startTestServer.sh local|ci"
    exit 1
fi

IS_CONTINUOUS_INTEGRATION=false;
if [ "$1" == "ci" ]; then
    IS_CONTINUOUS_INTEGRATION=true;
fi

SUCCESS=0

set -e -o pipefail

function finish {
    SUCCESS=$?
    rm -rf .public
    trap - EXIT TERM
    if [ $SUCCESS -ne 0 ]; then
        echo ">>> FAILURE - dumping local-backends logs for troubleshooting"
        make -C vendor/daysofwonder/local-backends platform-logs
    fi

    echo ">>> stoping local-backends"
    make -C vendor/daysofwonder/local-backends platform-destroy
    echo ">>> exit"
    exit $SUCCESS
}
trap finish EXIT TERM INT

if [ "$IS_CONTINUOUS_INTEGRATION" == true ]; then
    echo ">>> installing npm and composer for asmodeenet_sso_js."
    rm -rf target
    npm install
    curl -s -z composer.phar -o composer.phar http://getcomposer.org/composer.phar
    rm -Rf vendor/daysofwonder/*
    php composer.phar --no-ansi --no-interaction update daysofwonder/*
    php composer.phar --no-ansi --no-interaction install

    echo ">>> installing local-backends root CA in the browser"
    sudo make -C vendor/daysofwonder/local-backends init-ca
fi

echo ">>> starting local-backends"
make -C vendor/daysofwonder/local-backends platform-update
make -C vendor/daysofwonder/local-backends platform-background

echo ">>> waiting for mysql service to be up"
docker run -t --rm --network platform_default -v $(pwd):/code bash:4.4 /code/contrib/wait-for-it.sh -t 120 db:3306
sleep 1
docker run -t --rm --network platform_default -v $(pwd):/code bash:4.4 /code/contrib/wait-for-it.sh -t 120 db:3306

echo ">>> Starting test"
./node_modules/.bin/grunt test:e2eRealtestByCLI
