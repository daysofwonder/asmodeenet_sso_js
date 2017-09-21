/* global require,module */
'use strict';

var URI = require('urijs');

// var apiMockEndpoints = { };

module.exports = function (grunt, proxyStatic, staticHostPort, staticPort) {
    var proxyPhp = null;
    var phpport = null;
    var prxPhpPort = null;
    return {
        settings: function (prxPhp, port, prxPhpPort_) {
            proxyPhp = prxPhp;
            phpport = port;
            phpport;
            prxPhpPort = prxPhpPort_;
        },
        ware: function (req, res, next) {
            var u = URI(req.originalUrl).normalize();
            if (!req.originalUrl.match(/(^\/.well-known\/|\.(js|css|png|jpg|json|map|svg|woff|eot|ttf|woff2)(\?|$))/)) {
                if (req.method === 'OPTIONS' && ['/main/v2/oauth/identity', '/en/signout', '/fr/signout'].indexOf(u.resource()) > -1) {
                    res.setHeader('Access-Control-Allow-Origin', '*');
                    res.setHeader('Access-Control-Allow-Methods', 'GET OPTIONS');
                    res.setHeader('Access-Control-Allow-Headers', 'Authorization, Access-Control-Allow-Origin, Origin, Accept');
                }
                // grunt.log.writeln('Query: ' + req.originalUrl+" GO TO PHP");
                return proxyPhp.web(req, res, {target: 'http://localhost:' + prxPhpPort});
            } else {
                if (u.resource() === '/jwks.json' || u.resource() === '/jwks.json?env=production') {
                    res.setHeader('Content-type', 'application/json');
                    res.setHeader('Access-Control-Allow-Origin', '*');
                    res.setHeader('Access-Control-Allow-Methods', 'GET');
                    res.setHeader('Access-Control-Allow-Headers', 'Authorization, Access-Control-Allow-Origin, Origin, Accept');
                    if (req.originalUrl === '/jwks.json') {
                        req.url = '/jwks.test.json';
                        req.originalUrl = '/jwks.test.json';
                    }
                } else if (u.resource() === '/.well-known/openid-configuration' || u.resource() === '/.well-known/openid-configuration?env=production') {
                    res.setHeader('Content-type', 'application/json');
                    res.setHeader('Access-Control-Allow-Origin', '*');
                    res.setHeader('Access-Control-Allow-Methods', 'GET');
                    res.setHeader('Access-Control-Allow-Headers', 'Authorization, Access-Control-Allow-Origin, Origin, Accept');
                }
                // grunt.log.writeln('Query: ' + req.originalUrl+" GO TO static");
                return proxyStatic.web(req, res, {target: staticHostPort});
            }
            // return next();
        }
    };
};
