/* global any */

describe('AsmodeeNet Main Object', function () {
    var tstore = {};
    var onStoreSet, onStoreRemove, onStoreGet, onStoreClear;
    beforeEach(function () {
        window.store = {
            set: function () {
                expect(arguments.length).toEqual(3);
                tstore[arguments[0]] = {val: arguments[1], limit: arguments[2]};
            },
            get: function () {
                expect(arguments.length).toEqual(1);
                if (typeof tstore[arguments[0]] === 'undefined') {
                    return null;
                }
                if (tstore[arguments[0]].limit < (new Date().getTime())) {
                    delete tstore[arguments[0]];
                    return null;
                }
                return tstore[arguments[0]].val;
            },
            remove: function () {
                if (typeof tstore[arguments[0]] !== 'undefined') {
                    delete tstore[arguments[0]];
                }
            },
            clearAll: function () {
                tstore = {};
            }
        };
        onStoreSet = spyOn(window.store, 'set').and.callThrough();
        onStoreGet = spyOn(window.store, 'get').and.callThrough();
        onStoreRemove = spyOn(window.store, 'remove').and.callThrough();
        onStoreClear = spyOn(window.store, 'clearAll').and.callThrough();
    });

    describe('should provide ajax query helpers', function () {
        var request, onSuccess, onFailure, onComplete;

        beforeEach(function () {
            jasmine.Ajax.install();

            onComplete = jasmine.createSpy('onComplete');
            onSuccess = jasmine.createSpy('onSuccess');
            onFailure = jasmine.createSpy('onFailure');
        });

        afterEach(function () {
            jasmine.Ajax.uninstall();
        });

        it('should be have an AsmodeeNet.ajax base object and a AsmodeeNet.ajaxq base helper', function () {
            expect(window.AsmodeeNet.ajaxq).toBeDefined();
            expect(window.AsmodeeNet.ajaxq).toBeFunction();
            expect(window.AsmodeeNet.ajax).toBeDefined();
            expect(window.AsmodeeNet.ajax).toBeFunction();
        });

        it('should be have an AsmodeeNet specialized helpers', function () {
            expect(window.AsmodeeNet.get).toBeDefined();
            expect(window.AsmodeeNet.get).toBeFunction();
            expect(window.AsmodeeNet.post).toBeDefined();
            expect(window.AsmodeeNet.post).toBeFunction();
            expect(window.AsmodeeNet.update).toBeDefined();
            expect(window.AsmodeeNet.update).toBeFunction();
            expect(window.AsmodeeNet.delete).toBeDefined();
            expect(window.AsmodeeNet.delete).toBeFunction();
        });

        [
            [
                '/tr', 'get', null, 'GET', {'status': 200, 'contentType': 'text/plain', 'responseText': 'BOB'}, {
                    complete: {
                        call: 1,
                        args: {
                            count: 2,
                            res: [
                                ['object', 'FakeXMLHttpRequest'],
                                ['string', 'success']
                            ]
                        }
                    },
                    success: {
                        call: 1,
                        args: {
                            count: 3,
                            res: [
                                ['string', 'BOB'],
                                ['string', 'success'],
                                ['object', 'FakeXMLHttpRequest']
                            ]
                        }
                    },
                    failure: null
                }
            ],
            [
                '/trpost', 'post', {name: 'BOBBY', count: 3}, 'POST', {'status': 200, 'contentType': 'application/json', 'responseText': '{"entry": "BOB"}'}, {
                    complete: {
                        call: 1,
                        args: {
                            count: 2,
                            res: [
                                ['object', 'FakeXMLHttpRequest'],
                                ['string', 'success']
                            ]
                        }
                    },
                    success: {
                        call: 1,
                        args: {
                            count: 3,
                            res: [
                                ['object', {entry: 'BOB'}],
                                ['string', 'success'],
                                ['object', 'FakeXMLHttpRequest']
                            ]
                        }
                    },
                    failure: null
                }
            ],
            [
                '/trdelete', 'delete', null, 'DELETE', {'status': 204, 'contentType': 'text/plain', 'responseText': ''}, {
                    complete: {
                        call: 1,
                        args: {
                            count: 2,
                            res: [
                                ['object', 'FakeXMLHttpRequest'],
                                ['string', 'success']
                            ]
                        }
                    },
                    success: {
                        call: 1,
                        args: {
                            count: 3,
                            res: [
                                ['string', ''],
                                ['string', 'success'],
                                ['object', 'FakeXMLHttpRequest']
                            ]
                        }
                    },
                    failure: null
                }
            ],
            [
                '/trdelete', 'update', {id: 100, col: 'BOB'}, 'PUT', {'status': 200, 'contentType': 'text/plain', 'responseText': 'Updated'}, {
                    complete: {
                        call: 1,
                        args: {
                            count: 2,
                            res: [
                                ['object', 'FakeXMLHttpRequest'],
                                ['string', 'success']
                            ]
                        }
                    },
                    success: {
                        call: 1,
                        args: {
                            count: 3,
                            res: [
                                ['string', 'Updated'],
                                ['string', 'success'],
                                ['object', 'FakeXMLHttpRequest']
                            ]
                        }
                    },
                    failure: null
                }
            ],
            [
                '/ntf', 'get', null, 'GET', {'status': 404, 'contentType': 'text/plain', 'responseText': 'not found ntf'}, {
                    complete: {
                        call: 1,
                        args: {
                            count: 2,
                            res: [
                                ['object', 'FakeXMLHttpRequest'],
                                ['string', 'error']
                            ]
                        }
                    },
                    failure: {
                        call: 1,
                        args: {
                            count: 3,
                            res: [
                                ['object', 'FakeXMLHttpRequest'],
                                ['string', 'error'],
                                ['string', 'not found ntf']
                            ]
                        }
                    },
                    success: null
                }
            ],
            [
                '/ntf', 'post', {id: 4546, name: 'BB'}, 'POST', {'status': 406, 'contentType': 'application/json', 'responseText': '{"error": "API006", "error_details": "BLOBB"}'}, {
                    complete: {
                        call: 1,
                        args: {
                            count: 2,
                            res: [
                                ['object', 'FakeXMLHttpRequest'],
                                ['string', 'error']
                            ]
                        }
                    },
                    failure: {
                        call: 1,
                        args: {
                            count: 3,
                            res: [
                                ['object', 'FakeXMLHttpRequest'],
                                ['string', 'error'],
                                ['object', {error: 'API006', error_details: 'BLOBB'}]
                            ]
                        }
                    },
                    success: null
                }
            ],
            [
                '/ntf/9', 'delete', null, 'DELETE', {'status': 403, 'contentType': 'application/json', 'responseText': '{"error": "API018", "error_details": "BLOBB"}'}, {
                    complete: {
                        call: 1,
                        args: {
                            count: 2,
                            res: [
                                ['object', 'FakeXMLHttpRequest'],
                                ['string', 'error']
                            ]
                        }
                    },
                    failure: {
                        call: 1,
                        args: {
                            count: 3,
                            res: [
                                ['object', 'FakeXMLHttpRequest'],
                                ['string', 'error'],
                                ['object', {error: 'API018', error_details: 'BLOBB'}]
                            ]
                        }
                    },
                    success: null
                }
            ],
            [
                '/ntf/9', 'update', {blob: 'OIO'}, 'PUT', {'status': 401, 'contentType': 'text/plain', 'responseText': 'Not auth'}, {
                    complete: {
                        call: 1,
                        args: {
                            count: 2,
                            res: [
                                ['object', 'FakeXMLHttpRequest'],
                                ['string', 'error']
                            ]
                        }
                    },
                    failure: {
                        call: 1,
                        args: {
                            count: 3,
                            res: [
                                ['object', 'FakeXMLHttpRequest'],
                                ['string', 'error'],
                                ['string', 'Not auth']
                            ]
                        }
                    },
                    success: null
                }
            ]
        ].forEach(function (data) {
            it('should execute ' + data[1] + ' ajax query with ' + (data[3].status < 400 ? 'success' : 'error'), function () {
                onComplete = jasmine.createSpy('onComplete');
                onSuccess = jasmine.createSpy('onSuccess');
                onFailure = jasmine.createSpy('onFailure');
                var onAjaxq = spyOn(window.AsmodeeNet, 'ajaxq').and.callThrough();

                window.AsmodeeNet[data[1]](data[0], {
                    success: onSuccess,
                    error: onFailure,
                    complete: onComplete,
                    data: data[2]
                });

                expect(onAjaxq).toHaveBeenCalled();
                expect(onComplete).not.toHaveBeenCalled();
                expect(onSuccess).not.toHaveBeenCalled();
                expect(onFailure).not.toHaveBeenCalled();

                request = jasmine.Ajax.requests.mostRecent();
                expect(request.url).toBe('https://api.asmodee.net/main/v1' + data[0]);
                expect(request.method).toBe(data[3]);
                if (data[2] !== null) {
                    expect(request.params).toEqual(data[2]);
                }

                request.respondWith(data[4]);

                for (var type in data[5]) {
                    if (data[5].hasOwnProperty(type)) {
                        var args = null;
                        var typedData = data[5][type];
                        if (type === 'complete') {
                            if (typedData === null) {
                                expect(onComplete).not.toHaveBeenCalled();
                            } else {
                                expect(onComplete).toHaveBeenCalledTimes(typedData.call);
                                args = onComplete.calls.mostRecent().args;
                            }
                        } else if (type === 'success') {
                            if (typedData === null) {
                                expect(onSuccess).not.toHaveBeenCalled();
                            } else {
                                expect(onSuccess).toHaveBeenCalledTimes(typedData.call);
                                args = onSuccess.calls.mostRecent().args;
                            }
                        } else if (type === 'failure') {
                            if (typedData === null) {
                                expect(onFailure).not.toHaveBeenCalled();
                            } else {
                                expect(onFailure).toHaveBeenCalledTimes(typedData.call);
                                args = onFailure.calls.mostRecent().args;
                            }
                        }
                        if (typedData !== null) {
                            expect(args.length).toBe(typedData.args.count);
                            for (var i = 0; i < typedData.args.count; i++) {
                                if (typedData.args.res[i][0] === 'string') {
                                    expect(args[i]).toBeString();
                                    expect(args[i]).toEqual(typedData.args.res[i][1]);
                                } else if (typedData.args.res[i][0] === 'object') {
                                    expect(args[i]).toBeObject();
                                    if (typeof typedData.args.res[i][1] === 'string') {
                                        expect(args[i]).toBeInstanceOf(typedData.args.res[i][1]);
                                    } else {
                                        expect(args[i]).toEqual(typedData.args.res[i][1]);
                                    }
                                }
                            }
                        }
                    }
                }
            });
        });
    });

    describe('should be initialized and configured', function () {
        it('should have default init with popup', function () {
            expect(window.AsmodeeNet.init).toBeDefined();
            expect(window.AsmodeeNet.init).toBeFunction();

            window.AsmodeeNet.init({
                client_id: 'bob_id'
            });

            expect(window.AsmodeeNet.getClientId()).toEqual('bob_id');
            var settings = window.AsmodeeNet.getSettings();
            expect(settings.base_is_host).toEqual('https://account.asmodee.net');
            expect(settings.base_is_path).toEqual('/main/v2/oauth');
            expect(settings.logout_endpoint).toEqual('/main/v2/logout');
            expect(settings.base_url).toEqual('https://api.asmodee.net/main/v1');
            expect(settings.redirect_uri).toEqual(null);
            expect(settings.cancel_uri).toEqual(null);
            expect(settings.logout_redirect_uri).toEqual(null);
            expect(settings.display).toEqual('popup');
            expect(settings.scope).toEqual('openid+profile');
            expect(settings.callback_signin_success).toBeFunction();
            expect(settings.callback_signin_error).toBeFunction();
            expect(settings.callback_post_logout_redirect).toEqual(null);
            expect(settings.display_options).toEqual({noheader: false, nofooter: false, lnk2bt: false, leglnk: true});
        });

        it('should have default init with page and callback', function () {
            var cbSuccess = function () { return 'success'; };
            var cbError = function () { return 'error'; };
            var cbLogout = function () { return 'logout'; };

            window.AsmodeeNet.init({
                client_id: 'cli_id',
                redirect_uri: 'http://basehost.net/cb',
                display: 'page',
                scope: 'openid+email+private',
                logout_redirect_uri: 'http://basehost.net/logout',
                callback_signin_success: cbSuccess,
                callback_signin_error: cbError,
                callback_post_logout_redirect: cbLogout,
                display_options: {lnk2bt: true}
            });

            expect(window.AsmodeeNet.getClientId()).toEqual('cli_id');
            var settings = window.AsmodeeNet.getSettings();
            expect(settings.base_is_host).toEqual('https://account.asmodee.net');
            expect(settings.base_is_path).toEqual('/main/v2/oauth');
            expect(settings.logout_endpoint).toEqual('/main/v2/logout');
            expect(settings.base_url).toEqual('https://api.asmodee.net/main/v1');
            expect(settings.redirect_uri).toEqual('http://basehost.net/cb');
            expect(settings.cancel_uri).toEqual(null);
            expect(settings.logout_redirect_uri).toEqual('http://basehost.net/logout');
            expect(settings.display).toEqual('page');
            expect(settings.scope).toEqual('openid+email+private');
            expect(settings.callback_signin_success).toEqual(cbSuccess);
            expect(settings.callback_signin_error).toEqual(cbError);
            expect(settings.callback_post_logout_redirect).toEqual(cbLogout);
            expect(settings.display_options).toEqual({lnk2bt: true});
        });

        it('should have default init with touch without callback', function () {
            window.AsmodeeNet.init({
                client_id: 'cli_id',
                display: 'touch'
            });

            expect(window.AsmodeeNet.getClientId()).toEqual('cli_id');
            var settings = window.AsmodeeNet.getSettings();
            expect(settings.base_is_host).toEqual('https://account.asmodee.net');
            expect(settings.base_is_path).toEqual('/main/v2/oauth');
            expect(settings.logout_endpoint).toEqual('/main/v2/logout');
            expect(settings.base_url).toEqual('https://api.asmodee.net/main/v1');
            expect(settings.redirect_uri).toEqual(null);
            expect(settings.cancel_uri).toEqual(null);
            expect(settings.logout_redirect_uri).toEqual(null);
            expect(settings.display).toEqual('touch');
            expect(settings.scope).toEqual('openid+profile');
            expect(settings.callback_signin_success).toBeFunction();
            expect(settings.callback_signin_error).toBeFunction();
            expect(settings.callback_post_logout_redirect).toEqual(null);
            expect(settings.display_options).toEqual({noheader: true, nofooter: true, lnk2bt: true, leglnk: false});
        });

        it('should have default init with iframe with callback', function () {
            var cbSuccess = function () { return 'success'; };
            var cbError = function () { return 'error'; };
            var cbLogout = function () { return 'logout'; };

            window.AsmodeeNet.init({
                client_id: 'cli_id',
                display: 'iframe',
                callback_signin_success: cbSuccess,
                callback_signin_error: cbError,
                callback_post_logout_redirect: cbLogout
            });

            expect(window.AsmodeeNet.getClientId()).toEqual('cli_id');
            var settings = window.AsmodeeNet.getSettings();
            expect(settings.base_is_host).toEqual('https://account.asmodee.net');
            expect(settings.base_is_path).toEqual('/main/v2/oauth');
            expect(settings.logout_endpoint).toEqual('/main/v2/logout');
            expect(settings.base_url).toEqual('https://api.asmodee.net/main/v1');
            expect(settings.redirect_uri).toEqual(null);
            expect(settings.cancel_uri).toEqual(null);
            expect(settings.logout_redirect_uri).toEqual(null);
            expect(settings.display).toEqual('iframe');
            expect(settings.scope).toEqual('openid+profile');
            expect(settings.callback_signin_success).toEqual(cbSuccess);
            expect(settings.callback_signin_error).toEqual(cbError);
            expect(settings.callback_post_logout_redirect).toEqual(cbLogout);
            expect(settings.display_options).toEqual({noheader: true, nofooter: true, lnk2bt: true, leglnk: false});
        });
    });

    describe('should can call OpenIDConnect discover after initialized', function () {
        var request;

        var responseForWellKnown = {
            status: 200,
            contentType: 'application/json',
            responseText: '{"issuer":"http://localhost:8009","authorization_endpoint":"http://localhost:8009/main/v2/oauth/authorize","token_endpoint":"http://localhost:8009/main/v2/oauth/token","userinfo_endpoint":"http://localhost:8009/main/v2/oauth/identity","end_session_endpoint":"http://localhost:8009/main/v2/oauth/logout","jwks_uri":"http://localhost:8009/jwks.json","token_endpoint_auth_signing_alg_values_supported":["RS256","HS256"],"scopes_supported":["openid","profile","email","address"],"response_types_supported":["token","code","code id_token","id_token","id_token token"],"response_modes_supported":["query","fragment"],"grant_types_supported":["authorization_code","implicit"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256","RS384","RS512"],"token_endpoint_auth_methods_supported":["client_secret_post","client_secret_basic","client_secret_jwt","private_key_jwt","none"],"claim_types_supported":["normal"],"claims_supported":["sub","iss","auth_time","acr","name","nickname","preferred_username","profile","gender","locale","picture","birthdate","email","email_verified","locale","zoneinfo","country","postal_code"],"claims_parameter_supported":false,"request_parameter_supported":false,"request_uri_parameter_supported":false,"service_documentation":"https://apidoc.asmodee.net","ui_locales_supported":["en-US","fr-FR","de-DE"]}'
        };
        var responseForJwksJson = {
            status: 200,
            contentType: 'application/json',
            responseText: '{"keys":[{"kty":"RSA", "alg": "RS256", "use": "sig", "kid": "dow","n":"sJlN4dMPOB580WK3h5mWqtoV-o7xgDGDh2bfc9ctF5gM0lzXvZbiMi_6LS0Mkl4yF1-vSXVPABMu1I9XdLkmrFOR6jyrSvEFxFWyoVkFZFrNvwCfLXky3MtyWV1KqHP_WK0afhqhf4Nb1vFvx3X6ZnPjacrZtH1Ogw6ZDZ1JYi66fc8JIrDpYxBs08ikibkHDP8_xtXXrv072fH5VJN0z-U2zyFz-U7HBB7AjL92kFhruCohNxMbhARSZNIfO4MYALyqOHNTZAytK8ieuk_TF7znpBLrzJjaFLezxG2wlX3VTVyUyhr0RUC7arssrGYzk8fqQTDT7L1hRJCUzs_Dkw","e":"AQAB"}]}'
        };
        var openidConfiguration = {issuer: 'http://localhost:8009', authorization_endpoint: 'http://localhost:8009/main/v2/oauth/authorize', token_endpoint: 'http://localhost:8009/main/v2/oauth/token', userinfo_endpoint: 'http://localhost:8009/main/v2/oauth/identity', end_session_endpoint: 'http://localhost:8009/main/v2/oauth/logout', jwks_uri: 'http://localhost:8009/jwks.json', token_endpoint_auth_signing_alg_values_supported: ['RS256', 'HS256'], scopes_supported: ['openid', 'profile', 'email', 'address'], response_types_supported: ['token', 'code', 'code id_token', 'id_token', 'id_token token'], response_modes_supported: ['query', 'fragment'], grant_types_supported: ['authorization_code', 'implicit'], subject_types_supported: ['public'], id_token_signing_alg_values_supported: ['RS256', 'RS384', 'RS512'], token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic', 'client_secret_jwt', 'private_key_jwt', 'none'], claim_types_supported: ['normal'], claims_supported: ['sub', 'iss', 'auth_time', 'acr', 'name', 'nickname', 'preferred_username', 'profile', 'gender', 'locale', 'picture', 'birthdate', 'email', 'email_verified', 'locale', 'zoneinfo', 'country', 'postal_code'], claims_parameter_supported: false, request_parameter_supported: false, request_uri_parameter_supported: false, service_documentation: 'https://apidoc.asmodee.net', 'ui_locales_supported': ['en-US', 'fr-FR', 'de-DE']};

        beforeEach(function () {
            jasmine.Ajax.install();

            // onComplete = jasmine.createSpy('onComplete');
            // onSuccess = jasmine.createSpy('onSuccess');
            // onFailure = jasmine.createSpy('onFailure');
        });

        afterEach(function () {
            jasmine.Ajax.uninstall();
        });

        it('should call discover and valid its return', function () {
            var onGetJwks = spyOn(window.AsmodeeNet, 'getJwks').and.callThrough();

            window.AsmodeeNet.init({
                client_id: 'bob_id',
                display: 'page'
            });
            window.AsmodeeNet.discover();

            request = jasmine.Ajax.requests.mostRecent();
            expect(request.url).toBe('https://account.asmodee.net/.well-known/openid-configuration');
            expect(request.method).toBe('GET');

            request.respondWith(responseForWellKnown);

            expect(onGetJwks).toHaveBeenCalled();
            expect(window.AsmodeeNet.getDiscovery()).toEqual(openidConfiguration);
            expect(window.AsmodeeNet.getSettings().base_is_host).toEqual('http://localhost:8009/');
            expect(window.AsmodeeNet.getSettings().logout_endpoint).toEqual('http://localhost:8009/main/v2/oauth/logout');

            request = jasmine.Ajax.requests.mostRecent();
            expect(request.url).toBe('http://localhost:8009/jwks.json');
            expect(request.method).toBe('GET');

            request.respondWith(responseForJwksJson);
            expect(window.AsmodeeNet.isJwksDone()).toBeTrue();

            window.AsmodeeNet.init({
                client_id: 'bob_id',
                display: 'page'
            }).discover();

            request = jasmine.Ajax.requests.mostRecent();
            expect(request.url).toBe('https://account.asmodee.net/.well-known/openid-configuration');
            expect(request.method).toBe('GET');

            request.respondWith(responseForWellKnown);

            expect(onGetJwks).toHaveBeenCalledTimes(2);
            expect(window.AsmodeeNet.getDiscovery()).toEqual(openidConfiguration);
            expect(window.AsmodeeNet.getSettings().base_is_host).toEqual('http://localhost:8009/');
            expect(window.AsmodeeNet.getSettings().logout_endpoint).toEqual('http://localhost:8009/main/v2/oauth/logout');
        });
    });

    describe('should can signIn after discover', function () {
        var onSuccess, onFailure;

        var responseForWellKnown = {
            status: 200,
            contentType: 'application/json',
            responseText: '{"issuer":"http://localhost:8009","authorization_endpoint":"http://localhost:8009/main/v2/oauth/authorize","token_endpoint":"http://localhost:8009/main/v2/oauth/token","userinfo_endpoint":"http://localhost:8009/main/v2/oauth/identity","end_session_endpoint":"http://localhost:8009/main/v2/oauth/logout","jwks_uri":"http://localhost:8009/jwks.json","token_endpoint_auth_signing_alg_values_supported":["RS256","HS256"],"scopes_supported":["openid","profile","email","address"],"response_types_supported":["token","code","code id_token","id_token","id_token token"],"response_modes_supported":["query","fragment"],"grant_types_supported":["authorization_code","implicit"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256","RS384","RS512"],"token_endpoint_auth_methods_supported":["client_secret_post","client_secret_basic","client_secret_jwt","private_key_jwt","none"],"claim_types_supported":["normal"],"claims_supported":["sub","iss","auth_time","acr","name","nickname","preferred_username","profile","gender","locale","picture","birthdate","email","email_verified","locale","zoneinfo","country","postal_code"],"claims_parameter_supported":false,"request_parameter_supported":false,"request_uri_parameter_supported":false,"service_documentation":"https://apidoc.asmodee.net","ui_locales_supported":["en-US","fr-FR","de-DE"]}'
        };
        var responseForJwksJson = {
            status: 200,
            contentType: 'application/json',
            responseText: '{"keys":[{"kty":"RSA", "alg": "RS256", "use": "sig", "kid": "dow","n":"sJlN4dMPOB580WK3h5mWqtoV-o7xgDGDh2bfc9ctF5gM0lzXvZbiMi_6LS0Mkl4yF1-vSXVPABMu1I9XdLkmrFOR6jyrSvEFxFWyoVkFZFrNvwCfLXky3MtyWV1KqHP_WK0afhqhf4Nb1vFvx3X6ZnPjacrZtH1Ogw6ZDZ1JYi66fc8JIrDpYxBs08ikibkHDP8_xtXXrv072fH5VJN0z-U2zyFz-U7HBB7AjL92kFhruCohNxMbhARSZNIfO4MYALyqOHNTZAytK8ieuk_TF7znpBLrzJjaFLezxG2wlX3VTVyUyhr0RUC7arssrGYzk8fqQTDT7L1hRJCUzs_Dkw","e":"AQAB"}]}'
        };

        beforeEach(function () {
            jasmine.Ajax.install();

            jasmine.Ajax.stubRequest(
                'http://localhost:8009/.well-known/openid-configuration',
                /.*openid-configuration.*/
            ).andReturn(responseForWellKnown);

            jasmine.Ajax.stubRequest(
                'http://localhost:8009/jwks.json',
                /.*jwks.*/
            ).andReturn(responseForJwksJson);

            onSuccess = jasmine.createSpy('onSuccess');
            onFailure = jasmine.createSpy('onFailure');
        });

        afterEach(function () {
            jasmine.Ajax.uninstall();
        });

        it('should call signin with state failure', function () {
            var onReload = spyOn(window.location, 'assign');
            window.location.hash = '#code=31870263e587560cc6802807862709f6effa27db&state=%STATE%&id_token=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwOlwvXC9sb2NhbGhvc3Q6ODAwOVwvIiwic3ViIjo1LCJhdWQiOiJ0ZXN0X2RpcmVjdCIsImlhdCI6MTUwNjI4MDk4MiwiZXhwIjoxNTA4ODcyOTgyLCJhdXRoX3RpbWUiOjE1MDYyODA5ODIsIm5vbmNlIjoiMmwxdTU4NXE3MDM0azIzaSIsImF0X2hhc2giOiJNRFF3WWpNNU9UZ3paakZtWTJaaVlqZGhZekk0WVdKak1qUXhOVFUxWmpjIiwiY19oYXNoIjoiWlRjM1ptVmlOemc1TnpCaE56VTNObVF3TUdNMVlUZzVNelkyWlRNMk9UUSJ9.g1PJHgxeNl6vzrJQl-AvMlxt6CMjLTMDNYr3AzTo1SqlUMGUFwUf4GE4WKeOL_ePt0FwhRyksk_Il_VYcZTYW7AUODfwDEAzfJA7fPGSy7KHn6FESFGYKKHoOiMaPnYvGOZ0dA-EVXW6Vevcpv7P4-czdocniqvni2ZrzJZvlAL-7Bhe5bVR8rWiVkpbn5tn_ZV4KDFQlwOl6gi_iz1XvTgLSOhQmEji9cZ76RQJawARqQPGyOM-u0xlDugiI_F2HOGtBvjwyHJ1YcJ6PHLsxJVuBmnVFG7qfsCNC-7ouw3B7BuEOXm2aI0R1VQLKfyWc9haAT9w0dIBUQKLZUEbZw&access_token=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpZCI6IjNkY2M4OGIzNzkxNjBjNzljMGQ4MjFlNWRhOTdlMzYwYmQ2Mjc3ZjMiLCJqdGkiOiIzZGNjODhiMzc5MTYwYzc5YzBkODIxZTVkYTk3ZTM2MGJkNjI3N2YzIiwiaXNzIjoiaHR0cDpcL1wvbG9jYWxob3N0OjgwMDlcLyIsImF1ZCI6InRlc3RfZGlyZWN0Iiwic3ViIjo1LCJleHAiOjE1MDg4NzI5ODIsImlhdCI6MTUwNjI4MDk4MiwidG9rZW5fdHlwZSI6ImJlYXJlciIsInNjb3BlIjoib3BlbmlkIGVtYWlsIHByb2ZpbGUifQ.Sm0YA6Kxy8nru5-fxQRhnaAGRXaWLA65CyBH0166cONqpNGuvszOCKia5-ihMXIkBU477ZLtvLvEvpisXXXmaSerEyo2aV_tSMcpCXO6ANwTuj9qjanCrtTSAGr-I4kNI-REV6Tmc-IS4uR8htex8BMdg6tELNqKFNIz3B2m7mG6ICh_PuM04u3hzaPJdkuhs7z2PhvRpIzSyHHWo2NDNf5Pj9e0rURUUE6wWERAH32Hxr0GFtRAlpMP1tHn0tkNnSLPJN4T2g8LxqKQ3jnSz0acSnYzy1ham2fZhQ7SJkwJOc0RiMrt_oH6-gHvxL9Gh4busOiKvcNzLDpTRa4UiA&expires_in=2592000&token_type=bearer&scope=openid+email+profile';

            window.AsmodeeNet.init({
                client_id: 'test_direct',
                display: 'page',
                scope: 'openid+email+profile',
                callback_signin_success: onSuccess,
                callback_signin_error: onFailure
            }).discover();

            expect(window.AsmodeeNet.isJwksDone()).toBeTrue();
            expect(onSuccess).not.toHaveBeenCalled();
            expect(onFailure).not.toHaveBeenCalled();
            expect(onStoreGet).not.toHaveBeenCalled();
            expect(onStoreSet).not.toHaveBeenCalled();
            expect(onStoreRemove).not.toHaveBeenCalled();
            expect(onStoreClear).not.toHaveBeenCalled();

            window.AsmodeeNet.signIn();
            expect(onReload).toHaveBeenCalledWith(any.startingWith('http://localhost:8009/main/v2/oauth/authorize?display=page&response_type=id_token%20token&state='));
            // var sta = tstore.state.val;
            // delete tstore.nonce;
            // window.location.hash = window.location.hash.replace('%STATE%', sta);

            window.AsmodeeNet.trackCb(false);

            expect(onFailure).not.toHaveBeenCalled();
            expect(onStoreSet).toHaveBeenCalled();

            window.AsmodeeNet.discover();

            var request = jasmine.Ajax.requests.mostRecent();
            request.respondWith(responseForWellKnown);
            request = jasmine.Ajax.requests.mostRecent();
            request.respondWith(responseForJwksJson);

            expect(onStoreGet).toHaveBeenCalled();
            expect(onStoreRemove).toHaveBeenCalled();
            expect(onStoreClear).not.toHaveBeenCalled();
            expect(onFailure).toHaveBeenCalledWith('Tokens validation issue : ', 'Invalid state');
        });

        it('should call signin page with success', function () {
            var onReload = spyOn(window.location, 'assign');
            window.location.hash = '#code=31870263e587560cc6802807862709f6effa27db&state=%STATE%&id_token=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwOlwvXC9sb2NhbGhvc3Q6ODAwOVwvIiwic3ViIjo1LCJhdWQiOiJ0ZXN0X2RpcmVjdCIsImlhdCI6MTUwNjI4MDk4MiwiZXhwIjoxNTA4ODcyOTgyLCJhdXRoX3RpbWUiOjE1MDYyODA5ODIsIm5vbmNlIjoiMmwxdTU4NXE3MDM0azIzaSIsImF0X2hhc2giOiJNRFF3WWpNNU9UZ3paakZtWTJaaVlqZGhZekk0WVdKak1qUXhOVFUxWmpjIiwiY19oYXNoIjoiWlRjM1ptVmlOemc1TnpCaE56VTNObVF3TUdNMVlUZzVNelkyWlRNMk9UUSJ9.g1PJHgxeNl6vzrJQl-AvMlxt6CMjLTMDNYr3AzTo1SqlUMGUFwUf4GE4WKeOL_ePt0FwhRyksk_Il_VYcZTYW7AUODfwDEAzfJA7fPGSy7KHn6FESFGYKKHoOiMaPnYvGOZ0dA-EVXW6Vevcpv7P4-czdocniqvni2ZrzJZvlAL-7Bhe5bVR8rWiVkpbn5tn_ZV4KDFQlwOl6gi_iz1XvTgLSOhQmEji9cZ76RQJawARqQPGyOM-u0xlDugiI_F2HOGtBvjwyHJ1YcJ6PHLsxJVuBmnVFG7qfsCNC-7ouw3B7BuEOXm2aI0R1VQLKfyWc9haAT9w0dIBUQKLZUEbZw&access_token=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpZCI6IjNkY2M4OGIzNzkxNjBjNzljMGQ4MjFlNWRhOTdlMzYwYmQ2Mjc3ZjMiLCJqdGkiOiIzZGNjODhiMzc5MTYwYzc5YzBkODIxZTVkYTk3ZTM2MGJkNjI3N2YzIiwiaXNzIjoiaHR0cDpcL1wvbG9jYWxob3N0OjgwMDlcLyIsImF1ZCI6InRlc3RfZGlyZWN0Iiwic3ViIjo1LCJleHAiOjE1MDg4NzI5ODIsImlhdCI6MTUwNjI4MDk4MiwidG9rZW5fdHlwZSI6ImJlYXJlciIsInNjb3BlIjoib3BlbmlkIGVtYWlsIHByb2ZpbGUifQ.Sm0YA6Kxy8nru5-fxQRhnaAGRXaWLA65CyBH0166cONqpNGuvszOCKia5-ihMXIkBU477ZLtvLvEvpisXXXmaSerEyo2aV_tSMcpCXO6ANwTuj9qjanCrtTSAGr-I4kNI-REV6Tmc-IS4uR8htex8BMdg6tELNqKFNIz3B2m7mG6ICh_PuM04u3hzaPJdkuhs7z2PhvRpIzSyHHWo2NDNf5Pj9e0rURUUE6wWERAH32Hxr0GFtRAlpMP1tHn0tkNnSLPJN4T2g8LxqKQ3jnSz0acSnYzy1ham2fZhQ7SJkwJOc0RiMrt_oH6-gHvxL9Gh4busOiKvcNzLDpTRa4UiA&expires_in=2592000&token_type=bearer&scope=openid+email+profile';

            onFailure.calls.reset();
            onSuccess.calls.reset();
            onStoreGet.calls.reset();
            onStoreSet.calls.reset();
            onStoreRemove.calls.reset();
            onStoreClear.calls.reset();

            window.AsmodeeNet.init({
                client_id: 'test_direct',
                display: 'page',
                scope: 'openid+email+profile',
                callback_signin_success: onSuccess,
                callback_signin_error: onFailure
            }).discover();

            expect(window.AsmodeeNet.isJwksDone()).toBeTrue();
            expect(onSuccess).not.toHaveBeenCalled();
            expect(onFailure).not.toHaveBeenCalled();
            expect(onStoreGet).not.toHaveBeenCalled();
            expect(onStoreSet).not.toHaveBeenCalled();
            expect(onStoreRemove).not.toHaveBeenCalled();
            expect(onStoreClear).not.toHaveBeenCalled();

            window.AsmodeeNet.signIn();
            expect(onReload).toHaveBeenCalledWith(any.startingWith('http://localhost:8009/main/v2/oauth/authorize?display=page&response_type=id_token%20token&state='));
            var sta = tstore.state.val;
            delete tstore.nonce;
            window.location.hash = window.location.hash.replace('%STATE%', sta);

            window.AsmodeeNet.trackCb(false);

            expect(onFailure).not.toHaveBeenCalled();
            expect(onStoreSet).toHaveBeenCalled();

            var getLimitExp = spyOn(window.AsmodeeNet, 'limit_exp_time').and.callFake(function () {
                return '1506872982';
            });
            var onSha = spyOn(window.KJUR.crypto.Util, 'sha256').and.returnValue('BOBsldfkzjblkqsbfvlkqsbflvhqsbflvhbqsfvbh');
            var bash;
            var onBash = spyOn(window.AsmodeeNet, 'verifyBHash').and.callFake(function (bHash) {
                bash = bHash;
                return bHash;
            });
            var onBoa = spyOn(window, 'btoa').and.callFake(function (t) {
                return bash;
            });
            var onVerify = spyOn(window.KJUR.jws.JWS, 'verify').and.returnValue(true);

            window.AsmodeeNet.discover();

            var request = jasmine.Ajax.requests.mostRecent();
            request.respondWith(responseForWellKnown);
            request = jasmine.Ajax.requests.mostRecent();
            request.respondWith(responseForJwksJson);

            expect(getLimitExp).toHaveBeenCalled();
            expect(onStoreGet).toHaveBeenCalled();
            expect(onStoreRemove).toHaveBeenCalled();
            expect(onSha).toHaveBeenCalled();
            expect(onBash).toHaveBeenCalled();
            expect(onBoa).toHaveBeenCalled();
            expect(onVerify).toHaveBeenCalled();

            expect(onFailure).not.toHaveBeenCalled();

            request = jasmine.Ajax.requests.mostRecent();
            expect(request.url).toBe('http://localhost:8009/main/v2/oauth/identity');
            expect(request.requestHeaders).toEqual({Authorization: 'Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpZCI6IjNkY2M4OGIzNzkxNjBjNzljMGQ4MjFlNWRhOTdlMzYwYmQ2Mjc3ZjMiLCJqdGkiOiIzZGNjODhiMzc5MTYwYzc5YzBkODIxZTVkYTk3ZTM2MGJkNjI3N2YzIiwiaXNzIjoiaHR0cDpcL1wvbG9jYWxob3N0OjgwMDlcLyIsImF1ZCI6InRlc3RfZGlyZWN0Iiwic3ViIjo1LCJleHAiOjE1MDg4NzI5ODIsImlhdCI6MTUwNjI4MDk4MiwidG9rZW5fdHlwZSI6ImJlYXJlciIsInNjb3BlIjoib3BlbmlkIGVtYWlsIHByb2ZpbGUifQ.Sm0YA6Kxy8nru5-fxQRhnaAGRXaWLA65CyBH0166cONqpNGuvszOCKia5-ihMXIkBU477ZLtvLvEvpisXXXmaSerEyo2aV_tSMcpCXO6ANwTuj9qjanCrtTSAGr-I4kNI-REV6Tmc-IS4uR8htex8BMdg6tELNqKFNIz3B2m7mG6ICh_PuM04u3hzaPJdkuhs7z2PhvRpIzSyHHWo2NDNf5Pj9e0rURUUE6wWERAH32Hxr0GFtRAlpMP1tHn0tkNnSLPJN4T2g8LxqKQ3jnSz0acSnYzy1ham2fZhQ7SJkwJOc0RiMrt_oH6-gHvxL9Gh4busOiKvcNzLDpTRa4UiA', Accept: 'application/json'});

            request.respondWith({status: 200, contentType: 'application/json', responseText: '{"sub": 5, "nickname": "Bob"}'});

            expect(onFailure).not.toHaveBeenCalled();
            expect(onSuccess).toHaveBeenCalled();
            expect(window.AsmodeeNet.getIdentity()).toEqual({sub: 5, nickname: 'Bob'});
        });

        it('should call logout without callback', function () {
            var onReload = spyOn(window.location, 'reload');

            onFailure.calls.reset();
            onSuccess.calls.reset();
            onStoreGet.calls.reset();
            onStoreSet.calls.reset();
            onStoreRemove.calls.reset();
            onStoreClear.calls.reset();

            window.AsmodeeNet.init({
                client_id: 'test_direct',
                display: 'page',
                scope: 'openid+email+profile',
                callback_signin_success: onSuccess,
                callback_signin_error: onFailure
            }).discover();

            window.AsmodeeNet.signOut();

            expect(onStoreClear).toHaveBeenCalled();
            expect(onReload).toHaveBeenCalled();
        });

        it('should call signin touch', function () {
            var onReload = spyOn(window.location, 'assign');
            onFailure.calls.reset();
            onSuccess.calls.reset();
            onStoreGet.calls.reset();
            onStoreSet.calls.reset();
            onStoreRemove.calls.reset();
            onStoreClear.calls.reset();

            window.AsmodeeNet.init({
                client_id: 'test_direct',
                display: 'touch',
                scope: 'openid+email+profile',
                callback_signin_success: onSuccess,
                callback_signin_error: onFailure
            }).discover();

            expect(window.AsmodeeNet.isJwksDone()).toBeTrue();
            expect(onSuccess).not.toHaveBeenCalled();
            expect(onFailure).not.toHaveBeenCalled();
            expect(onStoreGet).not.toHaveBeenCalled();
            expect(onStoreSet).not.toHaveBeenCalled();
            expect(onStoreRemove).not.toHaveBeenCalled();

            window.AsmodeeNet.signIn();
            expect(onReload).toHaveBeenCalledWith(any.startingWith('http://localhost:8009/main/v2/oauth/authorize?display=touch&response_type=id_token%20token&state='));
        });

        // Disabled it for the moment.
        //
        // it('should call signin popup', function () {
        //     var onPopup = spyOn(window, 'open');
        //     onFailure.calls.reset();
        //     onSuccess.calls.reset();
        //     onStoreGet.calls.reset();
        //     onStoreSet.calls.reset();
        //     onStoreRemove.calls.reset();
        //     onStoreClear.calls.reset();
        //
        //     window.AsmodeeNet.init({
        //         client_id: 'test_direct',
        //         display: 'popup',
        //         scope: 'openid+email+profile',
        //         callback_signin_success: onSuccess,
        //         callback_signin_error: onFailure
        //     }).discover();
        //
        //     expect(window.AsmodeeNet.isJwksDone()).toBeTrue();
        //     expect(onSuccess).not.toHaveBeenCalled();
        //     expect(onFailure).not.toHaveBeenCalled();
        //     expect(onStoreGet).not.toHaveBeenCalled();
        //     expect(onStoreSet).not.toHaveBeenCalled();
        //     expect(onStoreRemove).not.toHaveBeenCalled();
        //
        //     window.AsmodeeNet.signIn();
        //     expect(onPopup).toHaveBeenCalledWith(any.startingWith('http://localhost:8009/main/v2/oauth/authorize?display=popup&response_type=id_token%20token&state='), 'AsmodeeNetConnectWithOAuth', 'location=0,status=0,width=475,height=500');
        // });

        it('should call signin iframe', function () {
            var iframeEventLoad = null;
            var iframe = {
                focus: function () { return true; },
                removeEventListener: function () {},
                addEventListener: function (type, cb, dat) {
                    expect(type).toEqual('load');
                    expect(cb).toBeFunction();
                    iframeEventLoad = cb;
                    expect(dat).toBeFalse();
                }
            };
            var onIframe = spyOn(window.document, 'getElementById').and.returnValue(iframe);
            var onIframeFocus = spyOn(iframe, 'focus').and.callThrough();
            var onIframeAddEventListener = spyOn(iframe, 'addEventListener').and.callThrough();
            onFailure.calls.reset();
            onSuccess.calls.reset();
            onStoreGet.calls.reset();
            onStoreSet.calls.reset();
            onStoreRemove.calls.reset();
            onStoreClear.calls.reset();

            window.AsmodeeNet.init({
                client_id: 'test_direct',
                display: 'iframe',
                iframe_css: '#iframeId',
                scope: 'openid+email+profile',
                callback_signin_success: onSuccess,
                callback_signin_error: onFailure
            }).discover();

            var request = jasmine.Ajax.requests.mostRecent();
            request.respondWith(responseForWellKnown);
            request = jasmine.Ajax.requests.mostRecent();
            request.respondWith(responseForJwksJson);

            expect(window.AsmodeeNet.isJwksDone()).toBeTrue();
            expect(onSuccess).not.toHaveBeenCalled();
            expect(onFailure).not.toHaveBeenCalled();
            expect(onStoreGet).toHaveBeenCalled();
            expect(onStoreSet).not.toHaveBeenCalled();
            expect(onStoreRemove).not.toHaveBeenCalled();

            window.AsmodeeNet.signIn();
            expect(onIframe).toHaveBeenCalledWith('iframeId');
            expect(onIframeFocus).toHaveBeenCalled();
            expect(onIframeAddEventListener).toHaveBeenCalledWith('load', jasmine.any(Function), false);
            expect(iframe.name).toEqual('AsmodeeNetConnectWithOAuth');
            expect(iframe.width).toEqual(475);
            expect(iframe.height).toEqual(500);
            expect(iframe.src).toEqual(any.startingWith('http://localhost:8009/main/v2/oauth/authorize?display=iframe&response_type=id_token%20token&state='));

            expect(onStoreSet).toHaveBeenCalledWith('state', jasmine.any(String), jasmine.anything(String));
            var sta = tstore.state.val;
            delete tstore.nonce;

            tstore.gd_connect_hash = {val: '#code=31870263e587560cc6802807862709f6effa27db&state=' + sta + '&id_token=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwOlwvXC9sb2NhbGhvc3Q6ODAwOVwvIiwic3ViIjo1LCJhdWQiOiJ0ZXN0X2RpcmVjdCIsImlhdCI6MTUwNjI4MDk4MiwiZXhwIjoxNTA4ODcyOTgyLCJhdXRoX3RpbWUiOjE1MDYyODA5ODIsIm5vbmNlIjoiMmwxdTU4NXE3MDM0azIzaSIsImF0X2hhc2giOiJNRFF3WWpNNU9UZ3paakZtWTJaaVlqZGhZekk0WVdKak1qUXhOVFUxWmpjIiwiY19oYXNoIjoiWlRjM1ptVmlOemc1TnpCaE56VTNObVF3TUdNMVlUZzVNelkyWlRNMk9UUSJ9.g1PJHgxeNl6vzrJQl-AvMlxt6CMjLTMDNYr3AzTo1SqlUMGUFwUf4GE4WKeOL_ePt0FwhRyksk_Il_VYcZTYW7AUODfwDEAzfJA7fPGSy7KHn6FESFGYKKHoOiMaPnYvGOZ0dA-EVXW6Vevcpv7P4-czdocniqvni2ZrzJZvlAL-7Bhe5bVR8rWiVkpbn5tn_ZV4KDFQlwOl6gi_iz1XvTgLSOhQmEji9cZ76RQJawARqQPGyOM-u0xlDugiI_F2HOGtBvjwyHJ1YcJ6PHLsxJVuBmnVFG7qfsCNC-7ouw3B7BuEOXm2aI0R1VQLKfyWc9haAT9w0dIBUQKLZUEbZw&access_token=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpZCI6IjNkY2M4OGIzNzkxNjBjNzljMGQ4MjFlNWRhOTdlMzYwYmQ2Mjc3ZjMiLCJqdGkiOiIzZGNjODhiMzc5MTYwYzc5YzBkODIxZTVkYTk3ZTM2MGJkNjI3N2YzIiwiaXNzIjoiaHR0cDpcL1wvbG9jYWxob3N0OjgwMDlcLyIsImF1ZCI6InRlc3RfZGlyZWN0Iiwic3ViIjo1LCJleHAiOjE1MDg4NzI5ODIsImlhdCI6MTUwNjI4MDk4MiwidG9rZW5fdHlwZSI6ImJlYXJlciIsInNjb3BlIjoib3BlbmlkIGVtYWlsIHByb2ZpbGUifQ.Sm0YA6Kxy8nru5-fxQRhnaAGRXaWLA65CyBH0166cONqpNGuvszOCKia5-ihMXIkBU477ZLtvLvEvpisXXXmaSerEyo2aV_tSMcpCXO6ANwTuj9qjanCrtTSAGr-I4kNI-REV6Tmc-IS4uR8htex8BMdg6tELNqKFNIz3B2m7mG6ICh_PuM04u3hzaPJdkuhs7z2PhvRpIzSyHHWo2NDNf5Pj9e0rURUUE6wWERAH32Hxr0GFtRAlpMP1tHn0tkNnSLPJN4T2g8LxqKQ3jnSz0acSnYzy1ham2fZhQ7SJkwJOc0RiMrt_oH6-gHvxL9Gh4busOiKvcNzLDpTRa4UiA&expires_in=2592000&token_type=bearer&scope=openid+email+profile', limit: (new Date()).getTime() + 10000};

            expect(onFailure).not.toHaveBeenCalled();

            var getLimitExp = spyOn(window.AsmodeeNet, 'limit_exp_time').and.callFake(function () {
                return '1506872982';
            });

            var onSha = spyOn(window.KJUR.crypto.Util, 'sha256').and.returnValue('BOBsldfkzjblkqsbfvlkqsbflvhqsbflvhbqsfvbh');
            var bash;
            var onBash = spyOn(window.AsmodeeNet, 'verifyBHash').and.callFake(function (bHash) {
                bash = bHash;
                return bHash;
            });
            var onBoa = spyOn(window, 'btoa').and.callFake(function (t) {
                return bash;
            });
            var onVerify = spyOn(window.KJUR.jws.JWS, 'verify').and.returnValue(true);

            iframeEventLoad({currentTarget: iframe, contentWindow: {}});

            expect(getLimitExp).toHaveBeenCalled();
            expect(onStoreGet).toHaveBeenCalledWith('gd_connect_hash');
            expect(onSha).toHaveBeenCalled();
            expect(onBash).toHaveBeenCalled();
            expect(onBoa).toHaveBeenCalled();
            expect(onVerify).toHaveBeenCalled();

            expect(onFailure).not.toHaveBeenCalled();

            request = jasmine.Ajax.requests.mostRecent();
            expect(request.url).toBe('http://localhost:8009/main/v2/oauth/identity');
            expect(request.requestHeaders).toEqual({Authorization: 'Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpZCI6IjNkY2M4OGIzNzkxNjBjNzljMGQ4MjFlNWRhOTdlMzYwYmQ2Mjc3ZjMiLCJqdGkiOiIzZGNjODhiMzc5MTYwYzc5YzBkODIxZTVkYTk3ZTM2MGJkNjI3N2YzIiwiaXNzIjoiaHR0cDpcL1wvbG9jYWxob3N0OjgwMDlcLyIsImF1ZCI6InRlc3RfZGlyZWN0Iiwic3ViIjo1LCJleHAiOjE1MDg4NzI5ODIsImlhdCI6MTUwNjI4MDk4MiwidG9rZW5fdHlwZSI6ImJlYXJlciIsInNjb3BlIjoib3BlbmlkIGVtYWlsIHByb2ZpbGUifQ.Sm0YA6Kxy8nru5-fxQRhnaAGRXaWLA65CyBH0166cONqpNGuvszOCKia5-ihMXIkBU477ZLtvLvEvpisXXXmaSerEyo2aV_tSMcpCXO6ANwTuj9qjanCrtTSAGr-I4kNI-REV6Tmc-IS4uR8htex8BMdg6tELNqKFNIz3B2m7mG6ICh_PuM04u3hzaPJdkuhs7z2PhvRpIzSyHHWo2NDNf5Pj9e0rURUUE6wWERAH32Hxr0GFtRAlpMP1tHn0tkNnSLPJN4T2g8LxqKQ3jnSz0acSnYzy1ham2fZhQ7SJkwJOc0RiMrt_oH6-gHvxL9Gh4busOiKvcNzLDpTRa4UiA', Accept: 'application/json'});

            request.respondWith({status: 200, contentType: 'application/json', responseText: '{"sub": 5, "nickname": "Bob"}'});

            expect(onFailure).not.toHaveBeenCalled();
            expect(onSuccess).toHaveBeenCalledWith({sub: 5, nickname: 'Bob'}, window.AsmodeeNet.getCode());
            expect(iframe.src).toEqual('');
            expect(window.AsmodeeNet.getIdentity()).toEqual({sub: 5, nickname: 'Bob'});
        });

        it('should call logout by iframe and with callback', function () {
            onFailure.calls.reset();
            onSuccess.calls.reset();
            onStoreGet.calls.reset();
            onStoreSet.calls.reset();
            onStoreRemove.calls.reset();
            onStoreClear.calls.reset();

            window.AsmodeeNet.init({
                client_id: 'test_direct',
                display: 'iframe',
                iframe_css: '#iframeId',
                scope: 'openid+email+profile',
                callback_signin_success: onSuccess,
                callback_signin_error: onFailure
            }).discover();

            var onSignOutCb = jasmine.createSpy('onSignOutCb');

            window.AsmodeeNet.signOut({success: onSignOutCb});

            expect(onStoreClear).toHaveBeenCalled();
            expect(onSignOutCb).toHaveBeenCalled();
        });
    });
});
