(function() {
  window.AsmodeeNet = (function() {
    var access_hash, access_token, authorized, catHashCheck, checkErrors, checkLogoutRedirect, checkTokens, code, defaultErrorCallback, defaultSuccessCallback, disconnect, discovery_obj, getCryptoValue, id_token, identity_obj, jwks, nonce, oauth, oauthpopup, settings, signinCallback, state;
    settings = {
      base_is_host: 'https://account.asmodee.net',
      base_is_path: '/main/v2/oauth',
      logout_endpoint: '/main/v2/logout',
      base_url: 'https://api.asmodee.net/main/v1',
      client_id: null,
      redirect_uri: null,
      logout_redirect_uri: null,
      callback_post_logout_redirect: null,
      scope: 'openid+profile',
      response_type: 'id_token token',
      display: 'popup',
      callback_signin_success: defaultSuccessCallback,
      callback_signin_error: defaultErrorCallback
    };
    state = nonce = null;
    access_token = id_token = access_hash = identity_obj = discovery_obj = jwks = code = null;
    checkErrors = [];
    getCryptoValue = function() {
      var crypto, res, rnd;
      crypto = window.crypto || window.msCrypto;
      rnd = 0;
      res = [];
      if (crypto) {
        rnd = crypto.getRandomValues(new Uint8Array(30));
      } else {
        rnd = [Math.random()];
      }
      rnd.forEach(function(r) {
        return res.push(r.toString(36));
      });
      return (res.join('') + '00000000000000000').slice(2, 16 + 2);
    };
    disconnect = function(callback) {
      if (callback == null) {
        callback = false;
      }
      window.localStorage.clear();
      access_token = id_token = access_hash = identity_obj = code = null;
      if (callback) {
        return callback();
      } else {
        return window.location.reload();
      }
    };
    oauth = function(options) {
      if (settings.display === 'popup') {
        return oauthpopup(options);
      } else {
        return window.location.assign(options.path);
      }
    };
    oauthpopup = function(options) {
      var that;
      if (options.width == null) {
        options.width = 475;
      }
      if (options.height == null) {
        options.height = 500;
      }
      if (options.windowName == null) {
        options.windowName = 'AsmodeeNetConnectWithOAuth';
      }
      if (options.windowOptions == null) {
        options.windowOptions = 'location=0,status=0,width=' + options.width + ',height=' + options.height;
      }
      if (options.callback == null) {
        options.callback = function() {
          return window.location.reload();
        };
      }
      that = this;
      that._oauthWindow = window.open(options.path, options.windowName, options.windowOptions);
      if (options.autoclose) {
        that._oauthAutoCloseInterval = window.setInterval(function() {
          that._oauthWindow.close();
          delete that._oauthWindow;
          if (that._oauthAutoCloseInterval) {
            window.clearInterval(that._oauthAutoCloseInterval);
          }
          if (that._oauthInterval) {
            window.clearInterval(that._oauthInterval);
          }
          return options.callback();
        }, 500);
      }
      return that._oauthInterval = window.setInterval(function() {
        if (that._oauthWindow.closed) {
          if (that._oauthInterval) {
            window.clearInterval(that._oauthInterval);
          }
          if (that._oauthAutoCloseInterval) {
            window.clearInterval(that._oauthAutoCloseInterval);
          }
          return options.callback();
        }
      }, 1000);
    };
    authorized = function(access_hash_clt) {
      access_hash = access_hash_clt;
      access_token = access_hash.access_token;
      id_token = access_hash.id_token;
      if (access_hash.code) {
        return code = access_hash.code;
      }
    };
    catHashCheck = function(b_hash, bcode) {
      var mdHex;
      mdHex = KJUR.crypto.Util.sha256(bcode);
      mdHex = mdHex.substr(0, mdHex.length / 2);
      while (!(b_hash.length % 4 === 0)) {
        b_hash += '=';
      }
      return b_hash === btoa(mdHex);
    };
    checkTokens = function(nonce, hash) {
      var alg, at_dec, at_head, i, it_dec, it_head, key, len;
      if (hash.access_token) {
        at_dec = jwt_decode(hash.access_token);
        at_head = jwt_decode(hash.access_token, {
          header: true
        });
      }
      if (settings.response_type.search('id_token') >= 0) {
        if (typeof hash.id_token === void 0) {
          return false;
        }
        it_dec = jwt_decode(hash.id_token);
        it_head = jwt_decode(hash.id_token, {
          header: true
        });
        if (it_head.typ !== 'JWT') {
          checkErrors.push('Invalid type');
          return false;
        }
        if (it_head.alg !== 'RS256') {
          checkErrors.push('Invalid alg');
          return false;
        }
        if (it_dec.nonce !== nonce) {
          checkErrors.push('Invalid nonce');
          return false;
        }
        if (it_dec.iss !== settings.base_is_host) {
          checkErrors.push('Invalid issuer');
          return false;
        }
        if (it_dec.aud !== settings.client_id && (!Array.isArray(it_dec.aud) || id_dec.aud.indexOf(settings.client_id) === -1)) {
          checkErrors.push('Invalid auditor');
          return false;
        }
        if (it_dec.exp < (Date.now() / 1000).toPrecision(10)) {
          checkErrors.push('Invalid expiration date');
          return false;
        }
        if (typeof it_dec.at_hash === 'string' && !catHashCheck(it_dec.at_hash, hash.access_token)) {
          checkErrors.push('Invalid at_hash');
          return false;
        }
        if (typeof it_dec.c_hash === 'string' && !catHashCheck(it_dec.c_hash, hash.code)) {
          checkErrors.push('Invalid c_hash');
          return false;
        }
        alg = [it_head.alg];
        for (i = 0, len = jwks.length; i < len; i++) {
          key = jwks[i];
          if (KJUR.jws.JWS.verify(hash.id_token, KEYUTIL.getKey(key), alg)) {
            return true;
          }
        }
        checkErrors.push('Invalid JWS key');
        return false;
      }
      return true;
    };
    checkLogoutRedirect = function() {
      var found_state, re;
      if (settings.logout_redirect_uri) {
        re = new RegExp(settings.logout_redirect_uri.replace(/([?.+*()])/g, "\\$1"));
        if (re.test(window.location.href)) {
          found_state = window.location.href.replace(settings.logout_redirect_uri + '&state=', '').replace(/[&#].*$/, '');
          if ((found_state === window.localStorage.getItem('logout_state')) || (!found_state && !window.localStorage.getItem('logout_state'))) {
            window.localStorage.removeItem('logout_state');
            if (settings.callback_post_logout_redirect) {
              return settings.callback_post_logout_redirect();
            } else {
              return window.location = '/';
            }
          }
        }
      }
    };
    defaultSuccessCallback = function() {
      return console.log(arguments);
    };
    defaultErrorCallback = function() {
      return console.error(arguments);
    };
    signinCallback = function(gameThis) {
      var hash, i, item, j, len, len1, splitted, t;
      item = window.localStorage.getItem('gd_connect_hash');
      if (!item) {
        if (settings.display === 'popup') {
          return settings.callback_signin_error("popup closed without signin");
        }
      } else {
        window.localStorage.removeItem('gd_connect_hash');
        hash = {};
        splitted = null;
        if (item.search(/^#/) === 0) {
          splitted = item.replace(/^#/, '').split('&');
          for (i = 0, len = splitted.length; i < len; i++) {
            t = splitted[i];
            t = t.split('=');
            hash[t[0]] = t[1];
          }
          if (hash.token_type && hash.token_type === 'bearer') {
            state = window.localStorage.getItem('state');
            nonce = window.localStorage.getItem('nonce');
            if (hash.state && hash.state === state) {
              hash.scope = hash.scope.split('+');
              checkErrors = [];
              if (checkTokens(nonce, hash)) {
                window.localStorage.removeItem('state');
                window.localStorage.removeItem('nonce');
                authorized(hash);
                return gameThis.identity({
                  success: settings.callback_signin_success,
                  error: settings.callback_signin_error
                });
              } else {
                return settings.callback_signin_error("Tokens validation issue");
              }
            }
          }
        } else if (item.search(/^\?/) === 0) {
          splitted = item.replace(/^\?/, '').split('&');
          for (j = 0, len1 = splitted.length; j < len1; j++) {
            t = splitted[j];
            t = t.split('=');
            hash[t[0]] = t[1];
          }
          if (hash.state && hash.state === state) {
            return settings.callback_signin_error(hash.error + ' : ' + hash.error_description.replace(/\+/g, ' '));
          }
        }
      }
    };
    return {
      init: function(options) {
        settings = this.extend(settings, options);
        checkLogoutRedirect();
        return this;
      },
      baseSettings: function() {
        return {
          crossDomain: true,
          dataType: 'json',
          headers: {
            'Authorization': 'Bearer ' + access_token,
            'Accept': 'application/json'
          }
        };
      },
      isConnected: function() {
        return this.getAccessToken() !== null;
      },
      getAccessToken: function() {
        return access_token;
      },
      getIdToken: function() {
        return id_token;
      },
      getAccessHash: function() {
        return access_hash;
      },
      getDiscovery: function() {
        return discovery_obj;
      },
      getCode: function() {
        return code;
      },
      getCheckErrors: function() {
        return checkErrors;
      },
      auth_endpoint: function() {
        if (discovery_obj) {
          return discovery_obj.authorization_endpoint;
        }
        return settings.base_is_host + settings.base_is_path + '/authorize';
      },
      ident_endpoint: function() {
        if (discovery_obj) {
          return discovery_obj.userinfo_endpoint;
        }
        return settings.base_is_host + settings.base_is_path + '/identity';
      },
      get: function(url, options) {
        var base_url, sets;
        if (options == null) {
          options = {};
        }
        base_url = options.base_url || settings.base_url;
        delete options.base_url;
        sets = this.extend(options, this.baseSettings(), {
          type: 'GET'
        });
        if (options.auth !== void 0 && options.auth === false) {
          if (sets.headers.Authorization) {
            delete sets.headers.Authorization;
          }
          delete sets.auth;
        }
        return this.ajax(base_url + url, sets);
      },
      discover: function(host_port) {
        var gameThis;
        host_port = host_port || settings.base_is_host;
        gameThis = this;
        return this.get('/.well-known/openid-configuration', {
          base_url: host_port,
          auth: false,
          success: function(data) {
            discovery_obj = data;
            settings.base_is_host = discovery_obj.issuer;
            settings.logout_endpoint = discovery_obj.end_session_endpoint;
            return gameThis.getJwks();
          },
          error: function() {
            return console.error("error Discovery ", arguments);
          }
        });
      },
      getJwks: function() {
        var gameThis;
        gameThis = this;
        return this.get('', {
          base_url: discovery_obj.jwks_uri,
          auth: false,
          success: function(data) {
            jwks = data.keys;
            if (settings.display !== 'popup') {
              return signinCallback(gameThis);
            }
          },
          error: function() {
            return console.error("error JWKS", arguments);
          }
        });
      },
      signIn: function(options) {
        var gameThis;
        state = getCryptoValue();
        nonce = getCryptoValue();
        window.localStorage.setItem('state', state);
        window.localStorage.setItem('nonce', nonce);
        settings.callback_signin_success = options.success || settings.callback_signin_success;
        settings.callback_signin_error = options.error || settings.callback_signin_error;
        options.path = this.auth_endpoint() + '?display=' + settings.display + '&response_type=' + encodeURI(settings.response_type) + '&state=' + state + '&client_id=' + settings.client_id + '&redirect_uri=' + encodeURI(settings.redirect_uri) + '&scope=' + settings.scope;
        if (settings.response_type.search('id_token') >= 0) {
          options.path += '&nonce=' + nonce;
        }
        gameThis = this;
        options.callback = function() {
          var hash, i, item, j, len, len1, splitted, t;
          item = window.localStorage.getItem('gd_connect_hash');
          if (!item) {
            if (settings.display === 'popup') {
              return settings.callback_signin_error("popup closed without signin");
            }
          } else {
            window.localStorage.removeItem('gd_connect_hash');
            hash = {};
            splitted = null;
            if (item.search(/^#/) === 0) {
              splitted = item.replace(/^#/, '').split('&');
              for (i = 0, len = splitted.length; i < len; i++) {
                t = splitted[i];
                t = t.split('=');
                hash[t[0]] = t[1];
              }
              if (hash.token_type && hash.token_type === 'bearer') {
                state = window.localStorage.getItem('state');
                nonce = window.localStorage.getItem('nonce');
                if (hash.state && hash.state === state) {
                  hash.scope = hash.scope.split('+');
                  checkErrors = [];
                  if (checkTokens(nonce, hash)) {
                    window.localStorage.removeItem('state');
                    window.localStorage.removeItem('nonce');
                    authorized(hash);
                    return gameThis.identity({
                      success: settings.callback_signin_success,
                      error: settings.callback_signin_error
                    });
                  } else {
                    return settings.callback_signin_error("Tokens validation issue");
                  }
                }
              }
            } else if (item.search(/^\?/) === 0) {
              splitted = item.replace(/^\?/, '').split('&');
              for (j = 0, len1 = splitted.length; j < len1; j++) {
                t = splitted[j];
                t = t.split('=');
                hash[t[0]] = t[1];
              }
              if (hash.state && hash.state === state) {
                return settings.callback_signin_error(hash.error + ' : ' + hash.error_description.replace(/\+/g, ' '));
              }
            }
          }
        };
        return oauth(options);
      },
      identity: function(options) {
        if (this.isConnected() && identity_obj) {
          if (options.success) {
            return options.success(identity_obj, AsmodeeNet.getCode());
          }
        } else {
          return this.get('', {
            base_url: this.ident_endpoint(),
            success: function(data) {
              identity_obj = data;
              if (options.success) {
                return options.success(identity_obj, AsmodeeNet.getCode());
              }
            },
            error: function(context, xhr, type, error) {
              console.error('identity error', context, xhr, type, error);
              if (options.error) {
                return options.error(context, xhr, type, error);
              }
            }
          });
        }
      },
      signOut: function(options) {
        if (this.isConnected()) {
          if (settings.logout_redirect_uri) {
            state = getCryptoValue();
            window.localStorage.setItem('logout_state', state);
            return window.location = settings.logout_endpoint + '?post_logout_redirect_uri=' + encodeURI(settings.logout_redirect_uri) + '&state=' + state + '&id_token_hint=' + id_token;
          } else {
            return disconnect(options.success);
          }
        }
      },
      trackCb: function(closeit) {
        if (closeit == null) {
          closeit = true;
        }
        if (window.location.hash !== "") {
          window.localStorage.setItem('gd_connect_hash', window.location.hash);
        } else if (window.location.search !== "") {
          window.localStorage.setItem('gd_connect_hash', window.location.search);
        }
        if (window.name === 'AsmodeeNetConnectWithOAuth') {
          if (closeit) {
            return window.close();
          }
        }
      }
    };
  })();

  if (typeof window.AN === 'undefined') {
    window.AN = window.AsmodeeNet;
  }

  if (typeof window.GamifyDigital === 'undefined') {
    window.GamifyDigital = window.AsmodeeNet;
  }

  if (typeof window.GD === 'undefined') {
    window.GD = window.AsmodeeNet;
  }

}).call(this);

(function() {
  window.AsmodeeNet.extend = function() {
    var i, key, len, obj, ret;
    ret = {};
    for (i = 0, len = arguments.length; i < len; i++) {
      obj = arguments[i];
      for (key in obj) {
        if (Object.prototype.hasOwnProperty.call(obj, key)) {
          ret[key] = obj[key];
        }
      }
    }
    return ret;
  };

  window.AsmodeeNet.jwt_decode = function(token, options) {
    var deco;
    deco = KJUR.jws.JWS.parse(token);
    if (options && options.header !== "undefined" && options.header === true) {
      return deco.headerObj;
    }
    return deco.payloadObj;
  };

  if (!window.jwt_decode) {
    window.jwt_decode = window.AsmodeeNet.jwt_decode;
  }

}).call(this);

(function() {
  window.AsmodeeNet.ajax = function(url, settings) {
    var args, complete, defaultSettings, emptyFunction, error, key, mimeTypes, ref, success, xhr;
    args = arguments;
    settings = args.length === 1 ? args[0] : args[1];
    emptyFunction = function() {
      return null;
    };
    defaultSettings = {
      url: args.length === 2 && (typeof url === 'string') ? url : '.',
      cache: true,
      data: {},
      headers: {},
      context: null,
      type: 'GET',
      success: emptyFunction,
      error: emptyFunction,
      complete: emptyFunction
    };
    settings = this.extend(defaultSettings, settings || {});
    mimeTypes = {
      'application/json': 'json',
      'text/html': 'html',
      'text/plain': 'text'
    };
    if (!settings.cache) {
      settings.url = settings.url + ((ref = settings.url.indexOf('?')) != null ? ref : {
        '&': '?'
      }) + 'noCache=' + Math.floor(Math.random() * 9e9);
    }
    success = function(data, xhr, settings) {
      var status;
      status = 'success';
      settings.success.call(settings.context, data, status, xhr);
      return complete(status, xhr, settings);
    };
    error = function(error, type, xhr, settings) {
      settings.error.call(settings.context, xhr, type, error);
      return complete(type, xhr, settings);
    };
    complete = function(status, xhr, settings) {
      return settings.complete.call(settings.context, xhr, status);
    };
    xhr = new XMLHttpRequest();
    xhr.addEventListener('readystatechange', function() {
      var dataType, e, error1, mime, result;
      if (xhr.readyState === 4) {
        result = null;
        dataType = null;
        if ((xhr.status >= 200 && xhr.status < 300) || xhr.status === 304) {
          mime = xhr.getResponseHeader('content-type');
          dataType = mimeTypes[mime] || 'text';
          result = xhr.responseText;
          try {
            if (dataType === 'json') {
              result = JSON.parse(result);
            }
            success(result, xhr, settings);
            return;
          } catch (error1) {
            e = error1;
          }
        }
        return error(null, 'error', xhr, settings);
      }
    }, false);
    xhr.open(settings.type, settings.url);
    if (settings.type === 'POST') {
      settings.headers = this.extend(settings.headers, {
        'X-Requested-With': 'XMLHttpRequest',
        'Content-type': 'application/x-www-form-urlencoded'
      });
    }
    for (key in settings.headers) {
      xhr.setRequestHeader(key, settings.headers[key]);
    }
    xhr.send(settings.data);
    return this;
  };

}).call(this);

/*! jws-3.3.4 (c) 2013-2016 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
/*
 * jws.js - JSON Web Signature(JWS) and JSON Web Token(JWT) Class
 *
 * version: 3.3.4 (2016 May 17)
 *
 * Copyright (c) 2010-2016 Kenji Urushima (kenji.urushima@gmail.com)
 *
 * This software is licensed under the terms of the MIT License.
 * http://kjur.github.com/jsrsasign/license/
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

/**
 * @fileOverview
 * @name jws-3.3.js
 * @author Kenji Urushima kenji.urushima@gmail.com
 * @version 3.3.4 (2016-May-17)
 * @since jsjws 1.0, jsrsasign 4.8.0
 * @license <a href="http://kjur.github.io/jsrsasign/license/">MIT License</a>
 */

if (typeof KJUR == "undefined" || !KJUR) KJUR = {};

/**
 * kjur's JSON Web Signature/Token(JWS/JWT) library name space
 * <p>
 * This namespace privides following JWS/JWS related classes.
 * <ul>
 * <li>{@link KJUR.jws.JWS} - JSON Web Signature/Token(JWS/JWT) class</li>
 * <li>{@link KJUR.jws.JWSJS} - JWS JSON Serialization(JWSJS) class</li>
 * <li>{@link KJUR.jws.IntDate} - UNIX origin time utility class</li>
 * </ul>
 * NOTE: Please ignore method summary and document of this namespace. This caused by a bug of jsdoc2.
 * </p>
 * @name KJUR.jws
 * @namespace
 */
if (typeof KJUR.jws == "undefined" || !KJUR.jws) KJUR.jws = {};

/**
 * JSON Web Signature(JWS) class.<br/>
 * @name KJUR.jws.JWS
 * @class JSON Web Signature(JWS) class
 * @see <a href="http://kjur.github.com/jsjws/">'jwjws'(JWS JavaScript Library) home page http://kjur.github.com/jsjws/</a>
 * @see <a href="http://kjur.github.com/jsrsasigns/">'jwrsasign'(RSA Sign JavaScript Library) home page http://kjur.github.com/jsrsasign/</a>
 * @see <a href="http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-14">IETF I-D JSON Web Algorithms (JWA)</a>
 * @since jsjws 1.0
 * @description
 * This class provides JSON Web Signature(JWS)/JSON Web Token(JWT) signing and validation.
 *
 * <h4>METHOD SUMMARY</h4>
 * Here is major methods of {@link KJUR.jws.JWS} class.
 * <ul>
 * <li><b>SIGN</b><br/>
 * <li>{@link KJUR.jws.JWS.sign} - sign JWS</li>
 * </li>
 * <li><b>VERIFY</b><br/>
 * <li>{@link KJUR.jws.JWS.verify} - verify JWS signature</li>
 * <li>{@link KJUR.jws.JWS.verifyJWT} - verify properties of JWT token at specified time</li>
 * </li>
 * <li><b>UTILITY</b><br/>
 * <li>{@link KJUR.jws.JWS.getJWKthumbprint} - get RFC 7638 JWK thumbprint</li>
 * <li>{@link KJUR.jws.JWS.isSafeJSONString} - check whether safe JSON string or not</li>
 * <li>{@link KJUR.jws.JWS.readSafeJSONString} - read safe JSON string only</li>
 * </li>
 * </ul>
 *
 * <h4>SUPPORTED SIGNATURE ALGORITHMS</h4>
 * Here is supported algorithm names for {@link KJUR.jws.JWS.sign} and
 * {@link KJUR.jws.JWS.verify} methods.
 * <table>
 * <tr><th>alg value</th><th>spec requirement</th><th>jsjws support</th></tr>
 * <tr><td>HS256</td><td>REQUIRED</td><td>SUPPORTED</td></tr>
 * <tr><td>HS384</td><td>OPTIONAL</td><td>SUPPORTED</td></tr>
 * <tr><td>HS512</td><td>OPTIONAL</td><td>SUPPORTED</td></tr>
 * <tr><td>RS256</td><td>RECOMMENDED</td><td>SUPPORTED</td></tr>
 * <tr><td>RS384</td><td>OPTIONAL</td><td>SUPPORTED</td></tr>
 * <tr><td>RS512</td><td>OPTIONAL</td><td>SUPPORTED</td></tr>
 * <tr><td>ES256</td><td>RECOMMENDED+</td><td>SUPPORTED</td></tr>
 * <tr><td>ES384</td><td>OPTIONAL</td><td>SUPPORTED</td></tr>
 * <tr><td>ES512</td><td>OPTIONAL</td><td>-</td></tr>
 * <tr><td>PS256</td><td>OPTIONAL</td><td>SUPPORTED</td></tr>
 * <tr><td>PS384</td><td>OPTIONAL</td><td>SUPPORTED</td></tr>
 * <tr><td>PS512</td><td>OPTIONAL</td><td>SUPPORTED</td></tr>
 * <tr><td>none</td><td>REQUIRED</td><td>SUPPORTED(signature generation only)</td></tr>
 * </table>
 * <dl>
 * <dt><b>NOTE1</b>
 * <dd>HS384 is supported since jsjws 3.0.2 with jsrsasign 4.1.4.
 * <dt><b>NOTE2</b>
 * <dd>Some deprecated methods have been removed since jws 3.3 of jsrsasign 4.10.0.
 * Removed methods are following:
 * <ul>
 * <li>JWS.verifyJWSByNE</li>
 * <li>JWS.verifyJWSByKey</li>
 * <li>JWS.generateJWSByNED</li>
 * <li>JWS.generateJWSByKey</li>
 * <li>JWS.generateJWSByP1PrvKey</li>
 * </ul>
 * </dl>
 * <b>EXAMPLE</b><br/>
 * @example
 * // JWS signing
 * sJWS = KJUR.jws.JWS.sign(null, '{"alg":"HS256", "cty":"JWT"}', '{"age": 21}', {"utf8": "password"});
 * // JWS validation
 * isValid = KJUR.jws.JWS.verify('eyJjdHkiOiJKV1QiLCJhbGc...', {"utf8": "password"});
 * // JWT validation
 * isValid = KJUR.jws.JWS.verifyJWT('eyJh...', {"utf8": "password"}, {
 *   alg: ['HS256', 'HS384'],
 *   iss: ['http://foo.com']
 * });
 */
KJUR.jws.JWS = function() {
    var ns1 = KJUR.jws.JWS;

    // === utility =============================================================

    /**
     * parse JWS string and set public property 'parsedJWS' dictionary.<br/>
     * @name parseJWS
     * @memberOf KJUR.jws.JWS
     * @function
     * @param {String} sJWS JWS signature string to be parsed.
     * @throws if sJWS is not comma separated string such like "Header.Payload.Signature".
     * @throws if JWS Header is a malformed JSON string.
     * @since jws 1.1
     */
    this.parseJWS = function(sJWS, sigValNotNeeded) {
	if ((this.parsedJWS !== undefined) &&
	    (sigValNotNeeded || (this.parsedJWS.sigvalH !== undefined))) {
	    return;
	}
	if (sJWS.match(/^([^.]+)\.([^.]+)\.([^.]+)$/) == null) {
	    throw "JWS signature is not a form of 'Head.Payload.SigValue'.";
	}
	var b6Head = RegExp.$1;
	var b6Payload = RegExp.$2;
	var b6SigVal = RegExp.$3;
	var sSI = b6Head + "." + b6Payload;
	this.parsedJWS = {};
	this.parsedJWS.headB64U = b6Head;
	this.parsedJWS.payloadB64U = b6Payload;
	this.parsedJWS.sigvalB64U = b6SigVal;
	this.parsedJWS.si = sSI;

	if (!sigValNotNeeded) {
	    var hSigVal = b64utohex(b6SigVal);
	    var biSigVal = parseBigInt(hSigVal, 16);
	    this.parsedJWS.sigvalH = hSigVal;
	    this.parsedJWS.sigvalBI = biSigVal;
	}

	var sHead = b64utoutf8(b6Head);
	var sPayload = b64utoutf8(b6Payload);
	this.parsedJWS.headS = sHead;
	this.parsedJWS.payloadS = sPayload;

	if (! ns1.isSafeJSONString(sHead, this.parsedJWS, 'headP'))
	    throw "malformed JSON string for JWS Head: " + sHead;
    };
};

// === major static method ========================================================

/**
 * generate JWS signature by specified key<br/>
 * @name sign
 * @memberOf KJUR.jws.JWS
 * @function
 * @static
 * @param {String} alg JWS algorithm name to sign and force set to sHead or null
 * @param {String} spHead string or object of JWS Header
 * @param {String} spPayload string or object of JWS Payload
 * @param {String} key string of private key or mac key object to sign
 * @param {String} pass (OPTION)passcode to use encrypted asymmetric private key
 * @return {String} JWS signature string
 * @since jws 3.0.0
 * @see <a href="http://kjur.github.io/jsrsasign/api/symbols/KJUR.crypto.Signature.html">jsrsasign KJUR.crypto.Signature method</a>
 * @see <a href="http://kjur.github.io/jsrsasign/api/symbols/KJUR.crypto.Mac.html">jsrsasign KJUR.crypto.Mac method</a>
 * @description
 * This method supports following algorithms.
 * <table>
 * <tr><th>alg value</th><th>spec requirement</th><th>jsjws support</th></tr>
 * <tr><td>HS256</td><td>REQUIRED</td><td>SUPPORTED</td></tr>
 * <tr><td>HS384</td><td>OPTIONAL</td><td>SUPPORTED</td></tr>
 * <tr><td>HS512</td><td>OPTIONAL</td><td>SUPPORTED</td></tr>
 * <tr><td>RS256</td><td>RECOMMENDED</td><td>SUPPORTED</td></tr>
 * <tr><td>RS384</td><td>OPTIONAL</td><td>SUPPORTED</td></tr>
 * <tr><td>RS512</td><td>OPTIONAL</td><td>SUPPORTED</td></tr>
 * <tr><td>ES256</td><td>RECOMMENDED+</td><td>SUPPORTED</td></tr>
 * <tr><td>ES384</td><td>OPTIONAL</td><td>SUPPORTED</td></tr>
 * <tr><td>ES512</td><td>OPTIONAL</td><td>-</td></tr>
 * <tr><td>PS256</td><td>OPTIONAL</td><td>SUPPORTED</td></tr>
 * <tr><td>PS384</td><td>OPTIONAL</td><td>SUPPORTED</td></tr>
 * <tr><td>PS512</td><td>OPTIONAL</td><td>SUPPORTED</td></tr>
 * <tr><td>none</td><td>REQUIRED</td><td>SUPPORTED(signature generation only)</td></tr>
 * </table>
 * <dl>
 * <dt>NOTE1:
 * <dd>salt length of RSAPSS signature is the same as the hash algorithm length
 * because of <a href="http://www.ietf.org/mail-archive/web/jose/current/msg02901.html">IETF JOSE ML discussion</a>.
 * <dt>NOTE2:
 * <dd>To support HS384, patched version of CryptoJS is used.
 * <a href="https://code.google.com/p/crypto-js/issues/detail?id=84">See here for detail</a>.
 * <dt>NOTE3:
 * From jsrsasign 4.10.0 jws 3.3.0, Way to provide password
 * for HS* algorithm is changed. The 'key' attribute value is
 * passed to {@link KJUR.crypto.Mac.setPassword} so please see
 * {@link KJUR.crypto.Mac.setPassword} for detail.
 * As for backword compatibility, if key is a string, has even length and
 * 0..9, A-F or a-f characters, key string is treated as a hexadecimal
 * otherwise it is treated as a raw string.
 * <dd>
 * </dl>
 * <b>EXAMPLE</b><br/>
 * @example
 * // sign HS256 signature with password "aaa" implicitly handled as string
 * sJWS = KJUR.jws.JWS.sign(null, {alg: "HS256", cty: "JWT"}, {age: 21}, "aaa");
 * // sign HS256 signature with password "6161" implicitly handled as hex
 * sJWS = KJUR.jws.JWS.sign(null, {alg: "HS256", cty: "JWT"}, {age: 21}, "6161");
 * // sign HS256 signature with base64 password
 * sJWS = KJUR.jws.JWS.sign(null, {alg: "HS256"}, {age: 21}, {b64: "Mi/8..a="});
 * // sign RS256 signature with PKCS#8 PEM RSA private key
 * sJWS = KJUR.jws.JWS.sign(null, {alg: "RS256"}, {age: 21}, "-----BEGIN PRIVATE KEY...");
 * // sign RS256 signature with PKCS#8 PEM ECC private key with passcode
 * sJWS = KJUR.jws.JWS.sign(null, {alg: "ES256"}, {age: 21},
 *                          "-----BEGIN PRIVATE KEY...", "keypass");
 * // header and payload can be passed by both string and object
 * sJWS = KJUR.jws.JWS.sign(null, '{alg:"HS256",cty:"JWT"}', '{age:21}', "aaa");
 */
KJUR.jws.JWS.sign = function(alg, spHeader, spPayload, key, pass) {
    var ns1 = KJUR.jws.JWS;
    var sHeader, pHeader, sPayload;

    // 1. check signatureInput(Header, Payload) is string or object
    if (typeof spHeader != 'string' && typeof spHeader != 'object')
	throw "spHeader must be JSON string or object: " + spHeader;

    if (typeof spHeader == 'object') {
	pHeader = spHeader;
	sHeader = JSON.stringify(pHeader);
    }

    if (typeof spHeader == 'string') {
	sHeader = spHeader;
	if (! ns1.isSafeJSONString(sHeader))
	    throw "JWS Head is not safe JSON string: " + sHeader;
	pHeader = ns1.readSafeJSONString(sHeader);

    }

    sPayload = spPayload;
    if (typeof spPayload == 'object') sPayload = JSON.stringify(spPayload);

    // 2. use alg if defined in sHeader
    if ((alg == '' || alg == null) &&
	pHeader['alg'] !== undefined) {
	alg = pHeader['alg'];
    }

    // 3. update sHeader to add alg if alg undefined
    if ((alg != '' && alg != null) &&
	pHeader['alg'] === undefined) {
	pHeader['alg'] = alg;
	sHeader = JSON.stringify(pHeader);
    }

    // 4. check explicit algorithm doesn't match with JWS header.
    if (alg !== pHeader.alg)
	throw "alg and sHeader.alg doesn't match: " + alg + "!=" + pHeader.alg;

    // 5. set signature algorithm like SHA1withRSA
    var sigAlg = null;
    if (ns1.jwsalg2sigalg[alg] === undefined) {
	throw "unsupported alg name: " + alg;
    } else {
	sigAlg = ns1.jwsalg2sigalg[alg];
    }

    var uHeader = utf8tob64u(sHeader);
    var uPayload = utf8tob64u(sPayload);
    var uSignatureInput = uHeader + "." + uPayload
    // 6. sign
    var hSig = "";
    if (sigAlg.substr(0, 4) == "Hmac") {
	if (key === undefined)
	    throw "mac key shall be specified for HS* alg";
	//alert("sigAlg=" + sigAlg);
	var mac = new KJUR.crypto.Mac({'alg': sigAlg, 'prov': 'cryptojs', 'pass': key});
	mac.updateString(uSignatureInput);
	hSig = mac.doFinal();
    } else if (sigAlg.indexOf("withECDSA") != -1) {
	var sig = new KJUR.crypto.Signature({'alg': sigAlg});
	sig.init(key, pass);
	sig.updateString(uSignatureInput);
	hASN1Sig = sig.sign();
	hSig = KJUR.crypto.ECDSA.asn1SigToConcatSig(hASN1Sig);
    } else if (sigAlg != "none") {
	var sig = new KJUR.crypto.Signature({'alg': sigAlg});
	sig.init(key, pass);
	sig.updateString(uSignatureInput);
	hSig = sig.sign();
    }

    var uSig = hextob64u(hSig);
    return uSignatureInput + "." + uSig;
};

/**
 * verify JWS signature by specified key or certificate<br/>
 * @name verify
 * @memberOf KJUR.jws.JWS
 * @function
 * @static
 * @param {String} sJWS string of JWS signature to verify
 * @param {Object} key string of public key, certificate or key object to verify
 * @param {String} acceptAlgs array of algorithm name strings (OPTION)
 * @return {Boolean} true if the signature is valid otherwise false
 * @since jws 3.0.0
 * @see <a href="http://kjur.github.io/jsrsasign/api/symbols/KJUR.crypto.Signature.html">jsrsasign KJUR.crypto.Signature method</a>
 * @see <a href="http://kjur.github.io/jsrsasign/api/symbols/KJUR.crypto.Mac.html">jsrsasign KJUR.crypto.Mac method</a>
 * @description
 * <p>
 * This method verifies a JSON Web Signature Compact Serialization string by the validation
 * algorithm as described in
 * <a href="http://self-issued.info/docs/draft-jones-json-web-signature-04.html#anchor5">
 * the section 5 of Internet Draft draft-jones-json-web-signature-04.</a>
 * </p>
 * <p>
 * Since 3.2.0 strict key checking has been provided against a JWS algorithm
 * in a JWS header.
 * <ul>
 * <li>In case 'alg' is 'HS*' in the JWS header,
 * 'key' shall be hexadecimal string for Hmac{256,384,512} shared secret key.
 * Otherwise it raise an error.</li>
 * <li>In case 'alg' is 'RS*' or 'PS*' in the JWS header,
 * 'key' shall be a RSAKey object or a PEM string of
 * X.509 RSA public key certificate or PKCS#8 RSA public key.
 * Otherwise it raise an error.</li>
 * <li>In case 'alg' is 'ES*' in the JWS header,
 * 'key' shall be a KJUR.crypto.ECDSA object or a PEM string of
 * X.509 ECC public key certificate or PKCS#8 ECC public key.
 * Otherwise it raise an error.</li>
 * <li>In case 'alg' is 'none' in the JWS header,
 * validation not supported after jsjws 3.1.0.</li>
 * </ul>
 * </p>
 * <p>
 * NOTE1: The argument 'acceptAlgs' is supported since 3.2.0.
 * Strongly recommended to provide acceptAlgs to mitigate
 * signature replacement attacks.<br/>
 * </p>
 * <p>
 * NOTE2: From jsrsasign 4.9.0 jws 3.2.5, Way to provide password
 * for HS* algorithm is changed. The 'key' attribute value is
 * passed to {@link KJUR.crypto.Mac.setPassword} so please see
 * {@link KJUR.crypto.Mac.setPassword} for detail.
 * As for backword compatibility, if key is a string, has even length and
 * 0..9, A-F or a-f characters, key string is treated as a hexadecimal
 * otherwise it is treated as a raw string.
 * </p>
 * @example
 * // 1) verify a RS256 JWS signature by a certificate string.
 * isValid = KJUR.jws.JWS.verify('eyJh...', '-----BEGIN...', ['RS256']);
 *
 * // 2) verify a HS256 JWS signature by a certificate string.
 * isValid = KJUR.jws.JWS.verify('eyJh...', {hex: '6f62ad...'}, ['HS256']);
 * isValid = KJUR.jws.JWS.verify('eyJh...', {b64: 'Mi/ab8...a=='}, ['HS256']);
 * isValid = KJUR.jws.JWS.verify('eyJh...', {utf8: 'Secret秘密'}, ['HS256']);
 * isValid = KJUR.jws.JWS.verify('eyJh...', '6f62ad', ['HS256']); // implicit hex
 * isValid = KJUR.jws.JWS.verify('eyJh...', '6f62ada', ['HS256']); // implicit raw string
 *
 * // 3) verify a ES256 JWS signature by a KJUR.crypto.ECDSA key object.
 * var pubkey = KEYUTIL.getKey('-----BEGIN CERT...');
 * var isValid = KJUR.jws.JWS.verify('eyJh...', pubkey);
 */
KJUR.jws.JWS.verify = function(sJWS, key, acceptAlgs) {
    var jws = KJUR.jws.JWS;
    var a = sJWS.split(".");
    var uHeader = a[0];
    var uPayload = a[1];
    var uSignatureInput = uHeader + "." + uPayload;
    var hSig = b64utohex(a[2]);

    // 1. parse JWS header
    var pHeader = jws.readSafeJSONString(b64utoutf8(a[0]));
    var alg = null;
    var algType = null; // HS|RS|PS|ES|no
    if (pHeader.alg === undefined) {
	throw "algorithm not specified in header";
    } else {
	alg = pHeader.alg;
	algType = alg.substr(0, 2);
    }

    // 2. check whether alg is acceptable algorithms
    if (acceptAlgs != null &&
        Object.prototype.toString.call(acceptAlgs) === '[object Array]' &&
        acceptAlgs.length > 0) {
	var acceptAlgStr = ":" + acceptAlgs.join(":") + ":";
	if (acceptAlgStr.indexOf(":" + alg + ":") == -1) {
	    throw "algorithm '" + alg + "' not accepted in the list";
	}
    }

    // 3. check whether key is a proper key for alg.
    if (alg != "none" && key === null) {
	throw "key shall be specified to verify.";
    }

    // 3.1. There is no key check for HS* because Mac will check it.
    //      since jsrsasign 5.0.0.

    // 3.2. convert key object if key is a public key or cert PEM string
    if (typeof key == "string" &&
	key.indexOf("-----BEGIN ") != -1) {
	key = KEYUTIL.getKey(key);
    }

    // 3.3. check whether key is RSAKey obj if alg is RS* or PS*.
    if (algType == "RS" || algType == "PS") {
	if (!(key instanceof RSAKey)) {
	    throw "key shall be a RSAKey obj for RS* and PS* algs";
	}
    }

    // 3.4. check whether key is ECDSA obj if alg is ES*.
    if (algType == "ES") {
	if (!(key instanceof KJUR.crypto.ECDSA)) {
	    throw "key shall be a ECDSA obj for ES* algs";
	}
    }

    // 3.5. check when alg is 'none'
    if (alg == "none") {
    }

    // 4. check whether alg is supported alg in jsjws.
    var sigAlg = null;
    if (jws.jwsalg2sigalg[pHeader.alg] === undefined) {
	throw "unsupported alg name: " + alg;
    } else {
	sigAlg = jws.jwsalg2sigalg[alg];
    }

    // 5. verify
    if (sigAlg == "none") {
        throw "not supported";
    } else if (sigAlg.substr(0, 4) == "Hmac") {
	var hSig2 = null;
	if (key === undefined)
	    throw "hexadecimal key shall be specified for HMAC";
	//try {
	    var mac = new KJUR.crypto.Mac({'alg': sigAlg, 'pass': key});
	    mac.updateString(uSignatureInput);
	    hSig2 = mac.doFinal();
	//} catch(ex) {};
	return hSig == hSig2;
    } else if (sigAlg.indexOf("withECDSA") != -1) {
	var hASN1Sig = null;
        try {
	    hASN1Sig = KJUR.crypto.ECDSA.concatSigToASN1Sig(hSig);
	} catch (ex) {
	    return false;
	}
	var sig = new KJUR.crypto.Signature({'alg': sigAlg});
	sig.init(key)
	sig.updateString(uSignatureInput);
	return sig.verify(hASN1Sig);
    } else {
	var sig = new KJUR.crypto.Signature({'alg': sigAlg});
	sig.init(key)
	sig.updateString(uSignatureInput);
	return sig.verify(hSig);
    }
};

/**
 * parse header and payload of JWS signature<br/>
 * @name parse
 * @memberOf KJUR.jws.JWS
 * @function
 * @static
 * @param {String} sJWS string of JWS signature to parse
 * @return {Array} associative array of parsed header and payload. See below.
 * @throws if sJWS is malformed JWS signature
 * @since jws 3.3.3
 * @description
 * This method parses JWS signature string.
 * Resulted associative array has following properties:
 * <ul>
 * <li>headerObj - JSON object of header</li>
 * <li>payloadObj - JSON object of payload if payload is JSON string otherwise undefined</li>
 * <li>headerPP - pretty printed JSON header by stringify</li>
 * <li>payloadPP - pretty printed JSON payload by stringify if payload is JSON otherwise Base64URL decoded raw string of payload</li>
 * <li>sigHex - hexadecimal string of signature</li>
 * </ul>
 * @example
 * KJUR.jws.JWS.parse(sJWS) ->
 * {
 *   headerObj: {"alg": "RS256", "typ": "JWS"},
 *   payloadObj: {"product": "orange", "quantity": 100},
 *   headerPP:
 *   '{
 *     "alg": "RS256",
 *     "typ": "JWS"
 *   }',
 *   payloadPP:
 *   '{
 *     "product": "orange",
 *     "quantity": 100
 *   }',
 *   sigHex: "91f3cd..."
 * }
 */
KJUR.jws.JWS.parse = function(sJWS) {
    var a = sJWS.split(".");
    var result = {};
    var uHeader, uPayload, uSig;
    if (a.length != 2 && a.length != 3)
	throw "malformed sJWS: wrong number of '.' splitted elements";

    uHeader = a[0];
    uPayload = a[1];
    if (a.length == 3) uSig = a[2];

    result.headerObj = KJUR.jws.JWS.readSafeJSONString(b64utoutf8(uHeader));
    result.payloadObj = KJUR.jws.JWS.readSafeJSONString(b64utoutf8(uPayload));

    result.headerPP = JSON.stringify(result.headerObj, null, "  ");
    if (result.payloadObj == null) {
	result.payloadPP = b64utoutf8(uPayload);
    } else {
	result.payloadPP = JSON.stringify(result.payloadObj, null, "  ");
    }

    if (uSig !== undefined) {
	result.sigHex = b64utohex(uSig);
    }

    return result;
};

/**
 * @name verifyJWT
 * @memberOf KJUR.jws.JWS
 * @function
 * @static
 * @param {String} sJWT string of JSON Web Token(JWT) to verify
 * @param {Object} key string of public key, certificate or key object to verify
 * @param {Array} acceptField associative array of acceptable fields (OPTION)
 * @return {Boolean} true if the JWT token is valid otherwise false
 * @since jws 3.2.3 jsrsasign 4.8.0
 *
 * @description
 * This method verifies a
 * <a href="https://tools.ietf.org/html/rfc7519">RFC 7519</a>
 * JSON Web Token(JWT).
 * It will verify following:
 * <ul>
 * <li>Header.alg
 * <ul>
 * <li>alg is specified in JWT header.</li>
 * <li>alg is included in acceptField.alg array. (MANDATORY)</li>
 * <li>alg is proper for key.</li>
 * </ul>
 * </li>
 * <li>Payload.iss (issuer) - Payload.iss is included in acceptField.iss array if specified. (OPTION)</li>
 * <li>Payload.sub (subject) - Payload.sub is included in acceptField.sub array if specified. (OPTION)</li>
 * <li>Payload.aud (audience) - Payload.aud is included in acceptField.aud array or
 *     the same as value if specified. (OPTION)</li>
 * <li>Time validity
 * <ul>
 * <li>
 * If acceptField.verifyAt as number of UNIX origin time is specifed for validation time,
 * this method will verify at the time for it, otherwise current time will be used to verify.
 * </li>
 * <li>
 * Clock of JWT generator or verifier can be fast or slow. If these clocks are
 * very different, JWT validation may fail. To avoid such case, 'jsrsasign' supports
 * 'acceptField.gracePeriod' parameter which specifies acceptable time difference
 * of those clocks in seconds. So if you want to accept slow or fast in 2 hours,
 * you can specify <code>acceptField.gracePeriod = 2 * 60 * 60;</code>.
 * "gracePeriod" is zero by default.
 * "gracePeriod" is supported since jsrsasign 5.0.12.
 * </li>
 * <li>Payload.exp (expire) - Validation time is smaller than Payload.exp + gracePeriod.</li>
 * <li>Payload.nbf (not before) - Validation time is greater than Payload.nbf - gracePeriod.</li>
 * <li>Payload.iat (issued at) - Validation time is greater than Payload.iat - gracePeriod.</li>
 * </ul>
 * </li>
 * <li>Payload.jti (JWT id) - Payload.jti is included in acceptField.jti if specified. (OPTION)</li>
 * <li>JWS signature of JWS is valid for specified key.</li>
 * </ul>
 *
 * <h4>acceptField parameters</h4>
 * Here is available acceptField argument parameters:
 * <ul>
 * <li>alg - array of acceptable signature algorithm names (ex. ["HS256", "HS384"])</li>
 * <li>iss - array of acceptable issuer names (ex. ['http://foo.com'])</li>
 * <li>sub - array of acceptable subject names (ex. ['mailto:john@foo.com'])</li>
 * <li>aud - array or string of acceptable audience name(s) (ex. ['http://foo.com'])</li>
 * <li>jti - string of acceptable JWT ID (OPTION) (ex. 'id1234')</li>
 * <li>
 * verifyAt - time to verify 'nbf', 'iat' and 'exp' in UNIX seconds
 * (OPTION) (ex. 1377663900).
 * If this is not specified, current time of verifier will be used.
 * {@link KJUR.jws.IntDate} may be useful to specify it.
 * </li>
 * <li>gracePeriod - acceptable time difference between signer and verifier
 * in seconds (ex. 3600). If this is not specified, zero will be used.</li>
 * </ul>
 *
 * @example
 * // simple validation for HS256
 * isValid = KJUR.jws.JWS.verifyJWT("eyJhbG...", "616161", {alg: ["HS256"]}),
 *
 * // full validation for RS or PS
 * pubkey = KEYUTIL.getKey('-----BEGIN CERT...');
 * isValid = KJUR.jws.JWS.verifyJWT('eyJh...', pubkey, {
 *   alg: ['RS256', 'RS512', 'PS256', 'PS512'],
 *   iss: ['http://foo.com'],
 *   sub: ['mailto:john@foo.com', 'mailto:alice@foo.com'],
 *   verifyAt: KJUR.jws.IntDate.get('20150520235959Z'),
 *   aud: ['http://foo.com'], // aud: 'http://foo.com' is fine too.
 *   jti: 'id123456',
 *   gracePeriod: 1 * 60 * 60 // accept 1 hour slow or fast
 * });
 */
KJUR.jws.JWS.verifyJWT = function(sJWT, key, acceptField) {
    var ns1 = KJUR.jws.JWS;

    // 1. parse JWT
    var a = sJWT.split(".");
    var uHeader = a[0];
    var uPayload = a[1];
    var uSignatureInput = uHeader + "." + uPayload;
    var hSig = b64utohex(a[2]);

    // 2. parse JWS header
    var pHeader = ns1.readSafeJSONString(b64utoutf8(uHeader));

    // 3. parse JWS payload
    var pPayload = ns1.readSafeJSONString(b64utoutf8(uPayload));

    // 4. algorithm ('alg' in header) check
    if (pHeader.alg === undefined) return false;
    if (acceptField.alg === undefined)
	throw "acceptField.alg shall be specified";
    if (! ns1.inArray(pHeader.alg, acceptField.alg)) return false;

    // 5. issuer ('iss' in payload) check
    if (pPayload.iss !== undefined && typeof acceptField.iss === "object") {
	if (! ns1.inArray(pPayload.iss, acceptField.iss)) return false;
    }

    // 6. subject ('sub' in payload) check
    if (pPayload.sub !== undefined && typeof acceptField.sub === "object") {
	if (! ns1.inArray(pPayload.sub, acceptField.sub)) return false;
    }

    // 7. audience ('aud' in payload) check
    if (pPayload.aud !== undefined && typeof acceptField.aud === "object") {
	if (typeof pPayload.aud == "string") {
	    if (! ns1.inArray(pPayload.aud, acceptField.aud))
		return false;
	} else if (typeof pPayload.aud == "object") {
	    if (! ns1.includedArray(pPayload.aud, acceptField.aud))
		return false;
	}
    }

    // 8. time validity
    //   (nbf - gracePeriod < now < exp + gracePeriod) && (iat - gracePeriod < now)
    var now = KJUR.jws.IntDate.getNow();
    if (acceptField.verifyAt !== undefined && typeof acceptField.verifyAt === "number") {
	now = acceptField.verifyAt;
    }
    if (acceptField.gracePeriod === undefined ||
        typeof acceptField.gracePeriod !== "number") {
	acceptField.gracePeriod = 0;
    }

    // 8.1 expired time 'exp' check
    if (pPayload.exp !== undefined && typeof pPayload.exp == "number") {
	if (pPayload.exp + acceptField.gracePeriod < now) return false;
    }

    // 8.2 not before time 'nbf' check
    if (pPayload.nbf !== undefined && typeof pPayload.nbf == "number") {
	if (now < pPayload.nbf - acceptField.gracePeriod) return false;
    }

    // 8.3 issued at time 'iat' check
    if (pPayload.iat !== undefined && typeof pPayload.iat == "number") {
	if (now < pPayload.iat - acceptField.gracePeriod) return false;
    }

    // 9 JWT id 'jti' check
    if (pPayload.jti !== undefined && acceptField.jti !== undefined) {
      if (pPayload.jti !== acceptField.jti) return false;
    }

    // 10 JWS signature check
    if (! KJUR.jws.JWS.verify(sJWT, key, acceptField.alg)) return false;

    // 11 passed all check
    return true;
};

/**
 * check whether array is included by another array
 * @name includedArray
 * @memberOf KJUR.jws.JWS
 * @function
 * @static
 * @param {Array} a1 check whether set a1 is included by a2
 * @param {Array} a2 check whether set a1 is included by a2
 * @return {Boolean} check whether set a1 is included by a2
 * @since jws 3.2.3
 * This method verifies whether an array is included by another array.
 * It doesn't care about item ordering in a array.
 * @example
 * KJUR.jws.JWS.includedArray(['b'], ['b', 'c', 'a']) => true
 * KJUR.jws.JWS.includedArray(['a', 'b'], ['b', 'c', 'a']) => true
 * KJUR.jws.JWS.includedArray(['a', 'b'], ['b', 'c']) => false
 */
KJUR.jws.JWS.includedArray = function(a1, a2) {
    var inArray = KJUR.jws.JWS.inArray;
    if (a1 === null) return false;
    if (typeof a1 !== "object") return false;
    if (typeof a1.length !== "number") return false;

    for (var i = 0; i < a1.length; i++) {
	if (! inArray(a1[i], a2)) return false;
    }
    return true;
};

/**
 * check whether item is included by array
 * @name inArray
 * @memberOf KJUR.jws.JWS
 * @function
 * @static
 * @param {String} item check whether item is included by array
 * @param {Array} a check whether item is included by array
 * @return {Boolean} check whether item is included by array
 * @since jws 3.2.3
 * This method verifies whether an item is included by an array.
 * It doesn't care about item ordering in an array.
 * @example
 * KJUR.jws.JWS.inArray('b', ['b', 'c', 'a']) => true
 * KJUR.jws.JWS.inArray('a', ['b', 'c', 'a']) => true
 * KJUR.jws.JWS.inArray('a', ['b', 'c']) => false
 */
KJUR.jws.JWS.inArray = function(item, a) {
    if (a === null) return false;
    if (typeof a !== "object") return false;
    if (typeof a.length !== "number") return false;
    for (var i = 0; i < a.length; i++) {
	if (a[i] == item) return true;
    }
    return false;
};

/**
 * static associative array of general signature algorithm name from JWS algorithm name
 * @since jws 3.0.0
 */
KJUR.jws.JWS.jwsalg2sigalg = {
    "HS256":	"HmacSHA256",
    "HS384":	"HmacSHA384",
    "HS512":	"HmacSHA512",
    "RS256":	"SHA256withRSA",
    "RS384":	"SHA384withRSA",
    "RS512":	"SHA512withRSA",
    "ES256":	"SHA256withECDSA",
    "ES384":	"SHA384withECDSA",
    //"ES512":	"SHA512withECDSA", // unsupported because of jsrsasign's bug
    "PS256":	"SHA256withRSAandMGF1",
    "PS384":	"SHA384withRSAandMGF1",
    "PS512":	"SHA512withRSAandMGF1",
    "none":	"none",
};

// === utility static method ==================================================

/**
 * check whether a String "s" is a safe JSON string or not.<br/>
 * If a String "s" is a malformed JSON string or an other object type
 * this returns 0, otherwise this returns 1.
 * @name isSafeJSONString
 * @memberOf KJUR.jws.JWS
 * @function
 * @static
 * @param {String} s JSON string
 * @return {Number} 1 or 0
 */
KJUR.jws.JWS.isSafeJSONString = function(s, h, p) {
    var o = null;
    try {
	o = jsonParse(s);
	if (typeof o != "object") return 0;
	if (o.constructor === Array) return 0;
	if (h) h[p] = o;
	return 1;
    } catch (ex) {
	return 0;
    }
};

/**
 * read a String "s" as JSON object if it is safe.<br/>
 * If a String "s" is a malformed JSON string or not JSON string,
 * this returns null, otherwise returns JSON object.
 * @name readSafeJSONString
 * @memberOf KJUR.jws.JWS
 * @function
 * @static
 * @param {String} s JSON string
 * @return {Object} JSON object or null
 * @since 1.1.1
 */
KJUR.jws.JWS.readSafeJSONString = function(s) {
    var o = null;
    try {
	o = jsonParse(s);
	if (typeof o != "object") return null;
	if (o.constructor === Array) return null;
	return o;
    } catch (ex) {
	return null;
    }
};

/**
 * get Encoed Signature Value from JWS string.<br/>
 * @name getEncodedSignatureValueFromJWS
 * @memberOf KJUR.jws.JWS
 * @function
 * @static
 * @param {String} sJWS JWS signature string to be verified
 * @return {String} string of Encoded Signature Value
 * @throws if sJWS is not comma separated string such like "Header.Payload.Signature".
 */
KJUR.jws.JWS.getEncodedSignatureValueFromJWS = function(sJWS) {
    if (sJWS.match(/^[^.]+\.[^.]+\.([^.]+)$/) == null) {
	throw "JWS signature is not a form of 'Head.Payload.SigValue'.";
    }
    return RegExp.$1;
};

/**
 * get RFC 7638 JWK thumbprint from JWK object
 * @name getJWKthumbprint
 * @memberOf KJUR.jws.JWS
 * @function
 * @static
 * @param {Object} o JWK object to be calculated thumbprint
 * @return {String} Base64 URL encoded JWK thumbprint value
 * @since jsrsasign 5.0.2 jws 3.3.2
 * @description
 * This method calculates JWK thmubprint for specified JWK object
 * as described in
 * <a href="https://tools.ietf.org/html/rfc7638">RFC 7638</a>.
 * It supports all type of "kty". (i.e. "RSA", "EC" and "oct"
 * (for symmetric key))
 * Working sample is
 * <a href="https://kjur.github.io/jsrsasign/sample/tool_jwktp.html">here</a>.
 * @example
 * jwk = {"kty":"RSA", "n":"0vx...", "e":"AQAB", ...};
 * thumbprint = KJUR.jws.JWS.getJWKthumbprint(jwk);
 */
KJUR.jws.JWS.getJWKthumbprint = function(o) {
    if (o.kty !== "RSA" &&
	o.kty !== "EC" &&
	o.kty !== "oct")
	throw "unsupported algorithm for JWK Thumprint";

    // 1. get canonically ordered json string
    var s = '{';
    if (o.kty === "RSA") {
	if (typeof o.n != "string" || typeof o.e != "string")
	    throw "wrong n and e value for RSA key";
	s += '"' + 'e' + '":"' + o.e + '",';
	s += '"' + 'kty' + '":"' + o.kty + '",';
	s += '"' + 'n' + '":"' + o.n + '"}';
    } else if (o.kty === "EC") {
	if (typeof o.crv != "string" ||
	    typeof o.x != "string" ||
	    typeof o.y != "string")
	    throw "wrong crv, x and y value for EC key";
	s += '"' + 'crv' + '":"' + o.crv + '",';
	s += '"' + 'kty' + '":"' + o.kty + '",';
	s += '"' + 'x' + '":"' + o.x + '",';
	s += '"' + 'y' + '":"' + o.y + '"}';
    } else if (o.kty === "oct") {
	if (typeof o.k != "string")
	    throw "wrong k value for oct(symmetric) key";
	s += '"' + 'kty' + '":"' + o.kty + '",';
	s += '"' + 'k' + '":"' + o.k + '"}';
    }
    //alert(s);

    // 2. get thumb print
    var hJWK = rstrtohex(s);
    var hash = KJUR.crypto.Util.hashHex(hJWK, "sha256");
    var hashB64U = hextob64u(hash);

    return hashB64U;
};

/**
 * IntDate class for time representation for JSON Web Token(JWT)
 * @class KJUR.jws.IntDate class
 * @name KJUR.jws.IntDate
 * @since jws 3.0.1
 * @description
 * Utility class for IntDate which is integer representation of UNIX origin time
 * used in JSON Web Token(JWT).
 */
KJUR.jws.IntDate = {};

/**
 * get UNIX origin time from by string
 * @name get
 * @memberOf KJUR.jws.IntDate
 * @function
 * @static
 * @param {String} s string of time representation
 * @return {Integer} UNIX origin time in seconds for argument 's'
 * @since jws 3.0.1
 * @throws "unsupported format: s" when malformed format
 * @description
 * This method will accept following representation of time.
 * <ul>
 * <li>now - current time</li>
 * <li>now + 1hour - after 1 hour from now</li>
 * <li>now + 1day - after 1 day from now</li>
 * <li>now + 1month - after 30 days from now</li>
 * <li>now + 1year - after 365 days from now</li>
 * <li>YYYYmmDDHHMMSSZ - UTC time (ex. 20130828235959Z)</li>
 * <li>number - UNIX origin time (seconds from 1970-01-01 00:00:00) (ex. 1377714748)</li>
 * </ul>
 */
KJUR.jws.IntDate.get = function(s) {
    if (s == "now") {
	return KJUR.jws.IntDate.getNow();
    } else if (s == "now + 1hour") {
	return KJUR.jws.IntDate.getNow() + 60 * 60;
    } else if (s == "now + 1day") {
	return KJUR.jws.IntDate.getNow() + 60 * 60 * 24;
    } else if (s == "now + 1month") {
	return KJUR.jws.IntDate.getNow() + 60 * 60 * 24 * 30;
    } else if (s == "now + 1year") {
	return KJUR.jws.IntDate.getNow() + 60 * 60 * 24 * 365;
    } else if (s.match(/Z$/)) {
	return KJUR.jws.IntDate.getZulu(s);
    } else if (s.match(/^[0-9]+$/)) {
	return parseInt(s);
    }
    throw "unsupported format: " + s;
};

/**
 * get UNIX origin time from Zulu time representation string
 * @name getZulu
 * @memberOf KJUR.jws.IntDate
 * @function
 * @static
 * @param {String} s string of Zulu time representation (ex. 20151012125959Z)
 * @return {Integer} UNIX origin time in seconds for argument 's'
 * @since jws 3.0.1
 * @throws "unsupported format: s" when malformed format
 * @description
 * This method provides UNIX origin time from Zulu time.
 * Following representations are supported:
 * <ul>
 * <li>YYYYMMDDHHmmSSZ - GeneralizedTime format</li>
 * <li>YYMMDDHHmmSSZ - UTCTime format. If YY is greater or equal to
 * 50 then it represents 19YY otherwise 20YY.</li>
 * </ul>
 * @example
 * KJUR.jws.IntDate.getZulu("20151012125959Z") => 1478...
 * KJUR.jws.IntDate.getZulu("151012125959Z") => 1478...
 */
KJUR.jws.IntDate.getZulu = function(s) {
    var a;
    if (a = s.match(/(\d+)(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)Z/)) {
        var sYear = RegExp.$1;
	var year = parseInt(sYear);
	if (sYear.length == 4) {
        } else if (sYear.length == 2) {
	    if (50 <= year && year < 100) {
		year = 1900 + year;
	    } else if (0 <= year && year < 50) {
		year = 2000 + year;
	    } else {
		throw "malformed year string for UTCTime";
	    }
	} else {
	    throw "malformed year string";
	}
	var month = parseInt(RegExp.$2) - 1;
	var day = parseInt(RegExp.$3);
	var hour = parseInt(RegExp.$4);
	var min = parseInt(RegExp.$5);
	var sec = parseInt(RegExp.$6);
	var d = new Date(Date.UTC(year, month, day, hour, min, sec));
	return ~~(d / 1000);
    }
    throw "unsupported format: " + s;
};

/**
 * get UNIX origin time of current time
 * @name getNow
 * @memberOf KJUR.jws.IntDate
 * @function
 * @static
 * @return {Integer} UNIX origin time for current time
 * @since jws 3.0.1
 * @description
 * This method provides UNIX origin time for current time
 * @example
 * KJUR.jws.IntDate.getNow() => 1478...
 */
KJUR.jws.IntDate.getNow = function() {
    var d = ~~(new Date() / 1000);
    return d;
};

/**
 * get UTC time string from UNIX origin time value
 * @name intDate2UTCString
 * @memberOf KJUR.jws.IntDate
 * @function
 * @static
 * @param {Integer} intDate UNIX origin time value (ex. 1478...)
 * @return {String} UTC time string
 * @since jws 3.0.1
 * @description
 * This method provides UTC time string for UNIX origin time value.
 * @example
 * KJUR.jws.IntDate.intDate2UTCString(1478...) => "2015 Oct ..."
 */
KJUR.jws.IntDate.intDate2UTCString = function(intDate) {
    var d = new Date(intDate * 1000);
    return d.toUTCString();
};

/**
 * get UTC time string from UNIX origin time value
 * @name intDate2Zulu
 * @memberOf KJUR.jws.IntDate
 * @function
 * @static
 * @param {Integer} intDate UNIX origin time value (ex. 1478...)
 * @return {String} Zulu time string
 * @since jws 3.0.1
 * @description
 * This method provides Zulu time string for UNIX origin time value.
 * @example
 * KJUR.jws.IntDate.intDate2UTCString(1478...) => "20151012...Z"
 */
KJUR.jws.IntDate.intDate2Zulu = function(intDate) {
    var d = new Date(intDate * 1000);
    var year = ("0000" + d.getUTCFullYear()).slice(-4);
    var mon =  ("00" + (d.getUTCMonth() + 1)).slice(-2);
    var day =  ("00" + d.getUTCDate()).slice(-2);
    var hour = ("00" + d.getUTCHours()).slice(-2);
    var min =  ("00" + d.getUTCMinutes()).slice(-2);
    var sec =  ("00" + d.getUTCSeconds()).slice(-2);
    return year + mon + day + hour + min + sec + "Z";
};

/*! crypto-1.1.8.js (c) 2013-2016 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
/*
 * crypto.js - Cryptographic Algorithm Provider class
 *
 * Copyright (c) 2013-2016 Kenji Urushima (kenji.urushima@gmail.com)
 *
 * This software is licensed under the terms of the MIT License.
 * http://kjur.github.com/jsrsasign/license
 *
 * The above copyright and license notice shall be 
 * included in all copies or substantial portions of the Software.
 */

/**
 * @fileOverview
 * @name crypto-1.1.js
 * @author Kenji Urushima kenji.urushima@gmail.com
 * @version 1.1.8 (2016-Feb-28)
 * @since jsrsasign 2.2
 * @license <a href="http://kjur.github.io/jsrsasign/license/">MIT License</a>
 */

/** 
 * kjur's class library name space
 * @name KJUR
 * @namespace kjur's class library name space
 */
if (typeof KJUR == "undefined" || !KJUR) KJUR = {};
/**
 * kjur's cryptographic algorithm provider library name space
 * <p>
 * This namespace privides following crytpgrahic classes.
 * <ul>
 * <li>{@link KJUR.crypto.MessageDigest} - Java JCE(cryptograhic extension) style MessageDigest class</li>
 * <li>{@link KJUR.crypto.Signature} - Java JCE(cryptograhic extension) style Signature class</li>
 * <li>{@link KJUR.crypto.Util} - cryptographic utility functions and properties</li>
 * </ul>
 * NOTE: Please ignore method summary and document of this namespace. This caused by a bug of jsdoc2.
 * </p>
 * @name KJUR.crypto
 * @namespace
 */
if (typeof KJUR.crypto == "undefined" || !KJUR.crypto) KJUR.crypto = {};

/**
 * static object for cryptographic function utilities
 * @name KJUR.crypto.Util
 * @class static object for cryptographic function utilities
 * @property {Array} DIGESTINFOHEAD PKCS#1 DigestInfo heading hexadecimal bytes for each hash algorithms
 * @property {Array} DEFAULTPROVIDER associative array of default provider name for each hash and signature algorithms
 * @description
 */
KJUR.crypto.Util = new function() {
    this.DIGESTINFOHEAD = {
	'sha1':      "3021300906052b0e03021a05000414",
        'sha224':    "302d300d06096086480165030402040500041c",
	'sha256':    "3031300d060960864801650304020105000420",
	'sha384':    "3041300d060960864801650304020205000430",
	'sha512':    "3051300d060960864801650304020305000440",
	'md2':       "3020300c06082a864886f70d020205000410",
	'md5':       "3020300c06082a864886f70d020505000410",
	'ripemd160': "3021300906052b2403020105000414",
    };

    /*
     * @since crypto 1.1.1
     */
    this.DEFAULTPROVIDER = {
	'md5':			'cryptojs',
	'sha1':			'cryptojs',
	'sha224':		'cryptojs',
	'sha256':		'cryptojs',
	'sha384':		'cryptojs',
	'sha512':		'cryptojs',
	'ripemd160':		'cryptojs',
	'hmacmd5':		'cryptojs',
	'hmacsha1':		'cryptojs',
	'hmacsha224':		'cryptojs',
	'hmacsha256':		'cryptojs',
	'hmacsha384':		'cryptojs',
	'hmacsha512':		'cryptojs',
	'hmacripemd160':	'cryptojs',

	'MD5withRSA':		'cryptojs/jsrsa',
	'SHA1withRSA':		'cryptojs/jsrsa',
	'SHA224withRSA':	'cryptojs/jsrsa',
	'SHA256withRSA':	'cryptojs/jsrsa',
	'SHA384withRSA':	'cryptojs/jsrsa',
	'SHA512withRSA':	'cryptojs/jsrsa',
	'RIPEMD160withRSA':	'cryptojs/jsrsa',

	'MD5withECDSA':		'cryptojs/jsrsa',
	'SHA1withECDSA':	'cryptojs/jsrsa',
	'SHA224withECDSA':	'cryptojs/jsrsa',
	'SHA256withECDSA':	'cryptojs/jsrsa',
	'SHA384withECDSA':	'cryptojs/jsrsa',
	'SHA512withECDSA':	'cryptojs/jsrsa',
	'RIPEMD160withECDSA':	'cryptojs/jsrsa',

	'SHA1withDSA':		'cryptojs/jsrsa',
	'SHA224withDSA':	'cryptojs/jsrsa',
	'SHA256withDSA':	'cryptojs/jsrsa',

	'MD5withRSAandMGF1':		'cryptojs/jsrsa',
	'SHA1withRSAandMGF1':		'cryptojs/jsrsa',
	'SHA224withRSAandMGF1':		'cryptojs/jsrsa',
	'SHA256withRSAandMGF1':		'cryptojs/jsrsa',
	'SHA384withRSAandMGF1':		'cryptojs/jsrsa',
	'SHA512withRSAandMGF1':		'cryptojs/jsrsa',
	'RIPEMD160withRSAandMGF1':	'cryptojs/jsrsa',
    };

    /*
     * @since crypto 1.1.2
     */
    this.CRYPTOJSMESSAGEDIGESTNAME = {
	'md5':		CryptoJS.algo.MD5,
	'sha1':		CryptoJS.algo.SHA1,
	'sha224':	CryptoJS.algo.SHA224,
	'sha256':	CryptoJS.algo.SHA256,
	'sha384':	CryptoJS.algo.SHA384,
	'sha512':	CryptoJS.algo.SHA512,
	'ripemd160':	CryptoJS.algo.RIPEMD160
    };

    /**
     * get hexadecimal DigestInfo
     * @name getDigestInfoHex
     * @memberOf KJUR.crypto.Util
     * @function
     * @param {String} hHash hexadecimal hash value
     * @param {String} alg hash algorithm name (ex. 'sha1')
     * @return {String} hexadecimal string DigestInfo ASN.1 structure
     */
    this.getDigestInfoHex = function(hHash, alg) {
	if (typeof this.DIGESTINFOHEAD[alg] == "undefined")
	    throw "alg not supported in Util.DIGESTINFOHEAD: " + alg;
	return this.DIGESTINFOHEAD[alg] + hHash;
    };

    /**
     * get PKCS#1 padded hexadecimal DigestInfo
     * @name getPaddedDigestInfoHex
     * @memberOf KJUR.crypto.Util
     * @function
     * @param {String} hHash hexadecimal hash value of message to be signed
     * @param {String} alg hash algorithm name (ex. 'sha1')
     * @param {Integer} keySize key bit length (ex. 1024)
     * @return {String} hexadecimal string of PKCS#1 padded DigestInfo
     */
    this.getPaddedDigestInfoHex = function(hHash, alg, keySize) {
	var hDigestInfo = this.getDigestInfoHex(hHash, alg);
	var pmStrLen = keySize / 4; // minimum PM length

	if (hDigestInfo.length + 22 > pmStrLen) // len(0001+ff(*8)+00+hDigestInfo)=22
	    throw "key is too short for SigAlg: keylen=" + keySize + "," + alg;

	var hHead = "0001";
	var hTail = "00" + hDigestInfo;
	var hMid = "";
	var fLen = pmStrLen - hHead.length - hTail.length;
	for (var i = 0; i < fLen; i += 2) {
	    hMid += "ff";
	}
	var hPaddedMessage = hHead + hMid + hTail;
	return hPaddedMessage;
    };

    /**
     * get hexadecimal hash of string with specified algorithm
     * @name hashString
     * @memberOf KJUR.crypto.Util
     * @function
     * @param {String} s input string to be hashed
     * @param {String} alg hash algorithm name
     * @return {String} hexadecimal string of hash value
     * @since 1.1.1
     */
    this.hashString = function(s, alg) {
        var md = new KJUR.crypto.MessageDigest({'alg': alg});
        return md.digestString(s);
    };

    /**
     * get hexadecimal hash of hexadecimal string with specified algorithm
     * @name hashHex
     * @memberOf KJUR.crypto.Util
     * @function
     * @param {String} sHex input hexadecimal string to be hashed
     * @param {String} alg hash algorithm name
     * @return {String} hexadecimal string of hash value
     * @since 1.1.1
     */
    this.hashHex = function(sHex, alg) {
        var md = new KJUR.crypto.MessageDigest({'alg': alg});
        return md.digestHex(sHex);
    };

    /**
     * get hexadecimal SHA1 hash of string
     * @name sha1
     * @memberOf KJUR.crypto.Util
     * @function
     * @param {String} s input string to be hashed
     * @return {String} hexadecimal string of hash value
     * @since 1.0.3
     */
    this.sha1 = function(s) {
        var md = new KJUR.crypto.MessageDigest({'alg':'sha1', 'prov':'cryptojs'});
        return md.digestString(s);
    };

    /**
     * get hexadecimal SHA256 hash of string
     * @name sha256
     * @memberOf KJUR.crypto.Util
     * @function
     * @param {String} s input string to be hashed
     * @return {String} hexadecimal string of hash value
     * @since 1.0.3
     */
    this.sha256 = function(s) {
        var md = new KJUR.crypto.MessageDigest({'alg':'sha256', 'prov':'cryptojs'});
        return md.digestString(s);
    };

    this.sha256Hex = function(s) {
        var md = new KJUR.crypto.MessageDigest({'alg':'sha256', 'prov':'cryptojs'});
        return md.digestHex(s);
    };

    /**
     * get hexadecimal SHA512 hash of string
     * @name sha512
     * @memberOf KJUR.crypto.Util
     * @function
     * @param {String} s input string to be hashed
     * @return {String} hexadecimal string of hash value
     * @since 1.0.3
     */
    this.sha512 = function(s) {
        var md = new KJUR.crypto.MessageDigest({'alg':'sha512', 'prov':'cryptojs'});
        return md.digestString(s);
    };

    this.sha512Hex = function(s) {
        var md = new KJUR.crypto.MessageDigest({'alg':'sha512', 'prov':'cryptojs'});
        return md.digestHex(s);
    };

    /**
     * get hexadecimal MD5 hash of string
     * @name md5
     * @memberOf KJUR.crypto.Util
     * @function
     * @param {String} s input string to be hashed
     * @return {String} hexadecimal string of hash value
     * @since 1.0.3
     */
    this.md5 = function(s) {
        var md = new KJUR.crypto.MessageDigest({'alg':'md5', 'prov':'cryptojs'});
        return md.digestString(s);
    };

    /**
     * get hexadecimal RIPEMD160 hash of string
     * @name ripemd160
     * @memberOf KJUR.crypto.Util
     * @function
     * @param {String} s input string to be hashed
     * @return {String} hexadecimal string of hash value
     * @since 1.0.3
     */
    this.ripemd160 = function(s) {
        var md = new KJUR.crypto.MessageDigest({'alg':'ripemd160', 'prov':'cryptojs'});
        return md.digestString(s);
    };

    /*
     * @since 1.1.2
     */
    this.getCryptoJSMDByName = function(s) {
	
    };
};

/**
 * MessageDigest class which is very similar to java.security.MessageDigest class
 * @name KJUR.crypto.MessageDigest
 * @class MessageDigest class which is very similar to java.security.MessageDigest class
 * @param {Array} params parameters for constructor
 * @description
 * <br/>
 * Currently this supports following algorithm and providers combination:
 * <ul>
 * <li>md5 - cryptojs</li>
 * <li>sha1 - cryptojs</li>
 * <li>sha224 - cryptojs</li>
 * <li>sha256 - cryptojs</li>
 * <li>sha384 - cryptojs</li>
 * <li>sha512 - cryptojs</li>
 * <li>ripemd160 - cryptojs</li>
 * <li>sha256 - sjcl (NEW from crypto.js 1.0.4)</li>
 * </ul>
 * @example
 * // CryptoJS provider sample
 * var md = new KJUR.crypto.MessageDigest({alg: "sha1", prov: "cryptojs"});
 * md.updateString('aaa')
 * var mdHex = md.digest()
 *
 * // SJCL(Stanford JavaScript Crypto Library) provider sample
 * var md = new KJUR.crypto.MessageDigest({alg: "sha256", prov: "sjcl"}); // sjcl supports sha256 only
 * md.updateString('aaa')
 * var mdHex = md.digest()
 */
KJUR.crypto.MessageDigest = function(params) {
    var md = null;
    var algName = null;
    var provName = null;

    /**
     * set hash algorithm and provider
     * @name setAlgAndProvider
     * @memberOf KJUR.crypto.MessageDigest
     * @function
     * @param {String} alg hash algorithm name
     * @param {String} prov provider name
     * @description
     * @example
     * // for SHA1
     * md.setAlgAndProvider('sha1', 'cryptojs');
     * // for RIPEMD160
     * md.setAlgAndProvider('ripemd160', 'cryptojs');
     */
    this.setAlgAndProvider = function(alg, prov) {
	if (alg != null && prov === undefined) prov = KJUR.crypto.Util.DEFAULTPROVIDER[alg];

	// for cryptojs
	if (':md5:sha1:sha224:sha256:sha384:sha512:ripemd160:'.indexOf(alg) != -1 &&
	    prov == 'cryptojs') {
	    try {
		this.md = KJUR.crypto.Util.CRYPTOJSMESSAGEDIGESTNAME[alg].create();
	    } catch (ex) {
		throw "setAlgAndProvider hash alg set fail alg=" + alg + "/" + ex;
	    }
	    this.updateString = function(str) {
		this.md.update(str);
	    };
	    this.updateHex = function(hex) {
		var wHex = CryptoJS.enc.Hex.parse(hex);
		this.md.update(wHex);
	    };
	    this.digest = function() {
		var hash = this.md.finalize();
		return hash.toString(CryptoJS.enc.Hex);
	    };
	    this.digestString = function(str) {
		this.updateString(str);
		return this.digest();
	    };
	    this.digestHex = function(hex) {
		this.updateHex(hex);
		return this.digest();
	    };
	}
	if (':sha256:'.indexOf(alg) != -1 &&
	    prov == 'sjcl') {
	    try {
		this.md = new sjcl.hash.sha256();
	    } catch (ex) {
		throw "setAlgAndProvider hash alg set fail alg=" + alg + "/" + ex;
	    }
	    this.updateString = function(str) {
		this.md.update(str);
	    };
	    this.updateHex = function(hex) {
		var baHex = sjcl.codec.hex.toBits(hex);
		this.md.update(baHex);
	    };
	    this.digest = function() {
		var hash = this.md.finalize();
		return sjcl.codec.hex.fromBits(hash);
	    };
	    this.digestString = function(str) {
		this.updateString(str);
		return this.digest();
	    };
	    this.digestHex = function(hex) {
		this.updateHex(hex);
		return this.digest();
	    };
	}
    };

    /**
     * update digest by specified string
     * @name updateString
     * @memberOf KJUR.crypto.MessageDigest
     * @function
     * @param {String} str string to update
     * @description
     * @example
     * md.updateString('New York');
     */
    this.updateString = function(str) {
	throw "updateString(str) not supported for this alg/prov: " + this.algName + "/" + this.provName;
    };

    /**
     * update digest by specified hexadecimal string
     * @name updateHex
     * @memberOf KJUR.crypto.MessageDigest
     * @function
     * @param {String} hex hexadecimal string to update
     * @description
     * @example
     * md.updateHex('0afe36');
     */
    this.updateHex = function(hex) {
	throw "updateHex(hex) not supported for this alg/prov: " + this.algName + "/" + this.provName;
    };

    /**
     * completes hash calculation and returns hash result
     * @name digest
     * @memberOf KJUR.crypto.MessageDigest
     * @function
     * @description
     * @example
     * md.digest()
     */
    this.digest = function() {
	throw "digest() not supported for this alg/prov: " + this.algName + "/" + this.provName;
    };

    /**
     * performs final update on the digest using string, then completes the digest computation
     * @name digestString
     * @memberOf KJUR.crypto.MessageDigest
     * @function
     * @param {String} str string to final update
     * @description
     * @example
     * md.digestString('aaa')
     */
    this.digestString = function(str) {
	throw "digestString(str) not supported for this alg/prov: " + this.algName + "/" + this.provName;
    };

    /**
     * performs final update on the digest using hexadecimal string, then completes the digest computation
     * @name digestHex
     * @memberOf KJUR.crypto.MessageDigest
     * @function
     * @param {String} hex hexadecimal string to final update
     * @description
     * @example
     * md.digestHex('0f2abd')
     */
    this.digestHex = function(hex) {
	throw "digestHex(hex) not supported for this alg/prov: " + this.algName + "/" + this.provName;
    };

    if (params !== undefined) {
	if (params['alg'] !== undefined) {
	    this.algName = params['alg'];
	    if (params['prov'] === undefined)
		this.provName = KJUR.crypto.Util.DEFAULTPROVIDER[this.algName];
	    this.setAlgAndProvider(this.algName, this.provName);
	}
    }
};

/**
 * Mac(Message Authentication Code) class which is very similar to java.security.Mac class 
 * @name KJUR.crypto.Mac
 * @class Mac class which is very similar to java.security.Mac class
 * @param {Array} params parameters for constructor
 * @description
 * <br/>
 * Currently this supports following algorithm and providers combination:
 * <ul>
 * <li>hmacmd5 - cryptojs</li>
 * <li>hmacsha1 - cryptojs</li>
 * <li>hmacsha224 - cryptojs</li>
 * <li>hmacsha256 - cryptojs</li>
 * <li>hmacsha384 - cryptojs</li>
 * <li>hmacsha512 - cryptojs</li>
 * </ul>
 * NOTE: HmacSHA224 and HmacSHA384 issue was fixed since jsrsasign 4.1.4.
 * Please use 'ext/cryptojs-312-core-fix*.js' instead of 'core.js' of original CryptoJS
 * to avoid those issue.
 * <br/>
 * NOTE2: Hmac signature bug was fixed in jsrsasign 4.9.0 by providing CryptoJS
 * bug workaround.
 * <br/>
 * Please see {@link KJUR.crypto.Mac.setPassword}, how to provide password
 * in various ways in detail.
 * @example
 * var mac = new KJUR.crypto.Mac({alg: "HmacSHA1", "pass": "pass"});
 * mac.updateString('aaa')
 * var macHex = md.doFinal()
 *
 * // other password representation 
 * var mac = new KJUR.crypto.Mac({alg: "HmacSHA256", "pass": {"hex":  "6161"}});
 * var mac = new KJUR.crypto.Mac({alg: "HmacSHA256", "pass": {"utf8": "aa"}});
 * var mac = new KJUR.crypto.Mac({alg: "HmacSHA256", "pass": {"rstr": "\x61\x61"}});
 * var mac = new KJUR.crypto.Mac({alg: "HmacSHA256", "pass": {"b64":  "Mi02/+...a=="}});
 * var mac = new KJUR.crypto.Mac({alg: "HmacSHA256", "pass": {"b64u": "Mi02_-...a"}});
 */
KJUR.crypto.Mac = function(params) {
    var mac = null;
    var pass = null;
    var algName = null;
    var provName = null;
    var algProv = null;

    this.setAlgAndProvider = function(alg, prov) {
	alg = alg.toLowerCase();

	if (alg == null) alg = "hmacsha1";

	alg = alg.toLowerCase();
        if (alg.substr(0, 4) != "hmac") {
	    throw "setAlgAndProvider unsupported HMAC alg: " + alg;
	}

	if (prov === undefined) prov = KJUR.crypto.Util.DEFAULTPROVIDER[alg];
	this.algProv = alg + "/" + prov;

	var hashAlg = alg.substr(4);

	// for cryptojs
	if (':md5:sha1:sha224:sha256:sha384:sha512:ripemd160:'.indexOf(hashAlg) != -1 &&
	    prov == 'cryptojs') {
	    try {
		var mdObj = KJUR.crypto.Util.CRYPTOJSMESSAGEDIGESTNAME[hashAlg];
		this.mac = CryptoJS.algo.HMAC.create(mdObj, this.pass);
	    } catch (ex) {
		throw "setAlgAndProvider hash alg set fail hashAlg=" + hashAlg + "/" + ex;
	    }
	    this.updateString = function(str) {
		this.mac.update(str);
	    };
	    this.updateHex = function(hex) {
		var wHex = CryptoJS.enc.Hex.parse(hex);
		this.mac.update(wHex);
	    };
	    this.doFinal = function() {
		var hash = this.mac.finalize();
		return hash.toString(CryptoJS.enc.Hex);
	    };
	    this.doFinalString = function(str) {
		this.updateString(str);
		return this.doFinal();
	    };
	    this.doFinalHex = function(hex) {
		this.updateHex(hex);
		return this.doFinal();
	    };
	}
    };

    /**
     * update digest by specified string
     * @name updateString
     * @memberOf KJUR.crypto.Mac
     * @function
     * @param {String} str string to update
     * @description
     * @example
     * md.updateString('New York');
     */
    this.updateString = function(str) {
	throw "updateString(str) not supported for this alg/prov: " + this.algProv;
    };

    /**
     * update digest by specified hexadecimal string
     * @name updateHex
     * @memberOf KJUR.crypto.Mac
     * @function
     * @param {String} hex hexadecimal string to update
     * @description
     * @example
     * md.updateHex('0afe36');
     */
    this.updateHex = function(hex) {
	throw "updateHex(hex) not supported for this alg/prov: " + this.algProv;
    };

    /**
     * completes hash calculation and returns hash result
     * @name doFinal
     * @memberOf KJUR.crypto.Mac
     * @function
     * @description
     * @example
     * md.digest()
     */
    this.doFinal = function() {
	throw "digest() not supported for this alg/prov: " + this.algProv;
    };

    /**
     * performs final update on the digest using string, then completes the digest computation
     * @name doFinalString
     * @memberOf KJUR.crypto.Mac
     * @function
     * @param {String} str string to final update
     * @description
     * @example
     * md.digestString('aaa')
     */
    this.doFinalString = function(str) {
	throw "digestString(str) not supported for this alg/prov: " + this.algProv;
    };

    /**
     * performs final update on the digest using hexadecimal string, 
     * then completes the digest computation
     * @name doFinalHex
     * @memberOf KJUR.crypto.Mac
     * @function
     * @param {String} hex hexadecimal string to final update
     * @description
     * @example
     * md.digestHex('0f2abd')
     */
    this.doFinalHex = function(hex) {
	throw "digestHex(hex) not supported for this alg/prov: " + this.algProv;
    };

    /**
     * set password for Mac
     * @name setPassword
     * @memberOf KJUR.crypto.Mac
     * @function
     * @param {Object} pass password for Mac
     * @since crypto 1.1.7 jsrsasign 4.9.0
     * @description
     * This method will set password for (H)Mac internally.
     * Argument 'pass' can be specified as following:
     * <ul>
     * <li>even length string of 0..9, a..f or A-F: implicitly specified as hexadecimal string</li>
     * <li>not above string: implicitly specified as raw string</li>
     * <li>{rstr: "\x65\x70"}: explicitly specified as raw string</li>
     * <li>{hex: "6570"}: explicitly specified as hexacedimal string</li>
     * <li>{utf8: "秘密"}: explicitly specified as UTF8 string</li>
     * <li>{b64: "Mi78..=="}: explicitly specified as Base64 string</li>
     * <li>{b64u: "Mi7-_"}: explicitly specified as Base64URL string</li>
     * </ul>
     * It is *STRONGLY RECOMMENDED* that explicit representation of password argument
     * to avoid ambiguity. For example string  "6161" can mean a string "6161" or 
     * a hexadecimal string of "aa" (i.e. \x61\x61).
     * @example
     * mac = KJUR.crypto.Mac({'alg': 'hmacsha256'});
     * // set password by implicit raw string
     * mac.setPassword("\x65\x70\xb9\x0b");
     * mac.setPassword("password");
     * // set password by implicit hexadecimal string
     * mac.setPassword("6570b90b");
     * mac.setPassword("6570B90B");
     * // set password by explicit raw string
     * mac.setPassword({"rstr": "\x65\x70\xb9\x0b"});
     * // set password by explicit hexadecimal string
     * mac.setPassword({"hex": "6570b90b"});
     * // set password by explicit utf8 string
     * mac.setPassword({"utf8": "passwordパスワード");
     * // set password by explicit Base64 string
     * mac.setPassword({"b64": "Mb+c3f/=="});
     * // set password by explicit Base64URL string
     * mac.setPassword({"b64u": "Mb-c3f_"});
     */
    this.setPassword = function(pass) {
	// internal this.pass shall be CryptoJS DWord Object for CryptoJS bug
	// work around. CrytoJS HMac password can be passed by
	// raw string as described in the manual however it doesn't
	// work properly in some case. If password was passed
	// by CryptoJS DWord which is not described in the manual
	// it seems to work. (fixed since crypto 1.1.7)

	if (typeof pass == 'string') {
	    var hPass = pass;
	    if (pass.length % 2 == 1 || ! pass.match(/^[0-9A-Fa-f]+$/)) { // raw str
		hPass = rstrtohex(pass);
	    }
	    this.pass = CryptoJS.enc.Hex.parse(hPass);
	    return;
	}

	if (typeof pass != 'object')
	    throw "KJUR.crypto.Mac unsupported password type: " + pass;
	
	var hPass = null;
	if (pass.hex  !== undefined) {
	    if (pass.hex.length % 2 != 0 || ! pass.hex.match(/^[0-9A-Fa-f]+$/))
		throw "Mac: wrong hex password: " + pass.hex;
	    hPass = pass.hex;
	}
	if (pass.utf8 !== undefined) hPass = utf8tohex(pass.utf8);
	if (pass.rstr !== undefined) hPass = rstrtohex(pass.rstr);
	if (pass.b64  !== undefined) hPass = b64tohex(pass.b64);
	if (pass.b64u !== undefined) hPass = b64utohex(pass.b64u);

	if (hPass == null)
	    throw "KJUR.crypto.Mac unsupported password type: " + pass;

	this.pass = CryptoJS.enc.Hex.parse(hPass);
    };

    if (params !== undefined) {
	if (params.pass !== undefined) {
	    this.setPassword(params.pass);
	}
	if (params.alg !== undefined) {
	    this.algName = params.alg;
	    if (params['prov'] === undefined)
		this.provName = KJUR.crypto.Util.DEFAULTPROVIDER[this.algName];
	    this.setAlgAndProvider(this.algName, this.provName);
	}
    }
};

/**
 * Signature class which is very similar to java.security.Signature class
 * @name KJUR.crypto.Signature
 * @class Signature class which is very similar to java.security.Signature class
 * @param {Array} params parameters for constructor
 * @property {String} state Current state of this signature object whether 'SIGN', 'VERIFY' or null
 * @description
 * <br/>
 * As for params of constructor's argument, it can be specify following attributes:
 * <ul>
 * <li>alg - signature algorithm name (ex. {MD5,SHA1,SHA224,SHA256,SHA384,SHA512,RIPEMD160}with{RSA,ECDSA,DSA})</li>
 * <li>provider - currently 'cryptojs/jsrsa' only</li>
 * </ul>
 * <h4>SUPPORTED ALGORITHMS AND PROVIDERS</h4>
 * This Signature class supports following signature algorithm and provider names:
 * <ul>
 * <li>MD5withRSA - cryptojs/jsrsa</li>
 * <li>SHA1withRSA - cryptojs/jsrsa</li>
 * <li>SHA224withRSA - cryptojs/jsrsa</li>
 * <li>SHA256withRSA - cryptojs/jsrsa</li>
 * <li>SHA384withRSA - cryptojs/jsrsa</li>
 * <li>SHA512withRSA - cryptojs/jsrsa</li>
 * <li>RIPEMD160withRSA - cryptojs/jsrsa</li>
 * <li>MD5withECDSA - cryptojs/jsrsa</li>
 * <li>SHA1withECDSA - cryptojs/jsrsa</li>
 * <li>SHA224withECDSA - cryptojs/jsrsa</li>
 * <li>SHA256withECDSA - cryptojs/jsrsa</li>
 * <li>SHA384withECDSA - cryptojs/jsrsa</li>
 * <li>SHA512withECDSA - cryptojs/jsrsa</li>
 * <li>RIPEMD160withECDSA - cryptojs/jsrsa</li>
 * <li>MD5withRSAandMGF1 - cryptojs/jsrsa</li>
 * <li>SHA1withRSAandMGF1 - cryptojs/jsrsa</li>
 * <li>SHA224withRSAandMGF1 - cryptojs/jsrsa</li>
 * <li>SHA256withRSAandMGF1 - cryptojs/jsrsa</li>
 * <li>SHA384withRSAandMGF1 - cryptojs/jsrsa</li>
 * <li>SHA512withRSAandMGF1 - cryptojs/jsrsa</li>
 * <li>RIPEMD160withRSAandMGF1 - cryptojs/jsrsa</li>
 * <li>SHA1withDSA - cryptojs/jsrsa</li>
 * <li>SHA224withDSA - cryptojs/jsrsa</li>
 * <li>SHA256withDSA - cryptojs/jsrsa</li>
 * </ul>
 * Here are supported elliptic cryptographic curve names and their aliases for ECDSA:
 * <ul>
 * <li>secp256k1</li>
 * <li>secp256r1, NIST P-256, P-256, prime256v1</li>
 * <li>secp384r1, NIST P-384, P-384</li>
 * </ul>
 * NOTE1: DSA signing algorithm is also supported since crypto 1.1.5.
 * <h4>EXAMPLES</h4>
 * @example
 * // RSA signature generation
 * var sig = new KJUR.crypto.Signature({"alg": "SHA1withRSA"});
 * sig.init(prvKeyPEM);
 * sig.updateString('aaa');
 * var hSigVal = sig.sign();
 *
 * // DSA signature validation
 * var sig2 = new KJUR.crypto.Signature({"alg": "SHA1withDSA"});
 * sig2.init(certPEM);
 * sig.updateString('aaa');
 * var isValid = sig2.verify(hSigVal);
 * 
 * // ECDSA signing
 * var sig = new KJUR.crypto.Signature({'alg':'SHA1withECDSA'});
 * sig.init(prvKeyPEM);
 * sig.updateString('aaa');
 * var sigValueHex = sig.sign();
 *
 * // ECDSA verifying
 * var sig2 = new KJUR.crypto.Signature({'alg':'SHA1withECDSA'});
 * sig.init(certPEM);
 * sig.updateString('aaa');
 * var isValid = sig.verify(sigValueHex);
 */
KJUR.crypto.Signature = function(params) {
    var prvKey = null; // RSAKey/KJUR.crypto.{ECDSA,DSA} object for signing
    var pubKey = null; // RSAKey/KJUR.crypto.{ECDSA,DSA} object for verifying

    var md = null; // KJUR.crypto.MessageDigest object
    var sig = null;
    var algName = null;
    var provName = null;
    var algProvName = null;
    var mdAlgName = null;
    var pubkeyAlgName = null;	// rsa,ecdsa,rsaandmgf1(=rsapss)
    var state = null;
    var pssSaltLen = -1;
    var initParams = null;

    var sHashHex = null; // hex hash value for hex
    var hDigestInfo = null;
    var hPaddedDigestInfo = null;
    var hSign = null;

    this._setAlgNames = function() {
	if (this.algName.match(/^(.+)with(.+)$/)) {
	    this.mdAlgName = RegExp.$1.toLowerCase();
	    this.pubkeyAlgName = RegExp.$2.toLowerCase();
	}
    };

    this._zeroPaddingOfSignature = function(hex, bitLength) {
	var s = "";
	var nZero = bitLength / 4 - hex.length;
	for (var i = 0; i < nZero; i++) {
	    s = s + "0";
	}
	return s + hex;
    };

    /**
     * set signature algorithm and provider
     * @name setAlgAndProvider
     * @memberOf KJUR.crypto.Signature
     * @function
     * @param {String} alg signature algorithm name
     * @param {String} prov provider name
     * @description
     * @example
     * md.setAlgAndProvider('SHA1withRSA', 'cryptojs/jsrsa');
     */
    this.setAlgAndProvider = function(alg, prov) {
	this._setAlgNames();
	if (prov != 'cryptojs/jsrsa')
	    throw "provider not supported: " + prov;

	if (':md5:sha1:sha224:sha256:sha384:sha512:ripemd160:'.indexOf(this.mdAlgName) != -1) {
	    try {
		this.md = new KJUR.crypto.MessageDigest({'alg':this.mdAlgName});
	    } catch (ex) {
		throw "setAlgAndProvider hash alg set fail alg=" +
                      this.mdAlgName + "/" + ex;
	    }

	    this.init = function(keyparam, pass) {
		var keyObj = null;
		try {
		    if (pass === undefined) {
			keyObj = KEYUTIL.getKey(keyparam);
		    } else {
			keyObj = KEYUTIL.getKey(keyparam, pass);
		    }
		} catch (ex) {
		    throw "init failed:" + ex;
		}

		if (keyObj.isPrivate === true) {
		    this.prvKey = keyObj;
		    this.state = "SIGN";
		} else if (keyObj.isPublic === true) {
		    this.pubKey = keyObj;
		    this.state = "VERIFY";
		} else {
		    throw "init failed.:" + keyObj;
		}
	    };

	    this.initSign = function(params) {
		if (typeof params['ecprvhex'] == 'string' &&
                    typeof params['eccurvename'] == 'string') {
		    this.ecprvhex = params['ecprvhex'];
		    this.eccurvename = params['eccurvename'];
		} else {
		    this.prvKey = params;
		}
		this.state = "SIGN";
	    };

	    this.initVerifyByPublicKey = function(params) {
		if (typeof params['ecpubhex'] == 'string' &&
		    typeof params['eccurvename'] == 'string') {
		    this.ecpubhex = params['ecpubhex'];
		    this.eccurvename = params['eccurvename'];
		} else if (params instanceof KJUR.crypto.ECDSA) {
		    this.pubKey = params;
		} else if (params instanceof RSAKey) {
		    this.pubKey = params;
		}
		this.state = "VERIFY";
	    };

	    this.initVerifyByCertificatePEM = function(certPEM) {
		var x509 = new X509();
		x509.readCertPEM(certPEM);
		this.pubKey = x509.subjectPublicKeyRSA;
		this.state = "VERIFY";
	    };

	    this.updateString = function(str) {
		this.md.updateString(str);
	    };

	    this.updateHex = function(hex) {
		this.md.updateHex(hex);
	    };

	    this.sign = function() {
		this.sHashHex = this.md.digest();
		if (typeof this.ecprvhex != "undefined" &&
		    typeof this.eccurvename != "undefined") {
		    var ec = new KJUR.crypto.ECDSA({'curve': this.eccurvename});
		    this.hSign = ec.signHex(this.sHashHex, this.ecprvhex);
		} else if (this.prvKey instanceof RSAKey &&
		           this.pubkeyAlgName == "rsaandmgf1") {
		    this.hSign = this.prvKey.signWithMessageHashPSS(this.sHashHex,
								    this.mdAlgName,
								    this.pssSaltLen);
		} else if (this.prvKey instanceof RSAKey &&
			   this.pubkeyAlgName == "rsa") {
		    this.hSign = this.prvKey.signWithMessageHash(this.sHashHex,
								 this.mdAlgName);
		} else if (this.prvKey instanceof KJUR.crypto.ECDSA) {
		    this.hSign = this.prvKey.signWithMessageHash(this.sHashHex);
		} else if (this.prvKey instanceof KJUR.crypto.DSA) {
		    this.hSign = this.prvKey.signWithMessageHash(this.sHashHex);
		} else {
		    throw "Signature: unsupported public key alg: " + this.pubkeyAlgName;
		}
		return this.hSign;
	    };
	    this.signString = function(str) {
		this.updateString(str);
		return this.sign();
	    };
	    this.signHex = function(hex) {
		this.updateHex(hex);
		return this.sign();
	    };
	    this.verify = function(hSigVal) {
	        this.sHashHex = this.md.digest();
		if (typeof this.ecpubhex != "undefined" &&
		    typeof this.eccurvename != "undefined") {
		    var ec = new KJUR.crypto.ECDSA({curve: this.eccurvename});
		    return ec.verifyHex(this.sHashHex, hSigVal, this.ecpubhex);
		} else if (this.pubKey instanceof RSAKey &&
			   this.pubkeyAlgName == "rsaandmgf1") {
		    return this.pubKey.verifyWithMessageHashPSS(this.sHashHex, hSigVal, 
								this.mdAlgName,
								this.pssSaltLen);
		} else if (this.pubKey instanceof RSAKey &&
			   this.pubkeyAlgName == "rsa") {
		    return this.pubKey.verifyWithMessageHash(this.sHashHex, hSigVal);
		} else if (this.pubKey instanceof KJUR.crypto.ECDSA) {
		    return this.pubKey.verifyWithMessageHash(this.sHashHex, hSigVal);
		} else if (this.pubKey instanceof KJUR.crypto.DSA) {
		    return this.pubKey.verifyWithMessageHash(this.sHashHex, hSigVal);
		} else {
		    throw "Signature: unsupported public key alg: " + this.pubkeyAlgName;
		}
	    };
	}
    };

    /**
     * Initialize this object for signing or verifying depends on key
     * @name init
     * @memberOf KJUR.crypto.Signature
     * @function
     * @param {Object} key specifying public or private key as plain/encrypted PKCS#5/8 PEM file, certificate PEM or {@link RSAKey}, {@link KJUR.crypto.DSA} or {@link KJUR.crypto.ECDSA} object
     * @param {String} pass (OPTION) passcode for encrypted private key
     * @since crypto 1.1.3
     * @description
     * This method is very useful initialize method for Signature class since
     * you just specify key then this method will automatically initialize it
     * using {@link KEYUTIL.getKey} method.
     * As for 'key',  following argument type are supported:
     * <h5>signing</h5>
     * <ul>
     * <li>PEM formatted PKCS#8 encrypted RSA/ECDSA private key concluding "BEGIN ENCRYPTED PRIVATE KEY"</li>
     * <li>PEM formatted PKCS#5 encrypted RSA/DSA private key concluding "BEGIN RSA/DSA PRIVATE KEY" and ",ENCRYPTED"</li>
     * <li>PEM formatted PKCS#8 plain RSA/ECDSA private key concluding "BEGIN PRIVATE KEY"</li>
     * <li>PEM formatted PKCS#5 plain RSA/DSA private key concluding "BEGIN RSA/DSA PRIVATE KEY" without ",ENCRYPTED"</li>
     * <li>RSAKey object of private key</li>
     * <li>KJUR.crypto.ECDSA object of private key</li>
     * <li>KJUR.crypto.DSA object of private key</li>
     * </ul>
     * <h5>verification</h5>
     * <ul>
     * <li>PEM formatted PKCS#8 RSA/EC/DSA public key concluding "BEGIN PUBLIC KEY"</li>
     * <li>PEM formatted X.509 certificate with RSA/EC/DSA public key concluding
     *     "BEGIN CERTIFICATE", "BEGIN X509 CERTIFICATE" or "BEGIN TRUSTED CERTIFICATE".</li>
     * <li>RSAKey object of public key</li>
     * <li>KJUR.crypto.ECDSA object of public key</li>
     * <li>KJUR.crypto.DSA object of public key</li>
     * </ul>
     * @example
     * sig.init(sCertPEM)
     */
    this.init = function(key, pass) {
	throw "init(key, pass) not supported for this alg:prov=" +
	      this.algProvName;
    };

    /**
     * Initialize this object for verifying with a public key
     * @name initVerifyByPublicKey
     * @memberOf KJUR.crypto.Signature
     * @function
     * @param {Object} param RSAKey object of public key or associative array for ECDSA
     * @since 1.0.2
     * @deprecated from crypto 1.1.5. please use init() method instead.
     * @description
     * Public key information will be provided as 'param' parameter and the value will be
     * following:
     * <ul>
     * <li>{@link RSAKey} object for RSA verification</li>
     * <li>associative array for ECDSA verification
     *     (ex. <code>{'ecpubhex': '041f..', 'eccurvename': 'secp256r1'}</code>)
     * </li>
     * </ul>
     * @example
     * sig.initVerifyByPublicKey(rsaPrvKey)
     */
    this.initVerifyByPublicKey = function(rsaPubKey) {
	throw "initVerifyByPublicKey(rsaPubKeyy) not supported for this alg:prov=" +
	      this.algProvName;
    };

    /**
     * Initialize this object for verifying with a certficate
     * @name initVerifyByCertificatePEM
     * @memberOf KJUR.crypto.Signature
     * @function
     * @param {String} certPEM PEM formatted string of certificate
     * @since 1.0.2
     * @deprecated from crypto 1.1.5. please use init() method instead.
     * @description
     * @example
     * sig.initVerifyByCertificatePEM(certPEM)
     */
    this.initVerifyByCertificatePEM = function(certPEM) {
	throw "initVerifyByCertificatePEM(certPEM) not supported for this alg:prov=" +
	    this.algProvName;
    };

    /**
     * Initialize this object for signing
     * @name initSign
     * @memberOf KJUR.crypto.Signature
     * @function
     * @param {Object} param RSAKey object of public key or associative array for ECDSA
     * @deprecated from crypto 1.1.5. please use init() method instead.
     * @description
     * Private key information will be provided as 'param' parameter and the value will be
     * following:
     * <ul>
     * <li>{@link RSAKey} object for RSA signing</li>
     * <li>associative array for ECDSA signing
     *     (ex. <code>{'ecprvhex': '1d3f..', 'eccurvename': 'secp256r1'}</code>)</li>
     * </ul>
     * @example
     * sig.initSign(prvKey)
     */
    this.initSign = function(prvKey) {
	throw "initSign(prvKey) not supported for this alg:prov=" + this.algProvName;
    };

    /**
     * Updates the data to be signed or verified by a string
     * @name updateString
     * @memberOf KJUR.crypto.Signature
     * @function
     * @param {String} str string to use for the update
     * @description
     * @example
     * sig.updateString('aaa')
     */
    this.updateString = function(str) {
	throw "updateString(str) not supported for this alg:prov=" + this.algProvName;
    };

    /**
     * Updates the data to be signed or verified by a hexadecimal string
     * @name updateHex
     * @memberOf KJUR.crypto.Signature
     * @function
     * @param {String} hex hexadecimal string to use for the update
     * @description
     * @example
     * sig.updateHex('1f2f3f')
     */
    this.updateHex = function(hex) {
	throw "updateHex(hex) not supported for this alg:prov=" + this.algProvName;
    };

    /**
     * Returns the signature bytes of all data updates as a hexadecimal string
     * @name sign
     * @memberOf KJUR.crypto.Signature
     * @function
     * @return the signature bytes as a hexadecimal string
     * @description
     * @example
     * var hSigValue = sig.sign()
     */
    this.sign = function() {
	throw "sign() not supported for this alg:prov=" + this.algProvName;
    };

    /**
     * performs final update on the sign using string, then returns the signature bytes of all data updates as a hexadecimal string
     * @name signString
     * @memberOf KJUR.crypto.Signature
     * @function
     * @param {String} str string to final update
     * @return the signature bytes of a hexadecimal string
     * @description
     * @example
     * var hSigValue = sig.signString('aaa')
     */
    this.signString = function(str) {
	throw "digestString(str) not supported for this alg:prov=" + this.algProvName;
    };

    /**
     * performs final update on the sign using hexadecimal string, then returns the signature bytes of all data updates as a hexadecimal string
     * @name signHex
     * @memberOf KJUR.crypto.Signature
     * @function
     * @param {String} hex hexadecimal string to final update
     * @return the signature bytes of a hexadecimal string
     * @description
     * @example
     * var hSigValue = sig.signHex('1fdc33')
     */
    this.signHex = function(hex) {
	throw "digestHex(hex) not supported for this alg:prov=" + this.algProvName;
    };

    /**
     * verifies the passed-in signature.
     * @name verify
     * @memberOf KJUR.crypto.Signature
     * @function
     * @param {String} str string to final update
     * @return {Boolean} true if the signature was verified, otherwise false
     * @description
     * @example
     * var isValid = sig.verify('1fbcefdca4823a7(snip)')
     */
    this.verify = function(hSigVal) {
	throw "verify(hSigVal) not supported for this alg:prov=" + this.algProvName;
    };

    this.initParams = params;

    if (params !== undefined) {
	if (params['alg'] !== undefined) {
	    this.algName = params['alg'];
	    if (params['prov'] === undefined) {
		this.provName = KJUR.crypto.Util.DEFAULTPROVIDER[this.algName];
	    } else {
		this.provName = params['prov'];
	    }
	    this.algProvName = this.algName + ":" + this.provName;
	    this.setAlgAndProvider(this.algName, this.provName);
	    this._setAlgNames();
	}

	if (params['psssaltlen'] !== undefined) this.pssSaltLen = params['psssaltlen'];

	if (params['prvkeypem'] !== undefined) {
	    if (params['prvkeypas'] !== undefined) {
		throw "both prvkeypem and prvkeypas parameters not supported";
	    } else {
		try {
		    var prvKey = new RSAKey();
		    prvKey.readPrivateKeyFromPEMString(params['prvkeypem']);
		    this.initSign(prvKey);
		} catch (ex) {
		    throw "fatal error to load pem private key: " + ex;
		}
	    }
	}
    }
};

/**
 * static object for cryptographic function utilities
 * @name KJUR.crypto.OID
 * @class static object for cryptography related OIDs
 * @property {Array} oidhex2name key value of hexadecimal OID and its name
 *           (ex. '2a8648ce3d030107' and 'secp256r1')
 * @since crypto 1.1.3
 * @description
 */


KJUR.crypto.OID = new function() {
    this.oidhex2name = {
	'2a864886f70d010101': 'rsaEncryption',
	'2a8648ce3d0201': 'ecPublicKey',
	'2a8648ce380401': 'dsa',
	'2a8648ce3d030107': 'secp256r1',
	'2b8104001f': 'secp192k1',
	'2b81040021': 'secp224r1',
	'2b8104000a': 'secp256k1',
	'2b81040023': 'secp521r1',
	'2b81040022': 'secp384r1',
	'2a8648ce380403': 'SHA1withDSA', // 1.2.840.10040.4.3
	'608648016503040301': 'SHA224withDSA', // 2.16.840.1.101.3.4.3.1
	'608648016503040302': 'SHA256withDSA', // 2.16.840.1.101.3.4.3.2
    };
};

/*! base64x-1.1.7 (c) 2012-2016 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
/*
 * base64x.js - Base64url and supplementary functions for Tom Wu's base64.js library
 *
 * version: 1.1.7 (2016-Aug-03)
 *
 * Copyright (c) 2012-2016 Kenji Urushima (kenji.urushima@gmail.com)
 *
 * This software is licensed under the terms of the MIT License.
 * http://kjur.github.com/jsjws/license/
 *
 * The above copyright and license notice shall be 
 * included in all copies or substantial portions of the Software.
 *
 * DEPENDS ON:
 *   - base64.js - Tom Wu's Base64 library
 */

/**
 * @fileOverview
 * @name base64x-1.1.js
 * @author Kenji Urushima kenji.urushima@gmail.com
 * @version asn1 1.1.7 (2016-Aug-03)
 * @since jsrsasign 2.1
 * @license <a href="http://kjur.github.io/jsrsasign/license/">MIT License</a>
 */

var KJUR;
if (typeof KJUR == "undefined" || !KJUR) KJUR = {};
if (typeof KJUR.lang == "undefined" || !KJUR.lang) KJUR.lang = {};

/**
 * String and its utility class <br/>
 * This class provides some static utility methods for string.
 * @class String and its utility class
 * @author Kenji Urushima
 * @version 1.0 (2016-Aug-05)
 * @since base64x 1.1.7 jsrsasign 5.0.13
 */
KJUR.lang.String = function() {};

/**
 * Base64URL and supplementary functions for Tom Wu's base64.js library.<br/>
 * This class is just provide information about global functions
 * defined in 'base64x.js'. The 'base64x.js' script file provides
 * global functions for converting following data each other.
 * <ul>
 * <li>(ASCII) String</li>
 * <li>UTF8 String including CJK, Latin and other characters</li>
 * <li>byte array</li>
 * <li>hexadecimal encoded String</li>
 * <li>Full URIComponent encoded String (such like "%69%94")</li>
 * <li>Base64 encoded String</li>
 * <li>Base64URL encoded String</li>
 * </ul>
 * All functions in 'base64x.js' are defined in {@link _global_} and not
 * in this class.
 * 
 * @class Base64URL and supplementary functions for Tom Wu's base64.js library
 * @author Kenji Urushima
 * @version 1.1 (07 May 2012)
 * @requires base64.js
 * @see <a href="http://kjur.github.com/jsjws/">'jwjws'(JWS JavaScript Library) home page http://kjur.github.com/jsjws/</a>
 * @see <a href="http://kjur.github.com/jsrsasigns/">'jwrsasign'(RSA Sign JavaScript Library) home page http://kjur.github.com/jsrsasign/</a>
 */
function Base64x() {
}

// ==== string / byte array ================================
/**
 * convert a string to an array of character codes
 * @param {String} s
 * @return {Array of Numbers} 
 */
function stoBA(s) {
    var a = new Array();
    for (var i = 0; i < s.length; i++) {
	a[i] = s.charCodeAt(i);
    }
    return a;
}

/**
 * convert an array of character codes to a string
 * @param {Array of Numbers} a array of character codes
 * @return {String} s
 */
function BAtos(a) {
    var s = "";
    for (var i = 0; i < a.length; i++) {
	s = s + String.fromCharCode(a[i]);
    }
    return s;
}

// ==== byte array / hex ================================
/**
 * convert an array of bytes(Number) to hexadecimal string.<br/>
 * @param {Array of Numbers} a array of bytes
 * @return {String} hexadecimal string
 */
function BAtohex(a) {
    var s = "";
    for (var i = 0; i < a.length; i++) {
	var hex1 = a[i].toString(16);
	if (hex1.length == 1) hex1 = "0" + hex1;
	s = s + hex1;
    }
    return s;
}

// ==== string / hex ================================
/**
 * convert a ASCII string to a hexadecimal string of ASCII codes.<br/>
 * NOTE: This can't be used for non ASCII characters.
 * @param {s} s ASCII string
 * @return {String} hexadecimal string
 */
function stohex(s) {
    return BAtohex(stoBA(s));
}

// ==== string / base64 ================================
/**
 * convert a ASCII string to a Base64 encoded string.<br/>
 * NOTE: This can't be used for non ASCII characters.
 * @param {s} s ASCII string
 * @return {String} Base64 encoded string
 */
function stob64(s) {
    return hex2b64(stohex(s));
}

// ==== string / base64url ================================
/**
 * convert a ASCII string to a Base64URL encoded string.<br/>
 * NOTE: This can't be used for non ASCII characters.
 * @param {s} s ASCII string
 * @return {String} Base64URL encoded string
 */
function stob64u(s) {
    return b64tob64u(hex2b64(stohex(s)));
}

/**
 * convert a Base64URL encoded string to a ASCII string.<br/>
 * NOTE: This can't be used for Base64URL encoded non ASCII characters.
 * @param {s} s Base64URL encoded string
 * @return {String} ASCII string
 */
function b64utos(s) {
    return BAtos(b64toBA(b64utob64(s)));
}

// ==== base64 / base64url ================================
/**
 * convert a Base64 encoded string to a Base64URL encoded string.<br/>
 * Example: "ab+c3f/==" &rarr; "ab-c3f_"
 * @param {String} s Base64 encoded string
 * @return {String} Base64URL encoded string
 */
function b64tob64u(s) {
    s = s.replace(/\=/g, "");
    s = s.replace(/\+/g, "-");
    s = s.replace(/\//g, "_");
    return s;
}

/**
 * convert a Base64URL encoded string to a Base64 encoded string.<br/>
 * Example: "ab-c3f_" &rarr; "ab+c3f/=="
 * @param {String} s Base64URL encoded string
 * @return {String} Base64 encoded string
 */
function b64utob64(s) {
    if (s.length % 4 == 2) s = s + "==";
    else if (s.length % 4 == 3) s = s + "=";
    s = s.replace(/-/g, "+");
    s = s.replace(/_/g, "/");
    return s;
}

// ==== hex / base64url ================================
/**
 * convert a hexadecimal string to a Base64URL encoded string.<br/>
 * @param {String} s hexadecimal string
 * @return {String} Base64URL encoded string
 * @description
 * convert a hexadecimal string to a Base64URL encoded string.
 * NOTE: If leading "0" is omitted and odd number length for
 * hexadecimal leading "0" is automatically added.
 */
function hextob64u(s) {
    if (s.length % 2 == 1) s = "0" + s;
    return b64tob64u(hex2b64(s));
}

/**
 * convert a Base64URL encoded string to a hexadecimal string.<br/>
 * @param {String} s Base64URL encoded string
 * @return {String} hexadecimal string
 */
function b64utohex(s) {
    return b64tohex(b64utob64(s));
}

var utf8tob64u, b64utoutf8;

if (typeof Buffer === 'function')
{
  utf8tob64u = function (s)
  {
    return b64tob64u(new Buffer(s, 'utf8').toString('base64'));
  };

  b64utoutf8 = function (s)
  {
    return new Buffer(b64utob64(s), 'base64').toString('utf8');
  };
}
else
{
// ==== utf8 / base64url ================================
/**
 * convert a UTF-8 encoded string including CJK or Latin to a Base64URL encoded string.<br/>
 * @param {String} s UTF-8 encoded string
 * @return {String} Base64URL encoded string
 * @since 1.1
 */
  utf8tob64u = function (s)
  {
    return hextob64u(uricmptohex(encodeURIComponentAll(s)));
  };

/**
 * convert a Base64URL encoded string to a UTF-8 encoded string including CJK or Latin.<br/>
 * @param {String} s Base64URL encoded string
 * @return {String} UTF-8 encoded string
 * @since 1.1
 */
  b64utoutf8 = function (s)
  {
    return decodeURIComponent(hextouricmp(b64utohex(s)));
  };
}

// ==== utf8 / base64url ================================
/**
 * convert a UTF-8 encoded string including CJK or Latin to a Base64 encoded string.<br/>
 * @param {String} s UTF-8 encoded string
 * @return {String} Base64 encoded string
 * @since 1.1.1
 */
function utf8tob64(s) {
  return hex2b64(uricmptohex(encodeURIComponentAll(s)));
}

/**
 * convert a Base64 encoded string to a UTF-8 encoded string including CJK or Latin.<br/>
 * @param {String} s Base64 encoded string
 * @return {String} UTF-8 encoded string
 * @since 1.1.1
 */
function b64toutf8(s) {
  return decodeURIComponent(hextouricmp(b64tohex(s)));
}

// ==== utf8 / hex ================================
/**
 * convert a UTF-8 encoded string including CJK or Latin to a hexadecimal encoded string.<br/>
 * @param {String} s UTF-8 encoded string
 * @return {String} hexadecimal encoded string
 * @since 1.1.1
 */
function utf8tohex(s) {
  return uricmptohex(encodeURIComponentAll(s));
}

/**
 * convert a hexadecimal encoded string to a UTF-8 encoded string including CJK or Latin.<br/>
 * Note that when input is improper hexadecimal string as UTF-8 string, this function returns
 * 'null'.
 * @param {String} s hexadecimal encoded string
 * @return {String} UTF-8 encoded string or null
 * @since 1.1.1
 */
function hextoutf8(s) {
  return decodeURIComponent(hextouricmp(s));
}

/**
 * convert a hexadecimal encoded string to raw string including non printable characters.<br/>
 * @param {String} s hexadecimal encoded string
 * @return {String} raw string
 * @since 1.1.2
 * @example
 * hextorstr("610061") &rarr; "a\x00a"
 */
function hextorstr(sHex) {
    var s = "";
    for (var i = 0; i < sHex.length - 1; i += 2) {
        s += String.fromCharCode(parseInt(sHex.substr(i, 2), 16));
    }
    return s;
}

/**
 * convert a raw string including non printable characters to hexadecimal encoded string.<br/>
 * @param {String} s raw string
 * @return {String} hexadecimal encoded string
 * @since 1.1.2
 * @example
 * rstrtohex("a\x00a") &rarr; "610061"
 */
function rstrtohex(s) {
    var result = "";
    for (var i = 0; i < s.length; i++) {
        result += ("0" + s.charCodeAt(i).toString(16)).slice(-2);
    }
    return result;
}

// ==== hex / b64nl =======================================

/*
 * since base64x 1.1.3
 */
function hextob64(s) {
    return hex2b64(s);
}

/*
 * since base64x 1.1.3
 */
function hextob64nl(s) {
    var b64 = hextob64(s);
    var b64nl = b64.replace(/(.{64})/g, "$1\r\n");
    b64nl = b64nl.replace(/\r\n$/, '');
    return b64nl;
}

/*
 * since base64x 1.1.3
 */
function b64nltohex(s) {
    var b64 = s.replace(/[^0-9A-Za-z\/+=]*/g, '');
    var hex = b64tohex(b64);
    return hex;
} 

// ==== URIComponent / hex ================================
/**
 * convert a URLComponent string such like "%67%68" to a hexadecimal string.<br/>
 * @param {String} s URIComponent string such like "%67%68"
 * @return {String} hexadecimal string
 * @since 1.1
 */
function uricmptohex(s) {
  return s.replace(/%/g, "");
}

/**
 * convert a hexadecimal string to a URLComponent string such like "%67%68".<br/>
 * @param {String} s hexadecimal string
 * @return {String} URIComponent string such like "%67%68"
 * @since 1.1
 */
function hextouricmp(s) {
  return s.replace(/(..)/g, "%$1");
}

// ==== URIComponent ================================
/**
 * convert UTFa hexadecimal string to a URLComponent string such like "%67%68".<br/>
 * Note that these "<code>0-9A-Za-z!'()*-._~</code>" characters will not
 * converted to "%xx" format by builtin 'encodeURIComponent()' function.
 * However this 'encodeURIComponentAll()' function will convert 
 * all of characters into "%xx" format.
 * @param {String} s hexadecimal string
 * @return {String} URIComponent string such like "%67%68"
 * @since 1.1
 */
function encodeURIComponentAll(u8) {
  var s = encodeURIComponent(u8);
  var s2 = "";
  for (var i = 0; i < s.length; i++) {
    if (s[i] == "%") {
      s2 = s2 + s.substr(i, 3);
      i = i + 2;
    } else {
      s2 = s2 + "%" + stohex(s[i]);
    }
  }
  return s2;
}

// ==== new lines ================================
/**
 * convert all DOS new line("\r\n") to UNIX new line("\n") in 
 * a String "s".
 * @param {String} s string 
 * @return {String} converted string
 */
function newline_toUnix(s) {
    s = s.replace(/\r\n/mg, "\n");
    return s;
}

/**
 * convert all UNIX new line("\r\n") to DOS new line("\n") in 
 * a String "s".
 * @param {String} s string 
 * @return {String} converted string
 */
function newline_toDos(s) {
    s = s.replace(/\r\n/mg, "\n");
    s = s.replace(/\n/mg, "\r\n");
    return s;
}

// ==== string type checker ===================

/**
 * check whether a string is an integer string or not<br/>
 * @name isInteger
 * @memberOf KJUR.lang.String
 * @function
 * @static
 * @param {String} s input string
 * @return {Boolean} true if a string "s" is an integer string otherwise false
 * @since base64x 1.1.7 jsrsasign 5.0.13
 * @example
 * KJUR.lang.String.isInteger("12345") &rarr; true
 * KJUR.lang.String.isInteger("123ab") &rarr; false
 */
KJUR.lang.String.isInteger = function(s) {
    if (s.match(/^[0-9]+$/)) {
	return true;
    } else if (s.match(/^-[0-9]+$/)) {
	return true;
    } else {
	return false;
    }
};

/**
 * check whether a string is an hexadecimal string or not<br/>
 * @name isHex
 * @memberOf KJUR.lang.String
 * @function
 * @static
 * @param {String} s input string
 * @return {Boolean} true if a string "s" is an hexadecimal string otherwise false
 * @since base64x 1.1.7 jsrsasign 5.0.13
 * @example
 * KJUR.lang.String.isHex("1234") &rarr; true
 * KJUR.lang.String.isHex("12ab") &rarr; true
 * KJUR.lang.String.isHex("12AB") &rarr; true
 * KJUR.lang.String.isHex("12ZY") &rarr; false
 * KJUR.lang.String.isHex("121") &rarr; false -- odd length
 */
KJUR.lang.String.isHex = function(s) {
    if (s.length % 2 == 0 &&
	(s.match(/^[0-9a-f]+$/) || s.match(/^[0-9A-F]+$/))) {
	return true;
    } else {
	return false;
    }
};

/**
 * check whether a string is a base64 encoded string or not<br/>
 * Input string can conclude new lines or space characters.
 * @name isBase64
 * @memberOf KJUR.lang.String
 * @function
 * @static
 * @param {String} s input string
 * @return {Boolean} true if a string "s" is a base64 encoded string otherwise false
 * @since base64x 1.1.7 jsrsasign 5.0.13
 * @example
 * KJUR.lang.String.isBase64("YWE=") &rarr; true
 * KJUR.lang.String.isBase64("YW_=") &rarr; false
 * KJUR.lang.String.isBase64("YWE") &rarr; false -- length shall be multiples of 4
 */
KJUR.lang.String.isBase64 = function(s) {
    s = s.replace(/\s+/g, "");
    if (s.match(/^[0-9A-Za-z+\/]+={0,3}$/) && s.length % 4 == 0) {
	return true;
    } else {
	return false;
    }
};

/**
 * check whether a string is a base64url encoded string or not<br/>
 * Input string can conclude new lines or space characters.
 * @name isBase64URL
 * @memberOf KJUR.lang.String
 * @function
 * @static
 * @param {String} s input string
 * @return {Boolean} true if a string "s" is a base64url encoded string otherwise false
 * @since base64x 1.1.7 jsrsasign 5.0.13
 * @example
 * KJUR.lang.String.isBase64URL("YWE") &rarr; true
 * KJUR.lang.String.isBase64URL("YW-") &rarr; true
 * KJUR.lang.String.isBase64URL("YW+") &rarr; false
 */
KJUR.lang.String.isBase64URL = function(s) {
    if (s.match(/[+/=]/)) return false;
    s = b64utob64(s);
    return KJUR.lang.String.isBase64(s);
};

/**
 * check whether a string is a string of integer array or not<br/>
 * Input string can conclude new lines or space characters.
 * @name isIntegerArray
 * @memberOf KJUR.lang.String
 * @function
 * @static
 * @param {String} s input string
 * @return {Boolean} true if a string "s" is a string of integer array otherwise false
 * @since base64x 1.1.7 jsrsasign 5.0.13
 * @example
 * KJUR.lang.String.isIntegerArray("[1,2,3]") &rarr; true
 * KJUR.lang.String.isIntegerArray("  [1, 2, 3  ] ") &rarr; true
 * KJUR.lang.String.isIntegerArray("[a,2]") &rarr; false
 */
KJUR.lang.String.isIntegerArray = function(s) {
    s = s.replace(/\s+/g, "");
    if (s.match(/^\[[0-9,]+\]$/)) {
	return true;
    } else {
	return false;
    }
};

// ==== others ================================

/**
 * convert string of integer array to hexadecimal string.<br/>
 * @param {String} s string of integer array
 * @return {String} hexadecimal string
 * @since base64x 1.1.6 jsrsasign 5.0.2
 * @throws "malformed integer array string: *" for wrong input
 * @description
 * This function converts a string of JavaScript integer array to
 * a hexadecimal string. Each integer value shall be in a range 
 * from 0 to 255 otherwise it raise exception. Input string can
 * have extra space or newline string so that they will be ignored.
 * 
 * @example
 * intarystrtohex(" [123, 34, 101, 34, 58] ")
 * -> 7b2265223a (i.e. `{"e":` as string)
 */
function intarystrtohex(s) {
  s = s.replace(/^\s*\[\s*/, '');
  s = s.replace(/\s*\]\s*$/, '');
  s = s.replace(/\s*/g, '');
  try {
    var hex = s.split(/,/).map(function(element, index, array) {
      var i = parseInt(element);
      if (i < 0 || 255 < i) throw "integer not in range 0-255";
      var hI = ("00" + i.toString(16)).slice(-2);
      return hI;
    }).join('');
    return hex;
  } catch(ex) {
    throw "malformed integer array string: " + ex;
  }
}

/**
 * find index of string where two string differs
 * @param {String} s1 string to compare
 * @param {String} s2 string to compare
 * @return {Number} string index of where character differs. Return -1 if same.
 * @since jsrsasign 4.9.0 base64x 1.1.5
 * @example
 * strdiffidx("abcdefg", "abcd4fg") -> 4
 * strdiffidx("abcdefg", "abcdefg") -> -1
 * strdiffidx("abcdefg", "abcdef") -> 6
 * strdiffidx("abcdefgh", "abcdef") -> 6
 */
var strdiffidx = function(s1, s2) {
    var n = s1.length;
    if (s1.length > s2.length) n = s2.length;
    for (var i = 0; i < n; i++) {
	if (s1.charCodeAt(i) != s2.charCodeAt(i)) return i;
    }
    if (s1.length != s2.length) return n;
    return -1; // same
};



/*! (c) Tom Wu | http://www-cs-students.stanford.edu/~tjw/jsbn/
 */
// Depends on jsbn.js and rng.js

// Version 1.1: support utf-8 encoding in pkcs1pad2

// convert a (hex) string to a bignum object
function parseBigInt(str,r) {
  return new BigInteger(str,r);
}

function linebrk(s,n) {
  var ret = "";
  var i = 0;
  while(i + n < s.length) {
    ret += s.substring(i,i+n) + "\n";
    i += n;
  }
  return ret + s.substring(i,s.length);
}

function byte2Hex(b) {
  if(b < 0x10)
    return "0" + b.toString(16);
  else
    return b.toString(16);
}

// PKCS#1 (type 2, random) pad input string s to n bytes, and return a bigint
function pkcs1pad2(s,n) {
  if(n < s.length + 11) { // TODO: fix for utf-8
    alert("Message too long for RSA");
    return null;
  }
  var ba = new Array();
  var i = s.length - 1;
  while(i >= 0 && n > 0) {
    var c = s.charCodeAt(i--);
    if(c < 128) { // encode using utf-8
      ba[--n] = c;
    }
    else if((c > 127) && (c < 2048)) {
      ba[--n] = (c & 63) | 128;
      ba[--n] = (c >> 6) | 192;
    }
    else {
      ba[--n] = (c & 63) | 128;
      ba[--n] = ((c >> 6) & 63) | 128;
      ba[--n] = (c >> 12) | 224;
    }
  }
  ba[--n] = 0;
  var rng = new SecureRandom();
  var x = new Array();
  while(n > 2) { // random non-zero pad
    x[0] = 0;
    while(x[0] == 0) rng.nextBytes(x);
    ba[--n] = x[0];
  }
  ba[--n] = 2;
  ba[--n] = 0;
  return new BigInteger(ba);
}

// PKCS#1 (OAEP) mask generation function
function oaep_mgf1_arr(seed, len, hash)
{
    var mask = '', i = 0;

    while (mask.length < len)
    {
        mask += hash(String.fromCharCode.apply(String, seed.concat([
                (i & 0xff000000) >> 24,
                (i & 0x00ff0000) >> 16,
                (i & 0x0000ff00) >> 8,
                i & 0x000000ff])));
        i += 1;
    }

    return mask;
}

// PKCS#1 (OAEP) pad input string s to n bytes, and return a bigint
function oaep_pad(s, n, hash, hashLen)
{
    if (!hash)
    {
        hash = rstr_sha1;
        hashLen = 20;
    }

    if (s.length + 2 * hashLen + 2 > n)
    {
        throw "Message too long for RSA";
    }

    var PS = '', i;

    for (i = 0; i < n - s.length - 2 * hashLen - 2; i += 1)
    {
        PS += '\x00';
    }

    var DB = hash('') + PS + '\x01' + s;
    var seed = new Array(hashLen);
    new SecureRandom().nextBytes(seed);
    
    var dbMask = oaep_mgf1_arr(seed, DB.length, hash);
    var maskedDB = [];

    for (i = 0; i < DB.length; i += 1)
    {
        maskedDB[i] = DB.charCodeAt(i) ^ dbMask.charCodeAt(i);
    }

    var seedMask = oaep_mgf1_arr(maskedDB, seed.length, hash);
    var maskedSeed = [0];

    for (i = 0; i < seed.length; i += 1)
    {
        maskedSeed[i + 1] = seed[i] ^ seedMask.charCodeAt(i);
    }

    return new BigInteger(maskedSeed.concat(maskedDB));
}

// "empty" RSA key constructor
function RSAKey() {
  this.n = null;
  this.e = 0;
  this.d = null;
  this.p = null;
  this.q = null;
  this.dmp1 = null;
  this.dmq1 = null;
  this.coeff = null;
}

// Set the public key fields N and e from hex strings
function RSASetPublic(N,E) {
  this.isPublic = true;
  if (typeof N !== "string") 
  {
    this.n = N;
    this.e = E;
  }
  else if(N != null && E != null && N.length > 0 && E.length > 0) {
    this.n = parseBigInt(N,16);
    this.e = parseInt(E,16);
  }
  else
    alert("Invalid RSA public key");
}

// Perform raw public operation on "x": return x^e (mod n)
function RSADoPublic(x) {
  return x.modPowInt(this.e, this.n);
}

// Return the PKCS#1 RSA encryption of "text" as an even-length hex string
function RSAEncrypt(text) {
  var m = pkcs1pad2(text,(this.n.bitLength()+7)>>3);
  if(m == null) return null;
  var c = this.doPublic(m);
  if(c == null) return null;
  var h = c.toString(16);
  if((h.length & 1) == 0) return h; else return "0" + h;
}

// Return the PKCS#1 OAEP RSA encryption of "text" as an even-length hex string
function RSAEncryptOAEP(text, hash, hashLen) {
  var m = oaep_pad(text, (this.n.bitLength()+7)>>3, hash, hashLen);
  if(m == null) return null;
  var c = this.doPublic(m);
  if(c == null) return null;
  var h = c.toString(16);
  if((h.length & 1) == 0) return h; else return "0" + h;
}

// Return the PKCS#1 RSA encryption of "text" as a Base64-encoded string
//function RSAEncryptB64(text) {
//  var h = this.encrypt(text);
//  if(h) return hex2b64(h); else return null;
//}

// protected
RSAKey.prototype.doPublic = RSADoPublic;

// public
RSAKey.prototype.setPublic = RSASetPublic;
RSAKey.prototype.encrypt = RSAEncrypt;
RSAKey.prototype.encryptOAEP = RSAEncryptOAEP;
//RSAKey.prototype.encrypt_b64 = RSAEncryptB64;

RSAKey.prototype.type = "RSA";

/*! rsasign-1.2.7.js (c) 2012 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
/*
 * rsa-sign.js - adding signing functions to RSAKey class.
 *
 * version: 1.2.7 (2013 Aug 25)
 *
 * Copyright (c) 2010-2013 Kenji Urushima (kenji.urushima@gmail.com)
 *
 * This software is licensed under the terms of the MIT License.
 * http://kjur.github.com/jsrsasign/license/
 *
 * The above copyright and license notice shall be 
 * included in all copies or substantial portions of the Software.
 */

/**
 * @fileOverview
 * @name rsasign-1.2.js
 * @author Kenji Urushima kenji.urushima@gmail.com
 * @version rsasign 1.2.7
 * @license <a href="http://kjur.github.io/jsrsasign/license/">MIT License</a>
 */

var _RE_HEXDECONLY = new RegExp("");
_RE_HEXDECONLY.compile("[^0-9a-f]", "gi");

// ========================================================================
// Signature Generation
// ========================================================================

function _rsasign_getHexPaddedDigestInfoForString(s, keySize, hashAlg) {
    var hashFunc = function(s) { return KJUR.crypto.Util.hashString(s, hashAlg); };
    var sHashHex = hashFunc(s);

    return KJUR.crypto.Util.getPaddedDigestInfoHex(sHashHex, hashAlg, keySize);
}

function _zeroPaddingOfSignature(hex, bitLength) {
    var s = "";
    var nZero = bitLength / 4 - hex.length;
    for (var i = 0; i < nZero; i++) {
	s = s + "0";
    }
    return s + hex;
}

/**
 * sign for a message string with RSA private key.<br/>
 * @name signString
 * @memberOf RSAKey
 * @function
 * @param {String} s message string to be signed.
 * @param {String} hashAlg hash algorithm name for signing.<br/>
 * @return returns hexadecimal string of signature value.
 */
function _rsasign_signString(s, hashAlg) {
    var hashFunc = function(s) { return KJUR.crypto.Util.hashString(s, hashAlg); };
    var sHashHex = hashFunc(s);

    return this.signWithMessageHash(sHashHex, hashAlg);
}

/**
 * sign hash value of message to be signed with RSA private key.<br/>
 * @name signWithMessageHash
 * @memberOf RSAKey
 * @function
 * @param {String} sHashHex hexadecimal string of hash value of message to be signed.
 * @param {String} hashAlg hash algorithm name for signing.<br/>
 * @return returns hexadecimal string of signature value.
 * @since rsasign 1.2.6
 */
function _rsasign_signWithMessageHash(sHashHex, hashAlg) {
    var hPM = KJUR.crypto.Util.getPaddedDigestInfoHex(sHashHex, hashAlg, this.n.bitLength());
    var biPaddedMessage = parseBigInt(hPM, 16);
    var biSign = this.doPrivate(biPaddedMessage);
    var hexSign = biSign.toString(16);
    return _zeroPaddingOfSignature(hexSign, this.n.bitLength());
}

function _rsasign_signStringWithSHA1(s) {
    return _rsasign_signString.call(this, s, 'sha1');
}

function _rsasign_signStringWithSHA256(s) {
    return _rsasign_signString.call(this, s, 'sha256');
}

// PKCS#1 (PSS) mask generation function
function pss_mgf1_str(seed, len, hash) {
    var mask = '', i = 0;

    while (mask.length < len) {
        mask += hextorstr(hash(rstrtohex(seed + String.fromCharCode.apply(String, [
                (i & 0xff000000) >> 24,
                (i & 0x00ff0000) >> 16,
                (i & 0x0000ff00) >> 8,
                i & 0x000000ff]))));
        i += 1;
    }

    return mask;
}

/**
 * sign for a message string with RSA private key by PKCS#1 PSS signing.<br/>
 * @name signStringPSS
 * @memberOf RSAKey
 * @function
 * @param {String} s message string to be signed.
 * @param {String} hashAlg hash algorithm name for signing.
 * @param {Integer} sLen salt byte length from 0 to (keybytelen - hashbytelen - 2).
 *        There are two special values:
 *        <ul>
 *        <li>-1: sets the salt length to the digest length</li>
 *        <li>-2: sets the salt length to maximum permissible value
 *           (i.e. keybytelen - hashbytelen - 2)</li>
 *        </ul>
 *        DEFAULT is -1. (NOTE: OpenSSL's default is -2.)
 * @return returns hexadecimal string of signature value.
 */
function _rsasign_signStringPSS(s, hashAlg, sLen) {
    var hashFunc = function(sHex) { return KJUR.crypto.Util.hashHex(sHex, hashAlg); } 
    var hHash = hashFunc(rstrtohex(s));

    if (sLen === undefined) sLen = -1;
    return this.signWithMessageHashPSS(hHash, hashAlg, sLen);
}

/**
 * sign hash value of message with RSA private key by PKCS#1 PSS signing.<br/>
 * @name signWithMessageHashPSS
 * @memberOf RSAKey
 * @function
 * @param {String} hHash hexadecimal hash value of message to be signed.
 * @param {String} hashAlg hash algorithm name for signing.
 * @param {Integer} sLen salt byte length from 0 to (keybytelen - hashbytelen - 2).
 *        There are two special values:
 *        <ul>
 *        <li>-1: sets the salt length to the digest length</li>
 *        <li>-2: sets the salt length to maximum permissible value
 *           (i.e. keybytelen - hashbytelen - 2)</li>
 *        </ul>
 *        DEFAULT is -1. (NOTE: OpenSSL's default is -2.)
 * @return returns hexadecimal string of signature value.
 * @since rsasign 1.2.6
 */
function _rsasign_signWithMessageHashPSS(hHash, hashAlg, sLen) {
    var mHash = hextorstr(hHash);
    var hLen = mHash.length;
    var emBits = this.n.bitLength() - 1;
    var emLen = Math.ceil(emBits / 8);
    var i;
    var hashFunc = function(sHex) { return KJUR.crypto.Util.hashHex(sHex, hashAlg); } 

    if (sLen === -1 || sLen === undefined) {
        sLen = hLen; // same as hash length
    } else if (sLen === -2) {
        sLen = emLen - hLen - 2; // maximum
    } else if (sLen < -2) {
        throw "invalid salt length";
    }

    if (emLen < (hLen + sLen + 2)) {
        throw "data too long";
    }

    var salt = '';

    if (sLen > 0) {
        salt = new Array(sLen);
        new SecureRandom().nextBytes(salt);
        salt = String.fromCharCode.apply(String, salt);
    }

    var H = hextorstr(hashFunc(rstrtohex('\x00\x00\x00\x00\x00\x00\x00\x00' + mHash + salt)));
    var PS = [];

    for (i = 0; i < emLen - sLen - hLen - 2; i += 1) {
        PS[i] = 0x00;
    }

    var DB = String.fromCharCode.apply(String, PS) + '\x01' + salt;
    var dbMask = pss_mgf1_str(H, DB.length, hashFunc);
    var maskedDB = [];

    for (i = 0; i < DB.length; i += 1) {
        maskedDB[i] = DB.charCodeAt(i) ^ dbMask.charCodeAt(i);
    }

    var mask = (0xff00 >> (8 * emLen - emBits)) & 0xff;
    maskedDB[0] &= ~mask;

    for (i = 0; i < hLen; i++) {
        maskedDB.push(H.charCodeAt(i));
    }

    maskedDB.push(0xbc);

    return _zeroPaddingOfSignature(this.doPrivate(new BigInteger(maskedDB)).toString(16),
				   this.n.bitLength());
}

// ========================================================================
// Signature Verification
// ========================================================================

function _rsasign_getDecryptSignatureBI(biSig, hN, hE) {
    var rsa = new RSAKey();
    rsa.setPublic(hN, hE);
    var biDecryptedSig = rsa.doPublic(biSig);
    return biDecryptedSig;
}

function _rsasign_getHexDigestInfoFromSig(biSig, hN, hE) {
    var biDecryptedSig = _rsasign_getDecryptSignatureBI(biSig, hN, hE);
    var hDigestInfo = biDecryptedSig.toString(16).replace(/^1f+00/, '');
    return hDigestInfo;
}

function _rsasign_getAlgNameAndHashFromHexDisgestInfo(hDigestInfo) {
    for (var algName in KJUR.crypto.Util.DIGESTINFOHEAD) {
	var head = KJUR.crypto.Util.DIGESTINFOHEAD[algName];
	var len = head.length;
	if (hDigestInfo.substring(0, len) == head) {
	    var a = [algName, hDigestInfo.substring(len)];
	    return a;
	}
    }
    return [];
}

function _rsasign_verifySignatureWithArgs(sMsg, biSig, hN, hE) {
    var hDigestInfo = _rsasign_getHexDigestInfoFromSig(biSig, hN, hE);
    var digestInfoAry = _rsasign_getAlgNameAndHashFromHexDisgestInfo(hDigestInfo);
    if (digestInfoAry.length == 0) return false;
    var algName = digestInfoAry[0];
    var diHashValue = digestInfoAry[1];
    var ff = function(s) { return KJUR.crypto.Util.hashString(s, algName); };
    var msgHashValue = ff(sMsg);
    return (diHashValue == msgHashValue);
}

function _rsasign_verifyHexSignatureForMessage(hSig, sMsg) {
    var biSig = parseBigInt(hSig, 16);
    var result = _rsasign_verifySignatureWithArgs(sMsg, biSig,
						  this.n.toString(16),
						  this.e.toString(16));
    return result;
}

/**
 * verifies a sigature for a message string with RSA public key.<br/>
 * @name verifyString
 * @memberOf RSAKey#
 * @function
 * @param {String} sMsg message string to be verified.
 * @param {String} hSig hexadecimal string of siganture.<br/>
 *                 non-hexadecimal charactors including new lines will be ignored.
 * @return returns 1 if valid, otherwise 0
 */
function _rsasign_verifyString(sMsg, hSig) {
    hSig = hSig.replace(_RE_HEXDECONLY, '');
    hSig = hSig.replace(/[ \n]+/g, "");
    var biSig = parseBigInt(hSig, 16);
    if (biSig.bitLength() > this.n.bitLength()) return 0;
    var biDecryptedSig = this.doPublic(biSig);
    var hDigestInfo = biDecryptedSig.toString(16).replace(/^1f+00/, '');
    var digestInfoAry = _rsasign_getAlgNameAndHashFromHexDisgestInfo(hDigestInfo);
  
    if (digestInfoAry.length == 0) return false;
    var algName = digestInfoAry[0];
    var diHashValue = digestInfoAry[1];
    var ff = function(s) { return KJUR.crypto.Util.hashString(s, algName); };
    var msgHashValue = ff(sMsg);
    return (diHashValue == msgHashValue);
}

/**
 * verifies a sigature for a message string with RSA public key.<br/>
 * @name verifyWithMessageHash
 * @memberOf RSAKey
 * @function
 * @param {String} sHashHex hexadecimal hash value of message to be verified.
 * @param {String} hSig hexadecimal string of siganture.<br/>
 *                 non-hexadecimal charactors including new lines will be ignored.
 * @return returns 1 if valid, otherwise 0
 * @since rsasign 1.2.6
 */
function _rsasign_verifyWithMessageHash(sHashHex, hSig) {
    hSig = hSig.replace(_RE_HEXDECONLY, '');
    hSig = hSig.replace(/[ \n]+/g, "");
    var biSig = parseBigInt(hSig, 16);
    if (biSig.bitLength() > this.n.bitLength()) return 0;
    var biDecryptedSig = this.doPublic(biSig);
    var hDigestInfo = biDecryptedSig.toString(16).replace(/^1f+00/, '');
    var digestInfoAry = _rsasign_getAlgNameAndHashFromHexDisgestInfo(hDigestInfo);
  
    if (digestInfoAry.length == 0) return false;
    var algName = digestInfoAry[0];
    var diHashValue = digestInfoAry[1];
    return (diHashValue == sHashHex);
}

/**
 * verifies a sigature for a message string with RSA public key by PKCS#1 PSS sign.<br/>
 * @name verifyStringPSS
 * @memberOf RSAKey
 * @function
 * @param {String} sMsg message string to be verified.
 * @param {String} hSig hexadecimal string of signature value
 * @param {String} hashAlg hash algorithm name
 * @param {Integer} sLen salt byte length from 0 to (keybytelen - hashbytelen - 2).
 *        There are two special values:
 *        <ul>
 *        <li>-1: sets the salt length to the digest length</li>
 *        <li>-2: sets the salt length to maximum permissible value
 *           (i.e. keybytelen - hashbytelen - 2)</li>
 *        </ul>
 *        DEFAULT is -1. (NOTE: OpenSSL's default is -2.)
 * @return returns true if valid, otherwise false
 */
function _rsasign_verifyStringPSS(sMsg, hSig, hashAlg, sLen) {
    var hashFunc = function(sHex) { return KJUR.crypto.Util.hashHex(sHex, hashAlg); };
    var hHash = hashFunc(rstrtohex(sMsg));

    if (sLen === undefined) sLen = -1;
    return this.verifyWithMessageHashPSS(hHash, hSig, hashAlg, sLen);
}

/**
 * verifies a sigature for a hash value of message string with RSA public key by PKCS#1 PSS sign.<br/>
 * @name verifyWithMessageHashPSS
 * @memberOf RSAKey
 * @function
 * @param {String} hHash hexadecimal hash value of message string to be verified.
 * @param {String} hSig hexadecimal string of signature value
 * @param {String} hashAlg hash algorithm name
 * @param {Integer} sLen salt byte length from 0 to (keybytelen - hashbytelen - 2).
 *        There are two special values:
 *        <ul>
 *        <li>-1: sets the salt length to the digest length</li>
 *        <li>-2: sets the salt length to maximum permissible value
 *           (i.e. keybytelen - hashbytelen - 2)</li>
 *        </ul>
 *        DEFAULT is -1 (NOTE: OpenSSL's default is -2.)
 * @return returns true if valid, otherwise false
 * @since rsasign 1.2.6
 */
function _rsasign_verifyWithMessageHashPSS(hHash, hSig, hashAlg, sLen) {
    var biSig = new BigInteger(hSig, 16);

    if (biSig.bitLength() > this.n.bitLength()) {
        return false;
    }

    var hashFunc = function(sHex) { return KJUR.crypto.Util.hashHex(sHex, hashAlg); };
    var mHash = hextorstr(hHash);
    var hLen = mHash.length;
    var emBits = this.n.bitLength() - 1;
    var emLen = Math.ceil(emBits / 8);
    var i;

    if (sLen === -1 || sLen === undefined) {
        sLen = hLen; // same as hash length
    } else if (sLen === -2) {
        sLen = emLen - hLen - 2; // recover
    } else if (sLen < -2) {
        throw "invalid salt length";
    }

    if (emLen < (hLen + sLen + 2)) {
        throw "data too long";
    }

    var em = this.doPublic(biSig).toByteArray();

    for (i = 0; i < em.length; i += 1) {
        em[i] &= 0xff;
    }

    while (em.length < emLen) {
        em.unshift(0);
    }

    if (em[emLen -1] !== 0xbc) {
        throw "encoded message does not end in 0xbc";
    }

    em = String.fromCharCode.apply(String, em);

    var maskedDB = em.substr(0, emLen - hLen - 1);
    var H = em.substr(maskedDB.length, hLen);

    var mask = (0xff00 >> (8 * emLen - emBits)) & 0xff;

    if ((maskedDB.charCodeAt(0) & mask) !== 0) {
        throw "bits beyond keysize not zero";
    }

    var dbMask = pss_mgf1_str(H, maskedDB.length, hashFunc);
    var DB = [];

    for (i = 0; i < maskedDB.length; i += 1) {
        DB[i] = maskedDB.charCodeAt(i) ^ dbMask.charCodeAt(i);
    }

    DB[0] &= ~mask;

    var checkLen = emLen - hLen - sLen - 2;

    for (i = 0; i < checkLen; i += 1) {
        if (DB[i] !== 0x00) {
            throw "leftmost octets not zero";
        }
    }

    if (DB[checkLen] !== 0x01) {
        throw "0x01 marker not found";
    }

    return H === hextorstr(hashFunc(rstrtohex('\x00\x00\x00\x00\x00\x00\x00\x00' + mHash +
				     String.fromCharCode.apply(String, DB.slice(-sLen)))));
}

RSAKey.prototype.signWithMessageHash = _rsasign_signWithMessageHash;
RSAKey.prototype.signString = _rsasign_signString;
RSAKey.prototype.signStringWithSHA1 = _rsasign_signStringWithSHA1;
RSAKey.prototype.signStringWithSHA256 = _rsasign_signStringWithSHA256;
RSAKey.prototype.sign = _rsasign_signString;
RSAKey.prototype.signWithSHA1 = _rsasign_signStringWithSHA1;
RSAKey.prototype.signWithSHA256 = _rsasign_signStringWithSHA256;

RSAKey.prototype.signWithMessageHashPSS = _rsasign_signWithMessageHashPSS;
RSAKey.prototype.signStringPSS = _rsasign_signStringPSS;
RSAKey.prototype.signPSS = _rsasign_signStringPSS;
RSAKey.SALT_LEN_HLEN = -1;
RSAKey.SALT_LEN_MAX = -2;

RSAKey.prototype.verifyWithMessageHash = _rsasign_verifyWithMessageHash;
RSAKey.prototype.verifyString = _rsasign_verifyString;
RSAKey.prototype.verifyHexSignatureForMessage = _rsasign_verifyHexSignatureForMessage;
RSAKey.prototype.verify = _rsasign_verifyString;
RSAKey.prototype.verifyHexSignatureForByteArrayMessage = _rsasign_verifyHexSignatureForMessage;

RSAKey.prototype.verifyWithMessageHashPSS = _rsasign_verifyWithMessageHashPSS;
RSAKey.prototype.verifyStringPSS = _rsasign_verifyStringPSS;
RSAKey.prototype.verifyPSS = _rsasign_verifyStringPSS;
RSAKey.SALT_LEN_RECOVER = -2;

/**
 * @name RSAKey
 * @class key of RSA public key algorithm
 * @description Tom Wu's RSA Key class and extension
 */

/*! keyutil-1.0.13.js (c) 2013-2016 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
/*
 * keyutil.js - key utility for PKCS#1/5/8 PEM, RSA/DSA/ECDSA key object
 *
 * Copyright (c) 2013-2016 Kenji Urushima (kenji.urushima@gmail.com)
 *
 * This software is licensed under the terms of the MIT License.
 * http://kjur.github.com/jsrsasign/license
 *
 * The above copyright and license notice shall be 
 * included in all copies or substantial portions of the Software.
 */
/**
 * @fileOverview
 * @name keyutil-1.0.js
 * @author Kenji Urushima kenji.urushima@gmail.com
 * @version keyutil 1.0.13 (2016-Aug-11)
 * @since jsrsasign 4.1.4
 * @license <a href="http://kjur.github.io/jsrsasign/license/">MIT License</a>
 */

/**
 * @name KEYUTIL
 * @class class for RSA/ECC/DSA key utility
 * @description 
 * <br/>
 * {@link KEYUTIL} class is an update of former {@link PKCS5PKEY} class.
 * So for now, {@link PKCS5PKEY} is deprecated class.
 * {@link KEYUTIL} class has following features:
 * <dl>
 * <dt><b>key loading - {@link KEYUTIL.getKey}</b>
 * <dd>
 * <ul>
 * <li>supports RSAKey and KJUR.crypto.{ECDSA,DSA} key object</li>
 * <li>supports private key and public key</li>
 * <li>supports encrypted and plain private key</li>
 * <li>supports PKCS#1, PKCS#5 and PKCS#8 key</li>
 * <li>supports public key in X.509 certificate</li>
 * <li>key represented by JSON object</li>
 * </ul>
 * NOTE1: Encrypted PKCS#8 only supports PBKDF2/HmacSHA1/3DES <br/>
 * NOTE2: Encrypted PKCS#5 supports DES-CBC, DES-EDE3-CBC, AES-{128,192.256}-CBC <br/>
 *
 * <dt><b>exporting key - {@link KEYUTIL.getPEM}</b>
 * <dd>
 * {@link KEYUTIL.getPEM} method supports following formats:
 * <ul>
 * <li>supports RSA/EC/DSA keys</li>
 * <li>PKCS#1 plain RSA/EC/DSA private key</li>
 * <li>PKCS#5 encrypted RSA/EC/DSA private key with DES-CBC, DES-EDE3-CBC, AES-{128,192.256}-CBC</li>
 * <li>PKCS#8 plain RSA/EC/DSA private key</li>
 * <li>PKCS#8 encrypted RSA/EC/DSA private key with PBKDF2_HmacSHA1_3DES</li>
 * </ul>
 *
 * <dt><b>keypair generation - {@link KEYUTIL.generateKeypair}</b>
 * <ul>
 * <li>generate key pair of {@link RSAKey} or {@link KJUR.crypto.ECDSA}.</li>
 * <li>generate private key and convert it to PKCS#5 encrypted private key.</li>
 * </ul>
 * NOTE: {@link KJUR.crypto.DSA} is not yet supported.
 * </dl>
 * 
 * @example
 * // 1. loading PEM private key
 * var key = KEYUTIL.getKey(pemPKCS1PrivateKey);
 * var key = KEYUTIL.getKey(pemPKCS5EncryptedPrivateKey, "passcode");
 * var key = KEYUTIL.getKey(pemPKC85PlainPrivateKey);
 * var key = KEYUTIL.getKey(pemPKC85EncryptedPrivateKey, "passcode");
 * // 2. loading PEM public key
 * var key = KEYUTIL.getKey(pemPKCS8PublicKey);
 * var key = KEYUTIL.getKey(pemX509Certificate);
 * // 3. exporting private key
 * var pem = KEYUTIL.getPEM(privateKeyObj, "PKCS1PRV");
 * var pem = KEYUTIL.getPEM(privateKeyObj, "PKCS5PRV", "passcode"); // DES-EDE3-CBC by default
 * var pem = KEYUTIL.getPEM(privateKeyObj, "PKCS5PRV", "passcode", "DES-CBC");
 * var pem = KEYUTIL.getPEM(privateKeyObj, "PKCS8PRV");
 * var pem = KEYUTIL.getPEM(privateKeyObj, "PKCS8PRV", "passcode");
 * // 4. exporting public key
 * var pem = KEYUTIL.getPEM(publicKeyObj);
 */
/*
 * DEPRECATED METHODS
 * GET PKCS8
 * KEYUTIL.getRSAKeyFromPlainPKCS8PEM
 * KEYUTIL.getRSAKeyFromPlainPKCS8Hex
 * KEYUTIL.getRSAKeyFromEncryptedPKCS8PEM
 * P8 UTIL (make internal use)
 * KEYUTIL.getPlainPKCS8HexFromEncryptedPKCS8PEM
 * GET PKCS8 PUB
 * KEYUTIL.getKeyFromPublicPKCS8PEM
 * KEYUTIL.getKeyFromPublicPKCS8Hex
 * KEYUTIL.getRSAKeyFromPublicPKCS8PEM
 * KEYUTIL.getRSAKeyFromPublicPKCS8Hex
 * GET PKCS5
 * KEYUTIL.getRSAKeyFromEncryptedPKCS5PEM
 * PUT PKCS5
 * KEYUTIL.getEncryptedPKCS5PEMFromRSAKey
 * OTHER METHODS (FOR INTERNAL?)
 * KEYUTIL.getHexFromPEM
 * KEYUTIL.getDecryptedKeyHexByKeyIV
 */
var KEYUTIL = function() {
    // *****************************************************************
    // *** PRIVATE PROPERTIES AND METHODS *******************************
    // *****************************************************************
    // shared key decryption ------------------------------------------
    var decryptAES = function(dataHex, keyHex, ivHex) {
        return decryptGeneral(CryptoJS.AES, dataHex, keyHex, ivHex);
    };

    var decrypt3DES = function(dataHex, keyHex, ivHex) {
        return decryptGeneral(CryptoJS.TripleDES, dataHex, keyHex, ivHex);
    };

    var decryptDES = function(dataHex, keyHex, ivHex) {
        return decryptGeneral(CryptoJS.DES, dataHex, keyHex, ivHex);
    };

    var decryptGeneral = function(f, dataHex, keyHex, ivHex) {
        var data = CryptoJS.enc.Hex.parse(dataHex);
        var key = CryptoJS.enc.Hex.parse(keyHex);
        var iv = CryptoJS.enc.Hex.parse(ivHex);
        var encrypted = {};
        encrypted.key = key;
        encrypted.iv = iv;
        encrypted.ciphertext = data;
        var decrypted = f.decrypt(encrypted, key, { iv: iv });
        return CryptoJS.enc.Hex.stringify(decrypted);
    };

    // shared key decryption ------------------------------------------
    var encryptAES = function(dataHex, keyHex, ivHex) {
        return encryptGeneral(CryptoJS.AES, dataHex, keyHex, ivHex);
    };

    var encrypt3DES = function(dataHex, keyHex, ivHex) {
        return encryptGeneral(CryptoJS.TripleDES, dataHex, keyHex, ivHex);
    };

    var encryptDES = function(dataHex, keyHex, ivHex) {
        return encryptGeneral(CryptoJS.DES, dataHex, keyHex, ivHex);
    };

    var encryptGeneral = function(f, dataHex, keyHex, ivHex) {
        var data = CryptoJS.enc.Hex.parse(dataHex);
        var key = CryptoJS.enc.Hex.parse(keyHex);
        var iv = CryptoJS.enc.Hex.parse(ivHex);
        var encryptedHex = f.encrypt(data, key, { iv: iv });
        var encryptedWA = CryptoJS.enc.Hex.parse(encryptedHex.toString());
        var encryptedB64 = CryptoJS.enc.Base64.stringify(encryptedWA);
        return encryptedB64;
    };

    // other methods and properties ----------------------------------------
    var ALGLIST = {
        'AES-256-CBC':  { 'proc': decryptAES,  'eproc': encryptAES,  keylen: 32, ivlen: 16 },
        'AES-192-CBC':  { 'proc': decryptAES,  'eproc': encryptAES,  keylen: 24, ivlen: 16 },
        'AES-128-CBC':  { 'proc': decryptAES,  'eproc': encryptAES,  keylen: 16, ivlen: 16 },
        'DES-EDE3-CBC': { 'proc': decrypt3DES, 'eproc': encrypt3DES, keylen: 24, ivlen: 8 },
        'DES-CBC':      { 'proc': decryptDES,  'eproc': encryptDES,  keylen: 8,  ivlen: 8 }
    };

    var getFuncByName = function(algName) {
        return ALGLIST[algName]['proc'];
    };

    var _generateIvSaltHex = function(numBytes) {
        var wa = CryptoJS.lib.WordArray.random(numBytes);
        var hex = CryptoJS.enc.Hex.stringify(wa);
        return hex;
    };

    var _parsePKCS5PEM = function(sPKCS5PEM) {
        var info = {};
        if (sPKCS5PEM.match(new RegExp("DEK-Info: ([^,]+),([0-9A-Fa-f]+)", "m"))) {
            info.cipher = RegExp.$1;
            info.ivsalt = RegExp.$2;
        }
        if (sPKCS5PEM.match(new RegExp("-----BEGIN ([A-Z]+) PRIVATE KEY-----"))) {
            info.type = RegExp.$1;
        }
        var i1 = -1;
        var lenNEWLINE = 0;
        if (sPKCS5PEM.indexOf("\r\n\r\n") != -1) {
            i1 = sPKCS5PEM.indexOf("\r\n\r\n");
            lenNEWLINE = 2;
        }
        if (sPKCS5PEM.indexOf("\n\n") != -1) {
            i1 = sPKCS5PEM.indexOf("\n\n");
            lenNEWLINE = 1;
        }
        var i2 = sPKCS5PEM.indexOf("-----END");
        if (i1 != -1 && i2 != -1) {
            var s = sPKCS5PEM.substring(i1 + lenNEWLINE * 2, i2 - lenNEWLINE);
            s = s.replace(/\s+/g, '');
            info.data = s;
        }
        return info;
    };

    var _getKeyAndUnusedIvByPasscodeAndIvsalt = function(algName, passcode, ivsaltHex) {
        //alert("ivsaltHex(2) = " + ivsaltHex);
        var saltHex = ivsaltHex.substring(0, 16);
        //alert("salt = " + saltHex);
        
        var salt = CryptoJS.enc.Hex.parse(saltHex);
        var data = CryptoJS.enc.Utf8.parse(passcode);
        //alert("salt = " + salt);
        //alert("data = " + data);

        var nRequiredBytes = ALGLIST[algName]['keylen'] + ALGLIST[algName]['ivlen'];
        var hHexValueJoined = '';
        var hLastValue = null;
        //alert("nRequiredBytes = " + nRequiredBytes);
        for (;;) {
            var h = CryptoJS.algo.MD5.create();
            if (hLastValue != null) {
                h.update(hLastValue);
            }
            h.update(data);
            h.update(salt);
            hLastValue = h.finalize();
            hHexValueJoined = hHexValueJoined + CryptoJS.enc.Hex.stringify(hLastValue);
            //alert("joined = " + hHexValueJoined);
            if (hHexValueJoined.length >= nRequiredBytes * 2) {
                break;
            }
        }
        var result = {};
        result.keyhex = hHexValueJoined.substr(0, ALGLIST[algName]['keylen'] * 2);
        result.ivhex = hHexValueJoined.substr(ALGLIST[algName]['keylen'] * 2, ALGLIST[algName]['ivlen'] * 2);
        return result;
    };

    /*
     * @param {String} privateKeyB64 base64 string of encrypted private key
     * @param {String} sharedKeyAlgName algorithm name of shared key encryption
     * @param {String} sharedKeyHex hexadecimal string of shared key to encrypt
     * @param {String} ivsaltHex hexadecimal string of IV and salt
     * @param {String} hexadecimal string of decrypted private key
     */
    var _decryptKeyB64 = function(privateKeyB64, sharedKeyAlgName, sharedKeyHex, ivsaltHex) {
        var privateKeyWA = CryptoJS.enc.Base64.parse(privateKeyB64);
        var privateKeyHex = CryptoJS.enc.Hex.stringify(privateKeyWA);
        var f = ALGLIST[sharedKeyAlgName]['proc'];
        var decryptedKeyHex = f(privateKeyHex, sharedKeyHex, ivsaltHex);
        return decryptedKeyHex;
    };
    
    /*
     * @param {String} privateKeyHex hexadecimal string of private key
     * @param {String} sharedKeyAlgName algorithm name of shared key encryption
     * @param {String} sharedKeyHex hexadecimal string of shared key to encrypt
     * @param {String} ivsaltHex hexadecimal string of IV and salt
     * @param {String} base64 string of encrypted private key
     */
    var _encryptKeyHex = function(privateKeyHex, sharedKeyAlgName, sharedKeyHex, ivsaltHex) {
        var f = ALGLIST[sharedKeyAlgName]['eproc'];
        var encryptedKeyB64 = f(privateKeyHex, sharedKeyHex, ivsaltHex);
        return encryptedKeyB64;
    };

    // *****************************************************************
    // *** PUBLIC PROPERTIES AND METHODS *******************************
    // *****************************************************************
    return {
        // -- UTILITY METHODS ------------------------------------------------------------
        /**
         * decrypt private key by shared key
         * @name version
         * @memberOf KEYUTIL
         * @property {String} version
         * @description version string of KEYUTIL class
         */
        version: "1.0.0",

        /**
         * get hexacedimal string of PEM format
         * @name getHexFromPEM
         * @memberOf KEYUTIL
         * @function
         * @param {String} sPEM PEM formatted string
         * @param {String} sHead PEM header string without BEGIN/END
         * @return {String} hexadecimal string data of PEM contents
         * @since pkcs5pkey 1.0.5
         */
        getHexFromPEM: function(sPEM, sHead) {
            var s = sPEM;
            if (s.indexOf("-----BEGIN ") == -1) {
                throw "can't find PEM header: " + sHead;
            }
            if (typeof sHead == "string" && sHead != "") {
                s = s.replace("-----BEGIN " + sHead + "-----", "");
                s = s.replace("-----END " + sHead + "-----", "");
            } else {
                s = s.replace(/-----BEGIN [^-]+-----/, '');
                s = s.replace(/-----END [^-]+-----/, '');
            }
            var sB64 = s.replace(/\s+/g, '');
            var dataHex = b64tohex(sB64);
            return dataHex;
        },

        /**
         * decrypt private key by shared key
         * @name getDecryptedKeyHexByKeyIV
         * @memberOf KEYUTIL
         * @function
         * @param {String} encryptedKeyHex hexadecimal string of encrypted private key
         * @param {String} algName name of symmetric key algorithm (ex. 'DES-EBE3-CBC')
         * @param {String} sharedKeyHex hexadecimal string of symmetric key
         * @param {String} ivHex hexadecimal string of initial vector(IV).
         * @return {String} hexadecimal string of decrypted privated key
         */
        getDecryptedKeyHexByKeyIV: function(encryptedKeyHex, algName, sharedKeyHex, ivHex) {
            var f1 = getFuncByName(algName);
            return f1(encryptedKeyHex, sharedKeyHex, ivHex);
        },

        /**
         * parse PEM formatted passcode protected PKCS#5 private key
         * @name parsePKCS5PEM
         * @memberOf KEYUTIL
         * @function
         * @param {String} sEncryptedPEM PEM formatted protected passcode protected PKCS#5 private key
         * @return {Hash} hash of key information
         * @description
         * Resulted hash has following attributes.
         * <ul>
         * <li>cipher - symmetric key algorithm name (ex. 'DES-EBE3-CBC', 'AES-256-CBC')</li>
         * <li>ivsalt - IV used for decrypt. Its heading 8 bytes will be used for passcode salt.</li>
         * <li>type - asymmetric key algorithm name of private key described in PEM header.</li>
         * <li>data - base64 encoded encrypted private key.</li>
         * </ul>
         *
         */
        parsePKCS5PEM: function(sPKCS5PEM) {
            return _parsePKCS5PEM(sPKCS5PEM);
        },

        /**
         * the same function as OpenSSL EVP_BytsToKey to generate shared key and IV
         * @name getKeyAndUnusedIvByPasscodeAndIvsalt
         * @memberOf KEYUTIL
         * @function
         * @param {String} algName name of symmetric key algorithm (ex. 'DES-EBE3-CBC')
         * @param {String} passcode passcode to decrypt private key (ex. 'password')
         * @param {String} hexadecimal string of IV. heading 8 bytes will be used for passcode salt
         * @return {Hash} hash of key and unused IV (ex. {keyhex:2fe3..., ivhex:3fad..})
         */
        getKeyAndUnusedIvByPasscodeAndIvsalt: function(algName, passcode, ivsaltHex) {
            return _getKeyAndUnusedIvByPasscodeAndIvsalt(algName, passcode, ivsaltHex);
        },

        decryptKeyB64: function(privateKeyB64, sharedKeyAlgName, sharedKeyHex, ivsaltHex) {
            return _decryptKeyB64(privateKeyB64, sharedKeyAlgName, sharedKeyHex, ivsaltHex);
        },

        /**
         * decrypt PEM formatted protected PKCS#5 private key with passcode
         * @name getDecryptedKeyHex
         * @memberOf KEYUTIL
         * @function
         * @param {String} sEncryptedPEM PEM formatted protected passcode protected PKCS#5 private key
         * @param {String} passcode passcode to decrypt private key (ex. 'password')
         * @return {String} hexadecimal string of decrypted RSA priavte key
         */
        getDecryptedKeyHex: function(sEncryptedPEM, passcode) {
            // 1. parse pem
            var info = _parsePKCS5PEM(sEncryptedPEM);
            var publicKeyAlgName = info.type;
            var sharedKeyAlgName = info.cipher;
            var ivsaltHex = info.ivsalt;
            var privateKeyB64 = info.data;
            //alert("ivsaltHex = " + ivsaltHex);

            // 2. generate shared key
            var sharedKeyInfo = _getKeyAndUnusedIvByPasscodeAndIvsalt(sharedKeyAlgName, passcode, ivsaltHex);
            var sharedKeyHex = sharedKeyInfo.keyhex;
            //alert("sharedKeyHex = " + sharedKeyHex);

            // 3. decrypt private key
            var decryptedKey = _decryptKeyB64(privateKeyB64, sharedKeyAlgName, sharedKeyHex, ivsaltHex);
            return decryptedKey;
        },

        /**
         * (DEPRECATED) read PEM formatted encrypted PKCS#5 private key and returns RSAKey object
         * @name getRSAKeyFromEncryptedPKCS5PEM
         * @memberOf KEYUTIL
         * @function
         * @param {String} sEncryptedP5PEM PEM formatted encrypted PKCS#5 private key
         * @param {String} passcode passcode to decrypt private key
         * @return {RSAKey} loaded RSAKey object of RSA private key
         * @since pkcs5pkey 1.0.2
         * @deprecated From jsrsasign 4.2.1 please use {@link KEYUTIL.getKey#}.
         */
        getRSAKeyFromEncryptedPKCS5PEM: function(sEncryptedP5PEM, passcode) {
            var hPKey = this.getDecryptedKeyHex(sEncryptedP5PEM, passcode);
            var rsaKey = new RSAKey();
            rsaKey.readPrivateKeyFromASN1HexString(hPKey);
            return rsaKey;
        },

        /*
         * get PEM formatted encrypted PKCS#5 private key from hexadecimal string of plain private key
         * @name getEncryptedPKCS5PEMFromPrvKeyHex
         * @memberOf KEYUTIL
         * @function
         * @param {String} pemHeadAlg algorithm name in the pem header (i.e. RSA,EC or DSA)
         * @param {String} hPrvKey hexadecimal string of plain private key
         * @param {String} passcode pass code to protect private key (ex. password)
         * @param {String} sharedKeyAlgName algorithm name to protect private key (ex. AES-256-CBC)
         * @param {String} ivsaltHex hexadecimal string of IV and salt
         * @return {String} string of PEM formatted encrypted PKCS#5 private key
         * @since pkcs5pkey 1.0.2
         * @description
         * <br/>
         * generate PEM formatted encrypted PKCS#5 private key by hexadecimal string encoded
         * ASN.1 object of plain RSA private key.
         * Following arguments can be omitted.
         * <ul>
         * <li>alg - AES-256-CBC will be used if omitted.</li>
         * <li>ivsaltHex - automatically generate IV and salt which length depends on algorithm</li>
         * </ul>
         * NOTE1: DES-CBC, DES-EDE3-CBC, AES-{128,192.256}-CBC algorithm are supported.
         * @example
         * var pem = 
         *   KEYUTIL.getEncryptedPKCS5PEMFromPrvKeyHex(plainKeyHex, "password");
         * var pem2 = 
         *   KEYUTIL.getEncryptedPKCS5PEMFromPrvKeyHex(plainKeyHex, "password", "AES-128-CBC");
         * var pem3 = 
         *   KEYUTIL.getEncryptedPKCS5PEMFromPrvKeyHex(plainKeyHex, "password", "AES-128-CBC", "1f3d02...");
         */
        getEncryptedPKCS5PEMFromPrvKeyHex: function(pemHeadAlg, hPrvKey, passcode, sharedKeyAlgName, ivsaltHex) {
            var sPEM = "";

            // 1. set sharedKeyAlgName if undefined (default AES-256-CBC)
            if (typeof sharedKeyAlgName == "undefined" || sharedKeyAlgName == null) {
                sharedKeyAlgName = "AES-256-CBC";
            }
            if (typeof ALGLIST[sharedKeyAlgName] == "undefined")
                throw "KEYUTIL unsupported algorithm: " + sharedKeyAlgName;

            // 2. set ivsaltHex if undefined
            if (typeof ivsaltHex == "undefined" || ivsaltHex == null) {
                var ivlen = ALGLIST[sharedKeyAlgName]['ivlen'];
                var randIV = _generateIvSaltHex(ivlen);
                ivsaltHex = randIV.toUpperCase();
            }

            // 3. get shared key
            //alert("ivsalthex=" + ivsaltHex);
            var sharedKeyInfo = _getKeyAndUnusedIvByPasscodeAndIvsalt(sharedKeyAlgName, passcode, ivsaltHex);
            var sharedKeyHex = sharedKeyInfo.keyhex;
            // alert("sharedKeyHex = " + sharedKeyHex);

            // 3. get encrypted Key in Base64
            var encryptedKeyB64 = _encryptKeyHex(hPrvKey, sharedKeyAlgName, sharedKeyHex, ivsaltHex);

            var pemBody = encryptedKeyB64.replace(/(.{64})/g, "$1\r\n");
            var sPEM = "-----BEGIN " + pemHeadAlg + " PRIVATE KEY-----\r\n";
            sPEM += "Proc-Type: 4,ENCRYPTED\r\n";
            sPEM += "DEK-Info: " + sharedKeyAlgName + "," + ivsaltHex + "\r\n";
            sPEM += "\r\n";
            sPEM += pemBody;
            sPEM += "\r\n-----END " + pemHeadAlg + " PRIVATE KEY-----\r\n";

            return sPEM;
        },

        /**
         * (DEPRECATED) get PEM formatted encrypted PKCS#5 private key from RSAKey object of private key
         * @name getEncryptedPKCS5PEMFromRSAKey
         * @memberOf KEYUTIL
         * @function
         * @param {RSAKey} pKey RSAKey object of private key
         * @param {String} passcode pass code to protect private key (ex. password)
         * @param {String} alg algorithm name to protect private key (default AES-256-CBC)
         * @param {String} ivsaltHex hexadecimal string of IV and salt (default generated random IV)
         * @return {String} string of PEM formatted encrypted PKCS#5 private key
         * @since pkcs5pkey 1.0.2
         * @deprecated From jsrsasign 4.2.1 please use {@link KEYUTIL.getPEM#}.
         * @description
         * <br/>
         * generate PEM formatted encrypted PKCS#5 private key by
         * {@link RSAKey} object of RSA private key and passcode.
         * Following argument can be omitted.
         * <ul>
         * <li>alg - AES-256-CBC will be used if omitted.</li>
         * <li>ivsaltHex - automatically generate IV and salt which length depends on algorithm</li>
         * </ul>
         * @example
         * var pkey = new RSAKey();
         * pkey.generate(1024, '10001'); // generate 1024bit RSA private key with public exponent 'x010001'
         * var pem = KEYUTIL.getEncryptedPKCS5PEMFromRSAKey(pkey, "password");
         */
        getEncryptedPKCS5PEMFromRSAKey: function(pKey, passcode, alg, ivsaltHex) {
            var version = new KJUR.asn1.DERInteger({'int': 0});
            var n = new KJUR.asn1.DERInteger({'bigint': pKey.n});
            var e = new KJUR.asn1.DERInteger({'int': pKey.e});
            var d = new KJUR.asn1.DERInteger({'bigint': pKey.d});
            var p = new KJUR.asn1.DERInteger({'bigint': pKey.p});
            var q = new KJUR.asn1.DERInteger({'bigint': pKey.q});
            var dmp1 = new KJUR.asn1.DERInteger({'bigint': pKey.dmp1});
            var dmq1 = new KJUR.asn1.DERInteger({'bigint': pKey.dmq1});
            var coeff = new KJUR.asn1.DERInteger({'bigint': pKey.coeff});
            var seq = new KJUR.asn1.DERSequence({'array': [version, n, e, d, p, q, dmp1, dmq1, coeff]});
            var hex = seq.getEncodedHex();
            return this.getEncryptedPKCS5PEMFromPrvKeyHex("RSA", hex, passcode, alg, ivsaltHex);
        },

        /**
         * generate RSAKey and PEM formatted encrypted PKCS#5 private key
         * @name newEncryptedPKCS5PEM
         * @memberOf KEYUTIL
         * @function
         * @param {String} passcode pass code to protect private key (ex. password)
         * @param {Integer} keyLen key bit length of RSA key to be generated. (default 1024)
         * @param {String} hPublicExponent hexadecimal string of public exponent (default 10001)
         * @param {String} alg shared key algorithm to encrypt private key (default AES-258-CBC)
         * @return {String} string of PEM formatted encrypted PKCS#5 private key
         * @since pkcs5pkey 1.0.2
         * @example
         * var pem1 = KEYUTIL.newEncryptedPKCS5PEM("password");           // RSA1024bit/10001/AES-256-CBC
         * var pem2 = KEYUTIL.newEncryptedPKCS5PEM("password", 512);      // RSA 512bit/10001/AES-256-CBC
         * var pem3 = KEYUTIL.newEncryptedPKCS5PEM("password", 512, '3'); // RSA 512bit/    3/AES-256-CBC
         */
        newEncryptedPKCS5PEM: function(passcode, keyLen, hPublicExponent, alg) {
            if (typeof keyLen == "undefined" || keyLen == null) {
                keyLen = 1024;
            }
            if (typeof hPublicExponent == "undefined" || hPublicExponent == null) {
                hPublicExponent = '10001';
            }
            var pKey = new RSAKey();
            pKey.generate(keyLen, hPublicExponent);
            var pem = null;
            if (typeof alg == "undefined" || alg == null) {
                pem = this.getEncryptedPKCS5PEMFromRSAKey(pKey, passcode);
            } else {
                pem = this.getEncryptedPKCS5PEMFromRSAKey(pKey, passcode, alg);
            }
            return pem;
        },

        // === PKCS8 ===============================================================

        /**
         * (DEPRECATED) read PEM formatted unencrypted PKCS#8 private key and returns RSAKey object
         * @name getRSAKeyFromPlainPKCS8PEM
         * @memberOf KEYUTIL
         * @function
         * @param {String} pkcs8PEM PEM formatted unencrypted PKCS#8 private key
         * @return {RSAKey} loaded RSAKey object of RSA private key
         * @since pkcs5pkey 1.0.1
         * @deprecated From jsrsasign 4.2.1 please use {@link KEYUTIL.getKey#}.
         */
        getRSAKeyFromPlainPKCS8PEM: function(pkcs8PEM) {
            if (pkcs8PEM.match(/ENCRYPTED/))
                throw "pem shall be not ENCRYPTED";
            var prvKeyHex = this.getHexFromPEM(pkcs8PEM, "PRIVATE KEY");
            var rsaKey = this.getRSAKeyFromPlainPKCS8Hex(prvKeyHex);
            return rsaKey;
        },

        /**
         * (DEPRECATED) provide hexadecimal string of unencrypted PKCS#8 private key and returns RSAKey object
         * @name getRSAKeyFromPlainPKCS8Hex
         * @memberOf KEYUTIL
         * @function
         * @param {String} prvKeyHex hexadecimal string of unencrypted PKCS#8 private key
         * @return {RSAKey} loaded RSAKey object of RSA private key
         * @since pkcs5pkey 1.0.3
         * @deprecated From jsrsasign 4.2.1 please use {@link KEYUTIL.getKey#}.
         */
        getRSAKeyFromPlainPKCS8Hex: function(prvKeyHex) {
            var a1 = ASN1HEX.getPosArrayOfChildren_AtObj(prvKeyHex, 0);
            if (a1.length != 3)
                throw "outer DERSequence shall have 3 elements: " + a1.length;
            var algIdTLV =ASN1HEX.getHexOfTLV_AtObj(prvKeyHex, a1[1]);
            if (algIdTLV != "300d06092a864886f70d0101010500") // AlgId rsaEncryption
                throw "PKCS8 AlgorithmIdentifier is not rsaEnc: " + algIdTLV;
            var algIdTLV = ASN1HEX.getHexOfTLV_AtObj(prvKeyHex, a1[1]);
            var octetStr = ASN1HEX.getHexOfTLV_AtObj(prvKeyHex, a1[2]);
            var p5KeyHex = ASN1HEX.getHexOfV_AtObj(octetStr, 0);
            //alert(p5KeyHex);
            var rsaKey = new RSAKey();
            rsaKey.readPrivateKeyFromASN1HexString(p5KeyHex);
            return rsaKey;
        },

        /**
         * generate PBKDF2 key hexstring with specified passcode and information
         * @name parseHexOfEncryptedPKCS8
         * @memberOf KEYUTIL
         * @function
         * @param {String} passcode passcode to decrypto private key
         * @return {Array} info associative array of PKCS#8 parameters
         * @since pkcs5pkey 1.0.3
         * @description
         * The associative array which is returned by this method has following properties:
         * <ul>
         * <li>info.pbkdf2Salt - hexadecimal string of PBKDF2 salt</li>
         * <li>info.pkbdf2Iter - iteration count</li>
         * <li>info.ciphertext - hexadecimal string of encrypted private key</li>
         * <li>info.encryptionSchemeAlg - encryption algorithm name (currently TripleDES only)</li>
         * <li>info.encryptionSchemeIV - initial vector for encryption algorithm</li>
         * </ul>
         * Currently, this method only supports PKCS#5v2.0 with PBES2/PBDKF2 of HmacSHA1 and TripleDES.
         * <ul>
         * <li>keyDerivationFunc = pkcs5PBKDF2 with HmacSHA1</li>
         * <li>encryptionScheme = des-EDE3-CBC(i.e. TripleDES</li>
         * </ul>
         * @example
         * // to convert plain PKCS#5 private key to encrypted PKCS#8 private
         * // key with PBKDF2 with TripleDES
         * % openssl pkcs8 -in plain_p5.pem -topk8 -v2 -des3 -out encrypted_p8.pem
         */
        parseHexOfEncryptedPKCS8: function(sHEX) {
            var info = {};
            
            var a0 = ASN1HEX.getPosArrayOfChildren_AtObj(sHEX, 0);
            if (a0.length != 2)
                throw "malformed format: SEQUENCE(0).items != 2: " + a0.length;

            // 1. ciphertext
            info.ciphertext = ASN1HEX.getHexOfV_AtObj(sHEX, a0[1]);

            // 2. pkcs5PBES2
            var a0_0 = ASN1HEX.getPosArrayOfChildren_AtObj(sHEX, a0[0]); 
            if (a0_0.length != 2)
                throw "malformed format: SEQUENCE(0.0).items != 2: " + a0_0.length;

            // 2.1 check if pkcs5PBES2(1 2 840 113549 1 5 13)
            if (ASN1HEX.getHexOfV_AtObj(sHEX, a0_0[0]) != "2a864886f70d01050d")
                throw "this only supports pkcs5PBES2";

            // 2.2 pkcs5PBES2 param
            var a0_0_1 = ASN1HEX.getPosArrayOfChildren_AtObj(sHEX, a0_0[1]); 
            if (a0_0.length != 2)
                throw "malformed format: SEQUENCE(0.0.1).items != 2: " + a0_0_1.length;

            // 2.2.1 encryptionScheme
            var a0_0_1_1 = ASN1HEX.getPosArrayOfChildren_AtObj(sHEX, a0_0_1[1]); 
            if (a0_0_1_1.length != 2)
                throw "malformed format: SEQUENCE(0.0.1.1).items != 2: " + a0_0_1_1.length;
            if (ASN1HEX.getHexOfV_AtObj(sHEX, a0_0_1_1[0]) != "2a864886f70d0307")
                throw "this only supports TripleDES";
            info.encryptionSchemeAlg = "TripleDES";

            // 2.2.1.1 IV of encryptionScheme
            info.encryptionSchemeIV = ASN1HEX.getHexOfV_AtObj(sHEX, a0_0_1_1[1]);

            // 2.2.2 keyDerivationFunc
            var a0_0_1_0 = ASN1HEX.getPosArrayOfChildren_AtObj(sHEX, a0_0_1[0]); 
            if (a0_0_1_0.length != 2)
                throw "malformed format: SEQUENCE(0.0.1.0).items != 2: " + a0_0_1_0.length;
            if (ASN1HEX.getHexOfV_AtObj(sHEX, a0_0_1_0[0]) != "2a864886f70d01050c")
                throw "this only supports pkcs5PBKDF2";

            // 2.2.2.1 pkcs5PBKDF2 param
            var a0_0_1_0_1 = ASN1HEX.getPosArrayOfChildren_AtObj(sHEX, a0_0_1_0[1]); 
            if (a0_0_1_0_1.length < 2)
                throw "malformed format: SEQUENCE(0.0.1.0.1).items < 2: " + a0_0_1_0_1.length;

            // 2.2.2.1.1 PBKDF2 salt
            info.pbkdf2Salt = ASN1HEX.getHexOfV_AtObj(sHEX, a0_0_1_0_1[0]);

            // 2.2.2.1.2 PBKDF2 iter
            var iterNumHex = ASN1HEX.getHexOfV_AtObj(sHEX, a0_0_1_0_1[1]);
            try {
                info.pbkdf2Iter = parseInt(iterNumHex, 16);
            } catch(ex) {
                throw "malformed format pbkdf2Iter: " + iterNumHex;
            }

            return info;
        },

        /**
         * generate PBKDF2 key hexstring with specified passcode and information
         * @name getPBKDF2KeyHexFromParam
         * @memberOf KEYUTIL
         * @function
         * @param {Array} info result of {@link parseHexOfEncryptedPKCS8} which has preference of PKCS#8 file
         * @param {String} passcode passcode to decrypto private key
         * @return {String} hexadecimal string of PBKDF2 key
         * @since pkcs5pkey 1.0.3
         * @description
         * As for info, this uses following properties:
         * <ul>
         * <li>info.pbkdf2Salt - hexadecimal string of PBKDF2 salt</li>
         * <li>info.pkbdf2Iter - iteration count</li>
         * </ul>
         * Currently, this method only supports PKCS#5v2.0 with PBES2/PBDKF2 of HmacSHA1 and TripleDES.
         * <ul>
         * <li>keyDerivationFunc = pkcs5PBKDF2 with HmacSHA1</li>
         * <li>encryptionScheme = des-EDE3-CBC(i.e. TripleDES</li>
         * </ul>
         * @example
         * // to convert plain PKCS#5 private key to encrypted PKCS#8 private
         * // key with PBKDF2 with TripleDES
         * % openssl pkcs8 -in plain_p5.pem -topk8 -v2 -des3 -out encrypted_p8.pem
         */
        getPBKDF2KeyHexFromParam: function(info, passcode) {
            var pbkdf2SaltWS = CryptoJS.enc.Hex.parse(info.pbkdf2Salt);
            var pbkdf2Iter = info.pbkdf2Iter;
            var pbkdf2KeyWS = CryptoJS.PBKDF2(passcode, 
                                              pbkdf2SaltWS, 
                                              { keySize: 192/32, iterations: pbkdf2Iter });
            var pbkdf2KeyHex = CryptoJS.enc.Hex.stringify(pbkdf2KeyWS);
            return pbkdf2KeyHex;
        },

        /**
         * read PEM formatted encrypted PKCS#8 private key and returns hexadecimal string of plain PKCS#8 private key
         * @name getPlainPKCS8HexFromEncryptedPKCS8PEM
         * @memberOf KEYUTIL
         * @function
         * @param {String} pkcs8PEM PEM formatted encrypted PKCS#8 private key
         * @param {String} passcode passcode to decrypto private key
         * @return {String} hexadecimal string of plain PKCS#8 private key
         * @since pkcs5pkey 1.0.3
         * @description
         * Currently, this method only supports PKCS#5v2.0 with PBES2/PBDKF2 of HmacSHA1 and TripleDES.
         * <ul>
         * <li>keyDerivationFunc = pkcs5PBKDF2 with HmacSHA1</li>
         * <li>encryptionScheme = des-EDE3-CBC(i.e. TripleDES</li>
         * </ul>
         * @example
         * // to convert plain PKCS#5 private key to encrypted PKCS#8 private
         * // key with PBKDF2 with TripleDES
         * % openssl pkcs8 -in plain_p5.pem -topk8 -v2 -des3 -out encrypted_p8.pem
         */
        getPlainPKCS8HexFromEncryptedPKCS8PEM: function(pkcs8PEM, passcode) {
            // 1. derHex - PKCS#8 private key encrypted by PBKDF2
            var derHex = this.getHexFromPEM(pkcs8PEM, "ENCRYPTED PRIVATE KEY");
            // 2. info - PKCS#5 PBES info
            var info = this.parseHexOfEncryptedPKCS8(derHex);
            // 3. hKey - PBKDF2 key
            var pbkdf2KeyHex = KEYUTIL.getPBKDF2KeyHexFromParam(info, passcode);
            // 4. decrypt ciphertext by PBKDF2 key
            var encrypted = {};
            encrypted.ciphertext = CryptoJS.enc.Hex.parse(info.ciphertext);
            var pbkdf2KeyWS = CryptoJS.enc.Hex.parse(pbkdf2KeyHex);
            var des3IVWS = CryptoJS.enc.Hex.parse(info.encryptionSchemeIV);
            var decWS = CryptoJS.TripleDES.decrypt(encrypted, pbkdf2KeyWS, { iv: des3IVWS });
            var decHex = CryptoJS.enc.Hex.stringify(decWS);
            return decHex;
        },

        /**
         * (DEPRECATED) read PEM formatted encrypted PKCS#8 private key and returns RSAKey object
         * @name getRSAKeyFromEncryptedPKCS8PEM
         * @memberOf KEYUTIL
         * @function
         * @param {String} pkcs8PEM PEM formatted encrypted PKCS#8 private key
         * @param {String} passcode passcode to decrypto private key
         * @return {RSAKey} loaded RSAKey object of RSA private key
         * @since pkcs5pkey 1.0.3
         * @deprecated From jsrsasign 4.2.1 please use {@link KEYUTIL.getKey#}.
         * @description
         * Currently, this method only supports PKCS#5v2.0 with PBES2/PBDKF2 of HmacSHA1 and TripleDES.
         * <ul>
         * <li>keyDerivationFunc = pkcs5PBKDF2 with HmacSHA1</li>
         * <li>encryptionScheme = des-EDE3-CBC(i.e. TripleDES</li>
         * </ul>
         * @example
         * // to convert plain PKCS#5 private key to encrypted PKCS#8 private
         * // key with PBKDF2 with TripleDES
         * % openssl pkcs8 -in plain_p5.pem -topk8 -v2 -des3 -out encrypted_p8.pem
         */
        getRSAKeyFromEncryptedPKCS8PEM: function(pkcs8PEM, passcode) {
            var prvKeyHex = this.getPlainPKCS8HexFromEncryptedPKCS8PEM(pkcs8PEM, passcode);
            var rsaKey = this.getRSAKeyFromPlainPKCS8Hex(prvKeyHex);
            return rsaKey;
        },

        /**
         * get RSAKey/ECDSA private key object from encrypted PEM PKCS#8 private key
         * @name getKeyFromEncryptedPKCS8PEM
         * @memberOf KEYUTIL
         * @function
         * @param {String} pkcs8PEM string of PEM formatted PKCS#8 private key
         * @param {String} passcode passcode string to decrypt key
         * @return {Object} RSAKey or KJUR.crypto.ECDSA private key object
         * @since pkcs5pkey 1.0.5
         */
        getKeyFromEncryptedPKCS8PEM: function(pkcs8PEM, passcode) {
            var prvKeyHex = this.getPlainPKCS8HexFromEncryptedPKCS8PEM(pkcs8PEM, passcode);
            var key = this.getKeyFromPlainPrivatePKCS8Hex(prvKeyHex);
            return key;
        },

        /**
         * parse hexadecimal string of plain PKCS#8 private key
         * @name parsePlainPrivatePKCS8Hex
         * @memberOf KEYUTIL
         * @function
         * @param {String} pkcs8PrvHex hexadecimal string of PKCS#8 plain private key
         * @return {Array} associative array of parsed key
         * @since pkcs5pkey 1.0.5
         * @description
         * Resulted associative array has following properties:
         * <ul>
         * <li>algoid - hexadecimal string of OID of asymmetric key algorithm</li>
         * <li>algparam - hexadecimal string of OID of ECC curve name or null</li>
         * <li>keyidx - string starting index of key in pkcs8PrvHex</li>
         * </ul>
         */
        parsePlainPrivatePKCS8Hex: function(pkcs8PrvHex) {
            var result = {};
            result.algparam = null;

            // 1. sequence
            if (pkcs8PrvHex.substr(0, 2) != "30")
                throw "malformed plain PKCS8 private key(code:001)"; // not sequence

            var a1 = ASN1HEX.getPosArrayOfChildren_AtObj(pkcs8PrvHex, 0);
            if (a1.length != 3)
                throw "malformed plain PKCS8 private key(code:002)";

            // 2. AlgID
            if (pkcs8PrvHex.substr(a1[1], 2) != "30")
                throw "malformed PKCS8 private key(code:003)"; // AlgId not sequence

            var a2 = ASN1HEX.getPosArrayOfChildren_AtObj(pkcs8PrvHex, a1[1]);
            if (a2.length != 2)
                throw "malformed PKCS8 private key(code:004)"; // AlgId not have two elements

            // 2.1. AlgID OID
            if (pkcs8PrvHex.substr(a2[0], 2) != "06")
                throw "malformed PKCS8 private key(code:005)"; // AlgId.oid is not OID

            result.algoid = ASN1HEX.getHexOfV_AtObj(pkcs8PrvHex, a2[0]);

            // 2.2. AlgID param
            if (pkcs8PrvHex.substr(a2[1], 2) == "06") {
                result.algparam = ASN1HEX.getHexOfV_AtObj(pkcs8PrvHex, a2[1]);
            }

            // 3. Key index
            if (pkcs8PrvHex.substr(a1[2], 2) != "04")
                throw "malformed PKCS8 private key(code:006)"; // not octet string

            result.keyidx = ASN1HEX.getStartPosOfV_AtObj(pkcs8PrvHex, a1[2]);

            return result;
        },

        /**
         * get RSAKey/ECDSA private key object from PEM plain PEM PKCS#8 private key
         * @name getKeyFromPlainPrivatePKCS8PEM
         * @memberOf KEYUTIL
         * @function
         * @param {String} pkcs8PEM string of plain PEM formatted PKCS#8 private key
         * @return {Object} RSAKey or KJUR.crypto.ECDSA private key object
         * @since pkcs5pkey 1.0.5
         */
        getKeyFromPlainPrivatePKCS8PEM: function(prvKeyPEM) {
            var prvKeyHex = this.getHexFromPEM(prvKeyPEM, "PRIVATE KEY");
            var key = this.getKeyFromPlainPrivatePKCS8Hex(prvKeyHex);
            return key;
        },

        /**
         * get RSAKey/ECDSA private key object from HEX plain PEM PKCS#8 private key
         * @name getKeyFromPlainPrivatePKCS8Hex
         * @memberOf KEYUTIL
         * @function
         * @param {String} prvKeyHex hexadecimal string of plain PKCS#8 private key
         * @return {Object} RSAKey or KJUR.crypto.ECDSA private key object
         * @since pkcs5pkey 1.0.5
         */
        getKeyFromPlainPrivatePKCS8Hex: function(prvKeyHex) {
            var p8 = this.parsePlainPrivatePKCS8Hex(prvKeyHex);
            
            if (p8.algoid == "2a864886f70d010101") { // RSA
                this.parsePrivateRawRSAKeyHexAtObj(prvKeyHex, p8);
                var k = p8.key;
                var key = new RSAKey();
                key.setPrivateEx(k.n, k.e, k.d, k.p, k.q, k.dp, k.dq, k.co);
                return key;
            } else if (p8.algoid == "2a8648ce3d0201") { // ECC
                this.parsePrivateRawECKeyHexAtObj(prvKeyHex, p8);
                if (KJUR.crypto.OID.oidhex2name[p8.algparam] === undefined)
                    throw "KJUR.crypto.OID.oidhex2name undefined: " + p8.algparam;
                var curveName = KJUR.crypto.OID.oidhex2name[p8.algparam];
                var key = new KJUR.crypto.ECDSA({'curve': curveName});
                key.setPublicKeyHex(p8.pubkey);
                key.setPrivateKeyHex(p8.key);
                key.isPublic = false;
                return key;
            } else if (p8.algoid == "2a8648ce380401") { // DSA
                var hP = ASN1HEX.getVbyList(prvKeyHex, 0, [1,1,0], "02");
                var hQ = ASN1HEX.getVbyList(prvKeyHex, 0, [1,1,1], "02");
                var hG = ASN1HEX.getVbyList(prvKeyHex, 0, [1,1,2], "02");
                var hX = ASN1HEX.getVbyList(prvKeyHex, 0, [2,0], "02");
                var biP = new BigInteger(hP, 16);
                var biQ = new BigInteger(hQ, 16);
                var biG = new BigInteger(hG, 16);
                var biX = new BigInteger(hX, 16);
                var key = new KJUR.crypto.DSA();
                key.setPrivate(biP, biQ, biG, null, biX);
                return key;
            } else {
                throw "unsupported private key algorithm";
            }
        },

        // === PKCS8 RSA Public Key ================================================
        /**
         * (DEPRECATED) read PEM formatted PKCS#8 public key and returns RSAKey object
         * @name getRSAKeyFromPublicPKCS8PEM
         * @memberOf KEYUTIL
         * @function
         * @param {String} pkcs8PubPEM PEM formatted PKCS#8 public key
         * @return {RSAKey} loaded RSAKey object of RSA public key
         * @since pkcs5pkey 1.0.4
         * @deprecated From jsrsasign 4.2.1 please use {@link KEYUTIL.getKey#}.
         */
        getRSAKeyFromPublicPKCS8PEM: function(pkcs8PubPEM) {
            var pubKeyHex = this.getHexFromPEM(pkcs8PubPEM, "PUBLIC KEY");
            var rsaKey = this.getRSAKeyFromPublicPKCS8Hex(pubKeyHex);
            return rsaKey;
        },

        /**
         * (DEPRECATED) get RSAKey/ECDSA public key object from PEM PKCS#8 public key
         * @name getKeyFromPublicPKCS8PEM
         * @memberOf KEYUTIL
         * @function
         * @param {String} pkcsPub8PEM string of PEM formatted PKCS#8 public key
         * @return {Object} RSAKey or KJUR.crypto.ECDSA private key object
         * @since pkcs5pkey 1.0.5
         * @deprecated From jsrsasign 4.2.1 please use {@link KEYUTIL.getKey#}.
         */
        getKeyFromPublicPKCS8PEM: function(pkcs8PubPEM) {
            var pubKeyHex = this.getHexFromPEM(pkcs8PubPEM, "PUBLIC KEY");
            var key = this.getKeyFromPublicPKCS8Hex(pubKeyHex);
            return key;
        },

        /**
         * (DEPRECATED) get RSAKey/DSA/ECDSA public key object from hexadecimal string of PKCS#8 public key
         * @name getKeyFromPublicPKCS8Hex
         * @memberOf KEYUTIL
         * @function
         * @param {String} pkcsPub8Hex hexadecimal string of PKCS#8 public key
         * @return {Object} RSAKey or KJUR.crypto.{ECDSA,DSA} private key object
         * @since pkcs5pkey 1.0.5
         * @deprecated From jsrsasign 4.2.1 please use {@link KEYUTIL.getKey#}.
         */
        getKeyFromPublicPKCS8Hex: function(pkcs8PubHex) {
            var p8 = this.parsePublicPKCS8Hex(pkcs8PubHex);
            
            if (p8.algoid == "2a864886f70d010101") { // RSA
                var aRSA = this.parsePublicRawRSAKeyHex(p8.key);
                var key = new RSAKey();
                key.setPublic(aRSA.n, aRSA.e);
                return key;
            } else if (p8.algoid == "2a8648ce3d0201") { // ECC
                if (KJUR.crypto.OID.oidhex2name[p8.algparam] === undefined)
                    throw "KJUR.crypto.OID.oidhex2name undefined: " + p8.algparam;
                var curveName = KJUR.crypto.OID.oidhex2name[p8.algparam];
                var key = new KJUR.crypto.ECDSA({'curve': curveName, 'pub': p8.key});
                return key;
            } else if (p8.algoid == "2a8648ce380401") { // DSA 1.2.840.10040.4.1
                var param = p8.algparam;
                var y = ASN1HEX.getHexOfV_AtObj(p8.key, 0);
                var key = new KJUR.crypto.DSA();
                key.setPublic(new BigInteger(param.p, 16),
                              new BigInteger(param.q, 16),
                              new BigInteger(param.g, 16),
                              new BigInteger(y, 16));
                return key;
            } else {
                throw "unsupported public key algorithm";
            }
        },

        /**
         * parse hexadecimal string of plain PKCS#8 private key
         * @name parsePublicRawRSAKeyHex
         * @memberOf KEYUTIL
         * @function
         * @param {String} pubRawRSAHex hexadecimal string of ASN.1 encoded PKCS#8 public key
         * @return {Array} associative array of parsed key
         * @since pkcs5pkey 1.0.5
         * @description
         * Resulted associative array has following properties:
         * <ul>
         * <li>n - hexadecimal string of public key
         * <li>e - hexadecimal string of public exponent
         * </ul>
         */
        parsePublicRawRSAKeyHex: function(pubRawRSAHex) {
            var result = {};
            
            // 1. Sequence
            if (pubRawRSAHex.substr(0, 2) != "30")
                throw "malformed RSA key(code:001)"; // not sequence
            
            var a1 = ASN1HEX.getPosArrayOfChildren_AtObj(pubRawRSAHex, 0);
            if (a1.length != 2)
                throw "malformed RSA key(code:002)"; // not 2 items in seq

            // 2. public key "N"
            if (pubRawRSAHex.substr(a1[0], 2) != "02")
                throw "malformed RSA key(code:003)"; // 1st item is not integer

            result.n = ASN1HEX.getHexOfV_AtObj(pubRawRSAHex, a1[0]);

            // 3. public key "E"
            if (pubRawRSAHex.substr(a1[1], 2) != "02")
                throw "malformed RSA key(code:004)"; // 2nd item is not integer

            result.e = ASN1HEX.getHexOfV_AtObj(pubRawRSAHex, a1[1]);

            return result;
        },

        /**
         * parse hexadecimal string of RSA private key
         * @name parsePrivateRawRSAKeyHexAtObj
         * @memberOf KEYUTIL
         * @function
         * @param {String} pkcs8PrvHex hexadecimal string of PKCS#8 private key concluding RSA private key
         * @return {Array} info associative array to add parsed RSA private key information
         * @since pkcs5pkey 1.0.5
         * @description
         * Following properties are added to associative array 'info'
         * <ul>
         * <li>n - hexadecimal string of public key
         * <li>e - hexadecimal string of public exponent
         * <li>d - hexadecimal string of private key
         * <li>p - hexadecimal string
         * <li>q - hexadecimal string
         * <li>dp - hexadecimal string
         * <li>dq - hexadecimal string
         * <li>co - hexadecimal string
         * </ul>
         */
        parsePrivateRawRSAKeyHexAtObj: function(pkcs8PrvHex, info) {
            var keyIdx = info.keyidx;
            
            // 1. sequence
            if (pkcs8PrvHex.substr(keyIdx, 2) != "30")
                throw "malformed RSA private key(code:001)"; // not sequence

            var a1 = ASN1HEX.getPosArrayOfChildren_AtObj(pkcs8PrvHex, keyIdx);
            if (a1.length != 9)
                throw "malformed RSA private key(code:002)"; // not sequence

            // 2. RSA key
            info.key = {};
            info.key.n = ASN1HEX.getHexOfV_AtObj(pkcs8PrvHex, a1[1]);
            info.key.e = ASN1HEX.getHexOfV_AtObj(pkcs8PrvHex, a1[2]);
            info.key.d = ASN1HEX.getHexOfV_AtObj(pkcs8PrvHex, a1[3]);
            info.key.p = ASN1HEX.getHexOfV_AtObj(pkcs8PrvHex, a1[4]);
            info.key.q = ASN1HEX.getHexOfV_AtObj(pkcs8PrvHex, a1[5]);
            info.key.dp = ASN1HEX.getHexOfV_AtObj(pkcs8PrvHex, a1[6]);
            info.key.dq = ASN1HEX.getHexOfV_AtObj(pkcs8PrvHex, a1[7]);
            info.key.co = ASN1HEX.getHexOfV_AtObj(pkcs8PrvHex, a1[8]);
        },

        /**
         * parse hexadecimal string of ECC private key
         * @name parsePrivateRawECKeyHexAtObj
         * @memberOf KEYUTIL
         * @function
         * @param {String} pkcs8PrvHex hexadecimal string of PKCS#8 private key concluding EC private key
         * @return {Array} info associative array to add parsed ECC private key information
         * @since pkcs5pkey 1.0.5
         * @description
         * Following properties are added to associative array 'info'
         * <ul>
         * <li>key - hexadecimal string of ECC private key
         * </ul>
         */
        parsePrivateRawECKeyHexAtObj: function(pkcs8PrvHex, info) {
            var keyIdx = info.keyidx;
            
            var key = ASN1HEX.getVbyList(pkcs8PrvHex, keyIdx, [1], "04");
            var pubkey = ASN1HEX.getVbyList(pkcs8PrvHex, keyIdx, [2,0], "03").substr(2);

            info.key = key;
            info.pubkey = pubkey;
        },

        /**
         * parse hexadecimal string of PKCS#8 RSA/EC/DSA public key
         * @name parsePublicPKCS8Hex
         * @memberOf KEYUTIL
         * @function
         * @param {String} pkcs8PubHex hexadecimal string of PKCS#8 public key
         * @return {Hash} hash of key information
         * @description
         * Resulted hash has following attributes.
         * <ul>
         * <li>algoid - hexadecimal string of OID of asymmetric key algorithm</li>
         * <li>algparam - hexadecimal string of OID of ECC curve name, parameter SEQUENCE of DSA or null</li>
         * <li>key - hexadecimal string of public key</li>
         * </ul>
         */
        parsePublicPKCS8Hex: function(pkcs8PubHex) {
            var result = {};
            result.algparam = null;

            // 1. AlgID and Key bit string
            var a1 = ASN1HEX.getPosArrayOfChildren_AtObj(pkcs8PubHex, 0);
            if (a1.length != 2)
                throw "outer DERSequence shall have 2 elements: " + a1.length;

            // 2. AlgID
            var idxAlgIdTLV = a1[0];
            if (pkcs8PubHex.substr(idxAlgIdTLV, 2) != "30")
                throw "malformed PKCS8 public key(code:001)"; // AlgId not sequence

            var a2 = ASN1HEX.getPosArrayOfChildren_AtObj(pkcs8PubHex, idxAlgIdTLV);
            if (a2.length != 2)
                throw "malformed PKCS8 public key(code:002)"; // AlgId not have two elements

            // 2.1. AlgID OID
            if (pkcs8PubHex.substr(a2[0], 2) != "06")
                throw "malformed PKCS8 public key(code:003)"; // AlgId.oid is not OID

            result.algoid = ASN1HEX.getHexOfV_AtObj(pkcs8PubHex, a2[0]);

            // 2.2. AlgID param
            if (pkcs8PubHex.substr(a2[1], 2) == "06") { // OID for EC
                result.algparam = ASN1HEX.getHexOfV_AtObj(pkcs8PubHex, a2[1]);
            } else if (pkcs8PubHex.substr(a2[1], 2) == "30") { // SEQ for DSA
                result.algparam = {};
                result.algparam.p = ASN1HEX.getVbyList(pkcs8PubHex, a2[1], [0], "02");
                result.algparam.q = ASN1HEX.getVbyList(pkcs8PubHex, a2[1], [1], "02");
                result.algparam.g = ASN1HEX.getVbyList(pkcs8PubHex, a2[1], [2], "02");
            }

            // 3. Key
            if (pkcs8PubHex.substr(a1[1], 2) != "03")
                throw "malformed PKCS8 public key(code:004)"; // Key is not bit string

            result.key = ASN1HEX.getHexOfV_AtObj(pkcs8PubHex, a1[1]).substr(2);
            
            // 4. return result assoc array
            return result;
        },

        /**
         * (DEPRECATED) provide hexadecimal string of unencrypted PKCS#8 private key and returns RSAKey object
         * @name getRSAKeyFromPublicPKCS8Hex
         * @memberOf KEYUTIL
         * @function
         * @param {String} pkcs8PubHex hexadecimal string of unencrypted PKCS#8 public key
         * @return {RSAKey} loaded RSAKey object of RSA public key
         * @since pkcs5pkey 1.0.4
         * @deprecated From jsrsasign 4.2.1 please use {@link KEYUTIL.getKey#}.
         */
        getRSAKeyFromPublicPKCS8Hex: function(pkcs8PubHex) {
            var a1 = ASN1HEX.getPosArrayOfChildren_AtObj(pkcs8PubHex, 0);
            if (a1.length != 2)
                throw "outer DERSequence shall have 2 elements: " + a1.length;

            var algIdTLV =ASN1HEX.getHexOfTLV_AtObj(pkcs8PubHex, a1[0]);
            if (algIdTLV != "300d06092a864886f70d0101010500") // AlgId rsaEncryption
                throw "PKCS8 AlgorithmId is not rsaEncryption";
            
            if (pkcs8PubHex.substr(a1[1], 2) != "03")
                throw "PKCS8 Public Key is not BITSTRING encapslated.";

            var idxPub = ASN1HEX.getStartPosOfV_AtObj(pkcs8PubHex, a1[1]) + 2; // 2 for unused bit
            
            if (pkcs8PubHex.substr(idxPub, 2) != "30")
                throw "PKCS8 Public Key is not SEQUENCE.";

            var a2 = ASN1HEX.getPosArrayOfChildren_AtObj(pkcs8PubHex, idxPub);
            if (a2.length != 2)
                throw "inner DERSequence shall have 2 elements: " + a2.length;

            if (pkcs8PubHex.substr(a2[0], 2) != "02") 
                throw "N is not ASN.1 INTEGER";
            if (pkcs8PubHex.substr(a2[1], 2) != "02") 
                throw "E is not ASN.1 INTEGER";
            
            var hN = ASN1HEX.getHexOfV_AtObj(pkcs8PubHex, a2[0]);
            var hE = ASN1HEX.getHexOfV_AtObj(pkcs8PubHex, a2[1]);

            var pubKey = new RSAKey();
            pubKey.setPublic(hN, hE);
            
            return pubKey;
        },

        //addAlgorithm: function(functionObject, algName, keyLen, ivLen) {
        //}
    };
}();

// -- MAJOR PUBLIC METHODS -------------------------------------------------------
/**
 * get private or public key object from any arguments
 * @name getKey
 * @memberOf KEYUTIL
 * @function
 * @static
 * @param {Object} param parameter to get key object. see description in detail.
 * @param {String} passcode (OPTION) parameter to get key object. see description in detail.
 * @param {String} hextype (OPTOIN) parameter to get key object. see description in detail.
 * @return {Object} {@link RSAKey}, {@link KJUR.crypto.ECDSA} or {@link KJUR.crypto.ECDSA} object
 * @since keyutil 1.0.0
 * @description
 * This method gets private or public key object({@link RSAKey}, {@link KJUR.crypto.DSA} or {@link KJUR.crypto.ECDSA})
 * for RSA, DSA and ECC.
 * Arguments for this methods depends on a key format you specify.
 * Following key representations are supported.
 * <ul>
 * <li>ECC private/public key object(as is): param=KJUR.crypto.ECDSA</li>
 * <li>DSA private/public key object(as is): param=KJUR.crypto.DSA</li>
 * <li>RSA private/public key object(as is): param=RSAKey </li>
 * <li>ECC private key parameters: param={d: d, curve: curveName}</li>
 * <li>RSA private key parameters: param={n: n, e: e, d: d, p: p, q: q, dp: dp, dq: dq, co: co}<br/>
 * NOTE: Each value shall be hexadecimal string of key spec.</li>
 * <li>DSA private key parameters: param={p: p, q: q, g: g, y: y, x: x}<br/>
 * NOTE: Each value shall be hexadecimal string of key spec.</li>
 * <li>ECC public key parameters: param={xy: xy, curve: curveName}<br/>
 * NOTE: ECC public key 'xy' shall be concatination of "04", x-bytes-hex and y-bytes-hex.</li>
 * <li>DSA public key parameters: param={p: p, q: q, g: g, y: y}<br/>
 * NOTE: Each value shall be hexadecimal string of key spec.</li>
 * <li>RSA public key parameters: param={n: n, e: e} </li>
 * <li>X.509v1/v3 PEM certificate (RSA/DSA/ECC): param=pemString</li>
 * <li>PKCS#8 hexadecimal RSA/ECC public key: param=pemString, null, "pkcs8pub"</li>
 * <li>PKCS#8 PEM RSA/DSA/ECC public key: param=pemString</li>
 * <li>PKCS#5 plain hexadecimal RSA private key: param=hexString, null, "pkcs5prv"</li>
 * <li>PKCS#5 plain PEM DSA/RSA private key: param=pemString</li>
 * <li>PKCS#8 plain PEM RSA/ECDSA private key: param=pemString</li>
 * <li>PKCS#5 encrypted PEM RSA/DSA private key: param=pemString, passcode</li>
 * <li>PKCS#8 encrypted PEM RSA/ECDSA private key: param=pemString, passcode</li>
 * </ul>
 * Please note following limitation on encrypted keys:
 * <ul>
 * <li>Encrypted PKCS#8 only supports PBKDF2/HmacSHA1/3DES</li>
 * <li>Encrypted PKCS#5 supports DES-CBC, DES-EDE3-CBC, AES-{128,192.256}-CBC</li>
 * <li>JWT plain ECC private/public key</li>
 * <li>JWT plain RSA public key</li>
 * <li>JWT plain RSA private key with P/Q/DP/DQ/COEFF</li>
 * <li>JWT plain RSA private key without P/Q/DP/DQ/COEFF (since jsrsasign 5.0.0)</li>
 * </ul>
 * NOTE1: <a href="https://tools.ietf.org/html/rfc7517">RFC 7517 JSON Web Key(JWK)</a> support for RSA/ECC private/public key from jsrsasign 4.8.1.<br/>
 * NOTE2: X509v1 support is added since jsrsasign 5.0.11.
 * 
 * <h5>EXAMPLE</h5>
 * @example
 * // 1. loading private key from PEM string
 * keyObj = KEYUTIL.getKey("-----BEGIN RSA PRIVATE KEY...");
 * keyObj = KEYUTIL.getKey("-----BEGIN RSA PRIVATE KEY..., "passcode");
 * keyObj = KEYUTIL.getKey("-----BEGIN PRIVATE KEY...");
 * keyObj = KEYUTIL.getKey("-----BEGIN PRIVATE KEY...", "passcode");
 * // 2. loading public key from PEM string
 * keyObj = KEYUTIL.getKey("-----BEGIN PUBLIC KEY...");
 * keyObj = KEYUTIL.getKey("-----BEGIN X509 CERTIFICATE...");
 * // 3. loading hexadecimal PKCS#5/PKCS#8 key
 * keyObj = KEYUTIL.getKey("308205c1...", null, "pkcs8pub");
 * keyObj = KEYUTIL.getKey("3082048b...", null, "pkcs5prv");
 * // 4. loading JSON Web Key(JWK)
 * keyObj = KEYUTIL.getKey({kty: "RSA", n: "0vx7...", e: "AQAB"});
 * keyObj = KEYUTIL.getKey({kty: "EC", crv: "P-256", 
 *                          x: "MKBC...", y: "4Etl6...", d: "870Mb..."});
 * // 5. bare hexadecimal key
 * keyObj = KEYUTIL.getKey({n: "75ab..", e: "010001"});
 */
KEYUTIL.getKey = function(param, passcode, hextype) {
    // 1. by key RSAKey/KJUR.crypto.ECDSA/KJUR.crypto.DSA object
    if (typeof RSAKey != 'undefined' && param instanceof RSAKey)
        return param;
    if (typeof KJUR.crypto.ECDSA != 'undefined' && param instanceof KJUR.crypto.ECDSA)
        return param;
    if (typeof KJUR.crypto.DSA != 'undefined' && param instanceof KJUR.crypto.DSA)
        return param;

    // 2. by parameters of key

    // 2.1. bare ECC
    // 2.1.1. bare ECC public key by hex values
    if (param.curve !== undefined &&
	param.xy !== undefined && param.d === undefined) {
        return new KJUR.crypto.ECDSA({pub: param.xy, curve: param.curve});
    }

    // 2.1.2. bare ECC private key by hex values
    if (param.curve !== undefined && param.d !== undefined) {
        return new KJUR.crypto.ECDSA({prv: param.d, curve: param.curve});
    }

    // 2.2. bare RSA
    // 2.2.1. bare RSA public key by hex values
    if (param.kty === undefined &&
	param.n !== undefined && param.e !== undefined &&
        param.d === undefined) {
        var key = new RSAKey();
        key.setPublic(param.n, param.e);
        return key;
    }

    // 2.2.2. bare RSA private key with P/Q/DP/DQ/COEFF by hex values
    if (param.kty === undefined &&
	param.n !== undefined &&
	param.e !== undefined &&
	param.d !== undefined &&
        param.p !== undefined &&
	param.q !== undefined &&
        param.dp !== undefined &&
	param.dq !== undefined &&
	param.co !== undefined &&
        param.qi === undefined) {
        var key = new RSAKey();
        key.setPrivateEx(param.n, param.e, param.d, param.p, param.q,
                         param.dp, param.dq, param.co);
        return key;
    }

    // 2.2.3. bare RSA public key without P/Q/DP/DQ/COEFF by hex values
    if (param.kty === undefined &&
	param.n !== undefined &&
	param.e !== undefined &&
	param.d !== undefined &&
        param.p === undefined) {
        var key = new RSAKey();
        key.setPrivate(param.n, param.e, param.d);
        return key;
    }

    // 2.3. bare DSA
    // 2.3.1. bare DSA public key by hex values
    if (param.p !== undefined && param.q !== undefined &&
	param.g !== undefined &&
        param.y !== undefined && param.x === undefined) {
        var key = new KJUR.crypto.DSA();
        key.setPublic(param.p, param.q, param.g, param.y);
        return key;
    }

    // 2.3.2. bare DSA private key by hex values
    if (param.p !== undefined && param.q !== undefined &&
	param.g !== undefined &&
        param.y !== undefined && param.x !== undefined) {
        var key = new KJUR.crypto.DSA();
        key.setPrivate(param.p, param.q, param.g, param.y, param.x);
        return key;
    }

    // 3. JWK
    // 3.1. JWK RSA
    // 3.1.1. JWK RSA public key by b64u values
    if (param.kty === "RSA" &&
	param.n !== undefined &&
	param.e !== undefined &&
	param.d === undefined) {
	var key = new RSAKey();
	key.setPublic(b64utohex(param.n), b64utohex(param.e));
	return key;
    }

    // 3.1.2. JWK RSA private key with p/q/dp/dq/coeff by b64u values
    if (param.kty === "RSA" &&
	param.n !== undefined &&
	param.e !== undefined &&
	param.d !== undefined &&
	param.p !== undefined &&
	param.q !== undefined &&
	param.dp !== undefined &&
	param.dq !== undefined &&
	param.qi !== undefined) {
	var key = new RSAKey();
        key.setPrivateEx(b64utohex(param.n),
			 b64utohex(param.e),
			 b64utohex(param.d),
			 b64utohex(param.p),
			 b64utohex(param.q),
                         b64utohex(param.dp),
			 b64utohex(param.dq),
			 b64utohex(param.qi));
	return key;
    }

    // 3.1.3. JWK RSA private key without p/q/dp/dq/coeff by b64u
    //        since jsrsasign 5.0.0 keyutil 1.0.11
    if (param.kty === "RSA" &&
	param.n !== undefined &&
	param.e !== undefined &&
	param.d !== undefined) {
	var key = new RSAKey();
        key.setPrivate(b64utohex(param.n),
		       b64utohex(param.e),
		       b64utohex(param.d));
	return key;
    }

    // 3.2. JWK ECC
    // 3.2.1. JWK ECC public key by b64u values
    if (param.kty === "EC" &&
	param.crv !== undefined &&
	param.x !== undefined &&
	param.y !== undefined &&
        param.d === undefined) {
	var ec = new KJUR.crypto.ECDSA({"curve": param.crv});
	var charlen = ec.ecparams.keylen / 4;
        var hX   = ("0000000000" + b64utohex(param.x)).slice(- charlen);
        var hY   = ("0000000000" + b64utohex(param.y)).slice(- charlen);
        var hPub = "04" + hX + hY;
	ec.setPublicKeyHex(hPub);
	return ec;
    }

    // 3.2.2. JWK ECC private key by b64u values
    if (param.kty === "EC" &&
	param.crv !== undefined &&
	param.x !== undefined &&
	param.y !== undefined &&
        param.d !== undefined) {
	var ec = new KJUR.crypto.ECDSA({"curve": param.crv});
	var charlen = ec.ecparams.keylen / 4;
        var hX   = ("0000000000" + b64utohex(param.x)).slice(- charlen);
        var hY   = ("0000000000" + b64utohex(param.y)).slice(- charlen);
        var hPub = "04" + hX + hY;
        var hPrv = ("0000000000" + b64utohex(param.d)).slice(- charlen);
	ec.setPublicKeyHex(hPub);
	ec.setPrivateKeyHex(hPrv);
	return ec;
    }
    
    // 4. by PEM certificate (-----BEGIN ... CERTIFITE----)
    if (param.indexOf("-END CERTIFICATE-", 0) != -1 ||
        param.indexOf("-END X509 CERTIFICATE-", 0) != -1 ||
        param.indexOf("-END TRUSTED CERTIFICATE-", 0) != -1) {
        return X509.getPublicKeyFromCertPEM(param);
    }

    // 4. public key by PKCS#8 hexadecimal string
    if (hextype === "pkcs8pub") {
        return KEYUTIL.getKeyFromPublicPKCS8Hex(param);
    }

    // 5. public key by PKCS#8 PEM string
    if (param.indexOf("-END PUBLIC KEY-") != -1) {
        return KEYUTIL.getKeyFromPublicPKCS8PEM(param);
    }
    
    // 6. private key by PKCS#5 plain hexadecimal RSA string
    if (hextype === "pkcs5prv") {
        var key = new RSAKey();
        key.readPrivateKeyFromASN1HexString(param);
        return key;
    }

    // 7. private key by plain PKCS#5 hexadecimal RSA string
    if (hextype === "pkcs5prv") {
        var key = new RSAKey();
        key.readPrivateKeyFromASN1HexString(param);
        return key;
    }

    // 8. private key by plain PKCS#5 PEM RSA string 
    //    getKey("-----BEGIN RSA PRIVATE KEY-...")
    if (param.indexOf("-END RSA PRIVATE KEY-") != -1 &&
        param.indexOf("4,ENCRYPTED") == -1) {
        var hex = KEYUTIL.getHexFromPEM(param, "RSA PRIVATE KEY");
        return KEYUTIL.getKey(hex, null, "pkcs5prv");
    }

    // 8.2. private key by plain PKCS#5 PEM DSA string
    if (param.indexOf("-END DSA PRIVATE KEY-") != -1 &&
        param.indexOf("4,ENCRYPTED") == -1) {

        var hKey = this.getHexFromPEM(param, "DSA PRIVATE KEY");
        var p = ASN1HEX.getVbyList(hKey, 0, [1], "02");
        var q = ASN1HEX.getVbyList(hKey, 0, [2], "02");
        var g = ASN1HEX.getVbyList(hKey, 0, [3], "02");
        var y = ASN1HEX.getVbyList(hKey, 0, [4], "02");
        var x = ASN1HEX.getVbyList(hKey, 0, [5], "02");
        var key = new KJUR.crypto.DSA();
        key.setPrivate(new BigInteger(p, 16),
                       new BigInteger(q, 16),
                       new BigInteger(g, 16),
                       new BigInteger(y, 16),
                       new BigInteger(x, 16));
        return key;
    }

    // 9. private key by plain PKCS#8 PEM ECC/RSA string
    if (param.indexOf("-END PRIVATE KEY-") != -1) {
        return KEYUTIL.getKeyFromPlainPrivatePKCS8PEM(param);
    }

    // 10. private key by encrypted PKCS#5 PEM RSA string
    if (param.indexOf("-END RSA PRIVATE KEY-") != -1 &&
        param.indexOf("4,ENCRYPTED") != -1) {
        return KEYUTIL.getRSAKeyFromEncryptedPKCS5PEM(param, passcode);
    }

    // 10.2. private key by encrypted PKCS#5 PEM ECDSA string
    if (param.indexOf("-END EC PRIVATE KEY-") != -1 &&
        param.indexOf("4,ENCRYPTED") != -1) {
        var hKey = KEYUTIL.getDecryptedKeyHex(param, passcode);

        var key = ASN1HEX.getVbyList(hKey, 0, [1], "04");
        var curveNameOidHex = ASN1HEX.getVbyList(hKey, 0, [2,0], "06");
        var pubkey = ASN1HEX.getVbyList(hKey, 0, [3,0], "03").substr(2);
        var curveName = "";

        if (KJUR.crypto.OID.oidhex2name[curveNameOidHex] !== undefined) {
            curveName = KJUR.crypto.OID.oidhex2name[curveNameOidHex];
        } else {
            throw "undefined OID(hex) in KJUR.crypto.OID: " + curveNameOidHex;
        }

        var ec = new KJUR.crypto.ECDSA({'name': curveName});
        ec.setPublicKeyHex(pubkey);
        ec.setPrivateKeyHex(key);
        ec.isPublic = false;
        return ec;
    }

    // 10.3. private key by encrypted PKCS#5 PEM DSA string
    if (param.indexOf("-END DSA PRIVATE KEY-") != -1 &&
        param.indexOf("4,ENCRYPTED") != -1) {
        var hKey = KEYUTIL.getDecryptedKeyHex(param, passcode);
        var p = ASN1HEX.getVbyList(hKey, 0, [1], "02");
        var q = ASN1HEX.getVbyList(hKey, 0, [2], "02");
        var g = ASN1HEX.getVbyList(hKey, 0, [3], "02");
        var y = ASN1HEX.getVbyList(hKey, 0, [4], "02");
        var x = ASN1HEX.getVbyList(hKey, 0, [5], "02");
        var key = new KJUR.crypto.DSA();
        key.setPrivate(new BigInteger(p, 16),
                       new BigInteger(q, 16),
                       new BigInteger(g, 16),
                       new BigInteger(y, 16),
                       new BigInteger(x, 16));
        return key;
    }

    // 11. private key by encrypted PKCS#8 hexadecimal RSA/ECDSA string
    if (param.indexOf("-END ENCRYPTED PRIVATE KEY-") != -1) {
        return KEYUTIL.getKeyFromEncryptedPKCS8PEM(param, passcode);
    }

    throw "not supported argument";
};

/**
 * @name generateKeypair
 * @memberOf KEYUTIL
 * @function
 * @static
 * @param {String} alg 'RSA' or 'EC'
 * @param {Object} keylenOrCurve key length for RSA or curve name for EC
 * @return {Array} associative array of keypair which has prvKeyObj and pubKeyObj parameters
 * @since keyutil 1.0.1
 * @description
 * This method generates a key pair of public key algorithm.
 * The result will be an associative array which has following
 * parameters:
 * <ul>
 * <li>prvKeyObj - RSAKey or ECDSA object of private key</li>
 * <li>pubKeyObj - RSAKey or ECDSA object of public key</li>
 * </ul>
 * NOTE1: As for RSA algoirthm, public exponent has fixed
 * value '0x10001'.
 * NOTE2: As for EC algorithm, supported names of curve are
 * secp256r1, secp256k1 and secp384r1.
 * NOTE3: DSA is not supported yet.
 * @example
 * var rsaKeypair = KEYUTIL.generateKeypair("RSA", 1024);
 * var ecKeypair = KEYUTIL.generateKeypair("EC", "secp256r1");
 *
 */
KEYUTIL.generateKeypair = function(alg, keylenOrCurve) {
    if (alg == "RSA") {
        var keylen = keylenOrCurve;
        var prvKey = new RSAKey();
        prvKey.generate(keylen, '10001');
        prvKey.isPrivate = true;
        prvKey.isPublic = true;
        
        var pubKey = new RSAKey();
        var hN = prvKey.n.toString(16);
        var hE = prvKey.e.toString(16);
        pubKey.setPublic(hN, hE);
        pubKey.isPrivate = false;
        pubKey.isPublic = true;
        
        var result = {};
        result.prvKeyObj = prvKey;
        result.pubKeyObj = pubKey;
        return result;
    } else if (alg == "EC") {
        var curve = keylenOrCurve;
        var ec = new KJUR.crypto.ECDSA({curve: curve});
        var keypairHex = ec.generateKeyPairHex();

        var prvKey = new KJUR.crypto.ECDSA({curve: curve});
        prvKey.setPublicKeyHex(keypairHex.ecpubhex);
        prvKey.setPrivateKeyHex(keypairHex.ecprvhex);
        prvKey.isPrivate = true;
        prvKey.isPublic = false;

        var pubKey = new KJUR.crypto.ECDSA({curve: curve});
        pubKey.setPublicKeyHex(keypairHex.ecpubhex);
        pubKey.isPrivate = false;
        pubKey.isPublic = true;

        var result = {};
        result.prvKeyObj = prvKey;
        result.pubKeyObj = pubKey;
        return result;
    } else {
        throw "unknown algorithm: " + alg;
    }
};

/**
 * get PEM formatted private or public key file from a RSA/ECDSA/DSA key object
 * @name getPEM
 * @memberOf KEYUTIL
 * @function
 * @static
 * @param {Object} keyObjOrHex key object {@link RSAKey}, {@link KJUR.crypto.ECDSA} or {@link KJUR.crypto.DSA} to encode to
 * @param {String} formatType (OPTION) output format type of "PKCS1PRV", "PKCS5PRV" or "PKCS8PRV" for private key
 * @param {String} passwd (OPTION) password to protect private key
 * @param {String} encAlg (OPTION) encryption algorithm for PKCS#5. currently supports DES-CBC, DES-EDE3-CBC and AES-{128,192,256}-CBC
 * @since keyutil 1.0.4
 * @description
 * <dl>
 * <dt><b>NOTE1:</b>
 * <dd>
 * PKCS#5 encrypted private key protection algorithm supports DES-CBC, 
 * DES-EDE3-CBC and AES-{128,192,256}-CBC
 * <dt><b>NOTE2:</b>
 * <dd>
 * OpenSSL supports
 * </dl>
 * @example
 * KEUUTIL.getPEM(publicKey) =&gt; generates PEM PKCS#8 public key 
 * KEUUTIL.getPEM(privateKey, "PKCS1PRV") =&gt; generates PEM PKCS#1 plain private key
 * KEUUTIL.getPEM(privateKey, "PKCS5PRV", "pass") =&gt; generates PEM PKCS#5 encrypted private key 
 *                                                          with DES-EDE3-CBC (DEFAULT)
 * KEUUTIL.getPEM(privateKey, "PKCS5PRV", "pass", "DES-CBC") =&gt; generates PEM PKCS#5 encrypted 
 *                                                                 private key with DES-CBC
 * KEUUTIL.getPEM(privateKey, "PKCS8PRV") =&gt; generates PEM PKCS#8 plain private key
 * KEUUTIL.getPEM(privateKey, "PKCS8PRV", "pass") =&gt; generates PEM PKCS#8 encrypted private key
 *                                                      with PBKDF2_HmacSHA1_3DES
 */
KEYUTIL.getPEM = function(keyObjOrHex, formatType, passwd, encAlg, hexType) {
    var ns1 = KJUR.asn1;
    var ns2 = KJUR.crypto;

    function _rsaprv2asn1obj(keyObjOrHex) {
        var asn1Obj = KJUR.asn1.ASN1Util.newObject({
            "seq": [
                {"int": 0 },
                {"int": {"bigint": keyObjOrHex.n}},
                {"int": keyObjOrHex.e},
                {"int": {"bigint": keyObjOrHex.d}},
                {"int": {"bigint": keyObjOrHex.p}},
                {"int": {"bigint": keyObjOrHex.q}},
                {"int": {"bigint": keyObjOrHex.dmp1}},
                {"int": {"bigint": keyObjOrHex.dmq1}},
                {"int": {"bigint": keyObjOrHex.coeff}}
            ]
        });
        return asn1Obj;
    };

    function _ecdsaprv2asn1obj(keyObjOrHex) {
        var asn1Obj2 = KJUR.asn1.ASN1Util.newObject({
            "seq": [
                {"int": 1 },
                {"octstr": {"hex": keyObjOrHex.prvKeyHex}},
                {"tag": ['a0', true, {'oid': {'name': keyObjOrHex.curveName}}]},
                {"tag": ['a1', true, {'bitstr': {'hex': '00' + keyObjOrHex.pubKeyHex}}]}
            ]
        });
        return asn1Obj2;
    };

    function _dsaprv2asn1obj(keyObjOrHex) {
        var asn1Obj = KJUR.asn1.ASN1Util.newObject({
            "seq": [
                {"int": 0 },
                {"int": {"bigint": keyObjOrHex.p}},
                {"int": {"bigint": keyObjOrHex.q}},
                {"int": {"bigint": keyObjOrHex.g}},
                {"int": {"bigint": keyObjOrHex.y}},
                {"int": {"bigint": keyObjOrHex.x}}
            ]
        });
        return asn1Obj;
    };

    // 1. public key

    // x. PEM PKCS#8 public key of RSA/ECDSA/DSA public key object
    if (((typeof RSAKey != "undefined" && keyObjOrHex instanceof RSAKey) ||
         (typeof ns2.DSA != "undefined" && keyObjOrHex instanceof ns2.DSA) ||
         (typeof ns2.ECDSA != "undefined" && keyObjOrHex instanceof ns2.ECDSA)) &&
        keyObjOrHex.isPublic == true &&
        (formatType === undefined || formatType == "PKCS8PUB")) {
        var asn1Obj = new KJUR.asn1.x509.SubjectPublicKeyInfo(keyObjOrHex);
        var asn1Hex = asn1Obj.getEncodedHex();
        return ns1.ASN1Util.getPEMStringFromHex(asn1Hex, "PUBLIC KEY");
    }
    
    // 2. private

    // x. PEM PKCS#1 plain private key of RSA private key object
    if (formatType == "PKCS1PRV" &&
        typeof RSAKey != "undefined" &&
        keyObjOrHex instanceof RSAKey &&
        (passwd === undefined || passwd == null) &&
        keyObjOrHex.isPrivate  == true) {

        var asn1Obj = _rsaprv2asn1obj(keyObjOrHex);
        var asn1Hex = asn1Obj.getEncodedHex();
        return ns1.ASN1Util.getPEMStringFromHex(asn1Hex, "RSA PRIVATE KEY");
    }

    // x. PEM PKCS#1 plain private key of ECDSA private key object
    if (formatType == "PKCS1PRV" &&
        typeof RSAKey != "undefined" &&
        keyObjOrHex instanceof KJUR.crypto.ECDSA &&
        (passwd === undefined || passwd == null) &&
        keyObjOrHex.isPrivate  == true) {

        var asn1Obj1 = new KJUR.asn1.DERObjectIdentifier({'name': keyObjOrHex.curveName});
        var asn1Hex1 = asn1Obj1.getEncodedHex();
        var asn1Obj2 = _ecdsaprv2asn1obj(keyObjOrHex);
        var asn1Hex2 = asn1Obj2.getEncodedHex();

        var s = "";
        s += ns1.ASN1Util.getPEMStringFromHex(asn1Hex1, "EC PARAMETERS");
        s += ns1.ASN1Util.getPEMStringFromHex(asn1Hex2, "EC PRIVATE KEY");
        return s;
    }

    // x. PEM PKCS#1 plain private key of DSA private key object
    if (formatType == "PKCS1PRV" &&
        typeof KJUR.crypto.DSA != "undefined" &&
        keyObjOrHex instanceof KJUR.crypto.DSA &&
        (passwd === undefined || passwd == null) &&
        keyObjOrHex.isPrivate  == true) {

        var asn1Obj = _dsaprv2asn1obj(keyObjOrHex);
        var asn1Hex = asn1Obj.getEncodedHex();
        return ns1.ASN1Util.getPEMStringFromHex(asn1Hex, "DSA PRIVATE KEY");
    }

    // 3. private

    // x. PEM PKCS#5 encrypted private key of RSA private key object
    if (formatType == "PKCS5PRV" &&
        typeof RSAKey != "undefined" &&
        keyObjOrHex instanceof RSAKey &&
        (passwd !== undefined && passwd != null) &&
        keyObjOrHex.isPrivate  == true) {

        var asn1Obj = _rsaprv2asn1obj(keyObjOrHex);
        var asn1Hex = asn1Obj.getEncodedHex();

        if (encAlg === undefined) encAlg = "DES-EDE3-CBC";
        return this.getEncryptedPKCS5PEMFromPrvKeyHex("RSA", asn1Hex, passwd, encAlg);
    }

    // x. PEM PKCS#5 encrypted private key of ECDSA private key object
    if (formatType == "PKCS5PRV" &&
        typeof KJUR.crypto.ECDSA != "undefined" &&
        keyObjOrHex instanceof KJUR.crypto.ECDSA &&
        (passwd !== undefined && passwd != null) &&
        keyObjOrHex.isPrivate  == true) {

        var asn1Obj = _ecdsaprv2asn1obj(keyObjOrHex);
        var asn1Hex = asn1Obj.getEncodedHex();

        if (encAlg === undefined) encAlg = "DES-EDE3-CBC";
        return this.getEncryptedPKCS5PEMFromPrvKeyHex("EC", asn1Hex, passwd, encAlg);
    }

    // x. PEM PKCS#5 encrypted private key of DSA private key object
    if (formatType == "PKCS5PRV" &&
        typeof KJUR.crypto.DSA != "undefined" &&
        keyObjOrHex instanceof KJUR.crypto.DSA &&
        (passwd !== undefined && passwd != null) &&
        keyObjOrHex.isPrivate  == true) {

        var asn1Obj = _dsaprv2asn1obj(keyObjOrHex);
        var asn1Hex = asn1Obj.getEncodedHex();

        if (encAlg === undefined) encAlg = "DES-EDE3-CBC";
        return this.getEncryptedPKCS5PEMFromPrvKeyHex("DSA", asn1Hex, passwd, encAlg);
    }

    // x. ======================================================================

    var _getEncryptedPKCS8 = function(plainKeyHex, passcode) {
        var info = _getEencryptedPKCS8Info(plainKeyHex, passcode);
        //alert("iv=" + info.encryptionSchemeIV);
        //alert("info.ciphertext2[" + info.ciphertext.length + "=" + info.ciphertext);
        var asn1Obj = new KJUR.asn1.ASN1Util.newObject({
            "seq": [
                {"seq": [
                    {"oid": {"name": "pkcs5PBES2"}},
                    {"seq": [
                        {"seq": [
                            {"oid": {"name": "pkcs5PBKDF2"}},
                            {"seq": [
                                {"octstr": {"hex": info.pbkdf2Salt}},
                                {"int": info.pbkdf2Iter}
                            ]}
                        ]},
                        {"seq": [
                            {"oid": {"name": "des-EDE3-CBC"}},
                            {"octstr": {"hex": info.encryptionSchemeIV}}
                        ]}
                    ]}
                ]},
                {"octstr": {"hex": info.ciphertext}}
            ]
        });
        return asn1Obj.getEncodedHex();
    };

    var _getEencryptedPKCS8Info = function(plainKeyHex, passcode) {
        var pbkdf2Iter = 100;
        var pbkdf2SaltWS = CryptoJS.lib.WordArray.random(8);
        var encryptionSchemeAlg = "DES-EDE3-CBC";
        var encryptionSchemeIVWS = CryptoJS.lib.WordArray.random(8);
        // PBKDF2 key
        var pbkdf2KeyWS = CryptoJS.PBKDF2(passcode, 
                                          pbkdf2SaltWS, { "keySize": 192/32,
                                                          "iterations": pbkdf2Iter });
        // ENCRYPT
        var plainKeyWS = CryptoJS.enc.Hex.parse(plainKeyHex);
        var encryptedKeyHex = 
            CryptoJS.TripleDES.encrypt(plainKeyWS, pbkdf2KeyWS, { "iv": encryptionSchemeIVWS }) + "";

        //alert("encryptedKeyHex=" + encryptedKeyHex);

        var info = {};
        info.ciphertext = encryptedKeyHex;
        //alert("info.ciphertext=" + info.ciphertext);
        info.pbkdf2Salt = CryptoJS.enc.Hex.stringify(pbkdf2SaltWS);
        info.pbkdf2Iter = pbkdf2Iter;
        info.encryptionSchemeAlg = encryptionSchemeAlg;
        info.encryptionSchemeIV = CryptoJS.enc.Hex.stringify(encryptionSchemeIVWS);
        return info;
    };

    // x. PEM PKCS#8 plain private key of RSA private key object
    if (formatType == "PKCS8PRV" &&
        typeof RSAKey != "undefined" &&
        keyObjOrHex instanceof RSAKey &&
        keyObjOrHex.isPrivate  == true) {

        var keyObj = _rsaprv2asn1obj(keyObjOrHex);
        var keyHex = keyObj.getEncodedHex();

        var asn1Obj = KJUR.asn1.ASN1Util.newObject({
            "seq": [
                {"int": 0},
                {"seq": [{"oid": {"name": "rsaEncryption"}},{"null": true}]},
                {"octstr": {"hex": keyHex}}
            ]
        });
        var asn1Hex = asn1Obj.getEncodedHex();

        if (passwd === undefined || passwd == null) {
            return ns1.ASN1Util.getPEMStringFromHex(asn1Hex, "PRIVATE KEY");
        } else {
            var asn1Hex2 = _getEncryptedPKCS8(asn1Hex, passwd);
            return ns1.ASN1Util.getPEMStringFromHex(asn1Hex2, "ENCRYPTED PRIVATE KEY");
        }
    }

    // x. PEM PKCS#8 plain private key of ECDSA private key object
    if (formatType == "PKCS8PRV" &&
        typeof KJUR.crypto.ECDSA != "undefined" &&
        keyObjOrHex instanceof KJUR.crypto.ECDSA &&
        keyObjOrHex.isPrivate  == true) {

        var keyObj = new KJUR.asn1.ASN1Util.newObject({
            "seq": [
                {"int": 1},
                {"octstr": {"hex": keyObjOrHex.prvKeyHex}},
                {"tag": ['a1', true, {"bitstr": {"hex": "00" + keyObjOrHex.pubKeyHex}}]}
            ]
        });
        var keyHex = keyObj.getEncodedHex();

        var asn1Obj = KJUR.asn1.ASN1Util.newObject({
            "seq": [
                {"int": 0},
                {"seq": [
                    {"oid": {"name": "ecPublicKey"}},
                    {"oid": {"name": keyObjOrHex.curveName}}
                ]},
                {"octstr": {"hex": keyHex}}
            ]
        });

        var asn1Hex = asn1Obj.getEncodedHex();
        if (passwd === undefined || passwd == null) {
            return ns1.ASN1Util.getPEMStringFromHex(asn1Hex, "PRIVATE KEY");
        } else {
            var asn1Hex2 = _getEncryptedPKCS8(asn1Hex, passwd);
            return ns1.ASN1Util.getPEMStringFromHex(asn1Hex2, "ENCRYPTED PRIVATE KEY");
        }
    }

    // x. PEM PKCS#8 plain private key of DSA private key object
    if (formatType == "PKCS8PRV" &&
        typeof KJUR.crypto.DSA != "undefined" &&
        keyObjOrHex instanceof KJUR.crypto.DSA &&
        keyObjOrHex.isPrivate  == true) {

        var keyObj = new KJUR.asn1.DERInteger({'bigint': keyObjOrHex.x});
        var keyHex = keyObj.getEncodedHex();

        var asn1Obj = KJUR.asn1.ASN1Util.newObject({
            "seq": [
                {"int": 0},
                {"seq": [
                    {"oid": {"name": "dsa"}},
                    {"seq": [
                        {"int": {"bigint": keyObjOrHex.p}},
                        {"int": {"bigint": keyObjOrHex.q}},
                        {"int": {"bigint": keyObjOrHex.g}}
                    ]}
                ]},
                {"octstr": {"hex": keyHex}}
            ]
        });

        var asn1Hex = asn1Obj.getEncodedHex();
        if (passwd === undefined || passwd == null) {
            return ns1.ASN1Util.getPEMStringFromHex(asn1Hex, "PRIVATE KEY");
        } else {
            var asn1Hex2 = _getEncryptedPKCS8(asn1Hex, passwd);
            return ns1.ASN1Util.getPEMStringFromHex(asn1Hex2, "ENCRYPTED PRIVATE KEY");
        }
    }

    throw "unsupported object nor format";
};

// -- PUBLIC METHODS FOR CSR -------------------------------------------------------

/**
 * get RSAKey/DSA/ECDSA public key object from PEM formatted PKCS#10 CSR string
 * @name getKeyFromCSRPEM
 * @memberOf KEYUTIL
 * @function
 * @param {String} csrPEM PEM formatted PKCS#10 CSR string
 * @return {Object} RSAKey/DSA/ECDSA public key object
 * @since keyutil 1.0.5
 */
KEYUTIL.getKeyFromCSRPEM = function(csrPEM) {
    var csrHex = KEYUTIL.getHexFromPEM(csrPEM, "CERTIFICATE REQUEST");
    var key = KEYUTIL.getKeyFromCSRHex(csrHex);
    return key;
};

/**
 * get RSAKey/DSA/ECDSA public key object from hexadecimal string of PKCS#10 CSR
 * @name getKeyFromCSRHex
 * @memberOf KEYUTIL
 * @function
 * @param {String} csrHex hexadecimal string of PKCS#10 CSR
 * @return {Object} RSAKey/DSA/ECDSA public key object
 * @since keyutil 1.0.5
 */
KEYUTIL.getKeyFromCSRHex = function(csrHex) {
    var info = KEYUTIL.parseCSRHex(csrHex);
    var key = KEYUTIL.getKey(info.p8pubkeyhex, null, "pkcs8pub");
    return key;
};

/**
 * parse hexadecimal string of PKCS#10 CSR (certificate signing request)
 * @name parseCSRHex
 * @memberOf KEYUTIL
 * @function
 * @param {String} csrHex hexadecimal string of PKCS#10 CSR
 * @return {Array} associative array of parsed CSR
 * @since keyutil 1.0.5
 * @description
 * Resulted associative array has following properties:
 * <ul>
 * <li>p8pubkeyhex - hexadecimal string of subject public key in PKCS#8</li>
 * </ul>
 */
KEYUTIL.parseCSRHex = function(csrHex) {
    var result = {};
    var h = csrHex;

    // 1. sequence
    if (h.substr(0, 2) != "30")
        throw "malformed CSR(code:001)"; // not sequence

    var a1 = ASN1HEX.getPosArrayOfChildren_AtObj(h, 0);
    if (a1.length < 1)
        throw "malformed CSR(code:002)"; // short length

    // 2. 2nd sequence
    if (h.substr(a1[0], 2) != "30")
        throw "malformed CSR(code:003)"; // not sequence

    var a2 = ASN1HEX.getPosArrayOfChildren_AtObj(h, a1[0]);
    if (a2.length < 3)
        throw "malformed CSR(code:004)"; // 2nd seq short elem

    result.p8pubkeyhex = ASN1HEX.getHexOfTLV_AtObj(h, a2[2]);

    return result;
};

// -- OTHER STATIC PUBLIC METHODS  -------------------------------------------------

/**
 * convert from RSAKey/KJUR.crypto.ECDSA public/private key object to RFC 7517 JSON Web Key(JWK)
 * @name getJWKFromKey
 * @memberOf KEYUTIL
 * @function
 * @static
 * @param {Object} RSAKey/KJUR.crypto.ECDSA public/private key object
 * @return {Object} JWK object
 * @since keyutil 1.0.13 jsrsasign 5.0.14
 * @description
 * This static method convert from RSAKey/KJUR.crypto.ECDSA public/private key object 
 * to RFC 7517 JSON Web Key(JWK)
 * @example
 * kp1 = KEYUTIL.generateKeypair("EC", "P-256");
 * jwkPrv1 = KEYUTIL.getJWKFromKey(kp1.prvKeyObj);
 * jwkPub1 = KEYUTIL.getJWKFromKey(kp1.pubKeyObj);
 *
 * kp2 = KEYUTIL.generateKeypair("RSA", 2048);
 * jwkPrv2 = KEYUTIL.getJWKFromKey(kp2.prvKeyObj);
 * jwkPub2 = KEYUTIL.getJWKFromKey(kp2.pubKeyObj);
 *
 * // if you need RFC 7636 JWK thumprint as kid do like this:
 * jwkPub2.kid = KJUR.jws.JWS.getJWKthumbprint(jwkPub2);
 */
KEYUTIL.getJWKFromKey = function(keyObj) {
    var jwk = {};
    if (keyObj instanceof RSAKey && keyObj.isPrivate) {
	jwk.kty = "RSA";
	jwk.n = hextob64u(keyObj.n.toString(16));
	jwk.e = hextob64u(keyObj.e.toString(16));
	jwk.d = hextob64u(keyObj.d.toString(16));
	jwk.p = hextob64u(keyObj.p.toString(16));
	jwk.q = hextob64u(keyObj.q.toString(16));
	jwk.dp = hextob64u(keyObj.dmp1.toString(16));
	jwk.dq = hextob64u(keyObj.dmq1.toString(16));
	jwk.qi = hextob64u(keyObj.coeff.toString(16));
	return jwk;
    } else if (keyObj instanceof RSAKey && keyObj.isPublic) {
	jwk.kty = "RSA";
	jwk.n = hextob64u(keyObj.n.toString(16));
	jwk.e = hextob64u(keyObj.e.toString(16));
	return jwk;
    } else if (keyObj instanceof KJUR.crypto.ECDSA && keyObj.isPrivate) {
	var name = keyObj.getShortNISTPCurveName();
	if (name !== "P-256" && name !== "P-384")
	    throw "unsupported curve name for JWT: " + name;
	var xy = keyObj.getPublicKeyXYHex();
	jwk.kty = "EC";
	jwk.crv =  name;
	jwk.x = hextob64u(xy.x);
	jwk.y = hextob64u(xy.y);
	jwk.d = hextob64u(keyObj.prvKeyHex);
	return jwk;
    } else if (keyObj instanceof KJUR.crypto.ECDSA && keyObj.isPublic) {
	var name = keyObj.getShortNISTPCurveName();
	if (name !== "P-256" && name !== "P-384")
	    throw "unsupported curve name for JWT: " + name;
	var xy = keyObj.getPublicKeyXYHex();
	jwk.kty = "EC";
	jwk.crv =  name;
	jwk.x = hextob64u(xy.x);
	jwk.y = hextob64u(xy.y);
	return jwk;
    }
    throw "not supported key object";
};


