(function() {
  var indexOf = [].indexOf || function(item) { for (var i = 0, l = this.length; i < l; i++) { if (i in this && this[i] === item) return i; } return -1; };

  window.AsmodeeNet = (function() {
    var access_hash, access_token, authorized, catHashCheck, checkDisplayOptions, checkErrors, checkLogoutRedirect, checkTokens, clearCookies, clearItems, code, defaultErrorCallback, defaultSuccessCallback, deleteCookie, disconnect, discovery_obj, getCookie, getCryptoValue, getItem, id_token, identity_obj, jwks, localStorageIsOk, nonce, oauth, oauthpopup, removeItem, setCookie, setItem, settings, signinCallback, state;
    settings = {
      base_is_host: 'https://account.asmodee.net',
      base_is_path: '/main/v2/oauth',
      logout_endpoint: '/main/v2/logout',
      base_url: 'https://api.asmodee.net/main/v1',
      client_id: null,
      redirect_uri: null,
      cancel_uri: null,
      logout_redirect_uri: null,
      callback_post_logout_redirect: null,
      scope: 'openid+profile',
      response_type: 'id_token token',
      display: 'popup',
      display_options: {},
      callback_signin_success: defaultSuccessCallback,
      callback_signin_error: defaultErrorCallback
    };
    state = nonce = null;
    access_token = id_token = access_hash = identity_obj = discovery_obj = jwks = code = null;
    checkErrors = [];
    localStorageIsOk = null;
    getCryptoValue = function() {
      var crypto, key, res, rnd, value;
      crypto = window.crypto || window.msCrypto;
      rnd = 0;
      res = [];
      if (crypto) {
        rnd = crypto.getRandomValues(new Uint8Array(30));
      } else {
        rnd = [Math.random()];
      }
      if (rnd.constructor === Array) {
        rnd.forEach(function(r) {
          return res.push(r.toString(36));
        });
      } else {
        for (key in rnd) {
          value = rnd[key];
          if (rnd.hasOwnProperty(key)) {
            res.push(value.toString(36));
          }
        }
      }
      return (res.join('') + '00000000000000000').slice(2, 16 + 2);
    };
    disconnect = function(callback) {
      if (callback == null) {
        callback = false;
      }
      clearItems();
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
      var alg, at_dec, at_head, it_dec, it_head, j, key, len;
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
        if (nonce && (it_dec.nonce !== nonce)) {
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
        if (hash.code && typeof it_dec.c_hash === 'string' && !catHashCheck(it_dec.c_hash, hash.code)) {
          checkErrors.push('Invalid c_hash');
          return false;
        }
        alg = [it_head.alg];
        for (j = 0, len = jwks.length; j < len; j++) {
          key = jwks[j];
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
          if ((found_state === getItem('logout_state')) || (!found_state && !getItem('logout_state'))) {
            removeItem('logout_state');
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
      var hash, item, j, l, len, len1, splitted, t;
      item = getItem('gd_connect_hash');
      if (!item) {
        if (settings.display === 'popup') {
          return settings.callback_signin_error("popup closed without signin");
        }
      } else {
        removeItem('gd_connect_hash');
        hash = {};
        splitted = null;
        if (item.search(/^#/) === 0) {
          splitted = item.replace(/^#/, '').split('&');
          for (j = 0, len = splitted.length; j < len; j++) {
            t = splitted[j];
            t = t.split('=');
            hash[t[0]] = t[1];
          }
          if (hash.token_type && hash.token_type === 'bearer') {
            state = getItem('state');
            nonce = getItem('nonce');
            if (hash.state && hash.state === state) {
              hash.scope = hash.scope.split('+');
              checkErrors = [];
              if (checkTokens(nonce, hash)) {
                removeItem('state');
                removeItem('nonce');
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
          for (l = 0, len1 = splitted.length; l < len1; l++) {
            t = splitted[l];
            t = t.split('=');
            hash[t[0]] = t[1];
          }
          if (hash.state && hash.state === state) {
            return settings.callback_signin_error(hash.error + ' : ' + hash.error_description.replace(/\+/g, ' '));
          }
        }
      }
    };
    checkDisplayOptions = function() {
      var opt, ref, ref1, tmpopts, val;
      if (Object.keys(settings.display_options).length > 0) {
        if ((ref = settings.display) === 'touch' || ref === 'popup') {
          tmpopts = {
            noheader: false,
            nofooter: false,
            lnk2bt: false,
            leglnk: true
          };
          ref1 = settings.display_options;
          for (opt in ref1) {
            val = ref1[opt];
            if (indexOf.call(Object.keys(tmpopts), opt) < 0) {
              delete settings.display_options[opt];
            }
          }
          if (Object.keys(settings.display_options).length > 0) {
            settings.display_options = AsmodeeNet.extend(tmpopts, settings.display_options);
          }
        } else {
          settings.display_options = {};
        }
      }
      if (settings.display === 'touch') {
        if (Object.keys(settings.display_options).length === 0) {
          settings.display_options = {
            noheader: true,
            nofooter: true,
            lnk2bt: true,
            leglnk: false
          };
        }
        if (!settings.cancel_uri) {
          return settings.cancel_uri = settings.redirect_uri;
        }
      }
    };
    setCookie = function(name, value, secondes) {
      var date, expires;
      if (secondes) {
        date = new Date();
        date.setTime(date.getTime() + (secondes * 1000));
        expires = "; expires=" + date.toGMTString();
      } else {
        expires = "";
      }
      return document.cookie = name + "=" + value + expires + "; path=/";
    };
    getCookie = function(name) {
      var c, ca, i, nameEQ;
      nameEQ = name + "=";
      ca = document.cookie.split(";");
      i = 0;
      while (i < ca.length) {
        c = ca[i];
        while (c.charAt(0) === " ") {
          c = c.substring(1, c.length);
        }
        if (c.indexOf(nameEQ) === 0) {
          return c.substring(nameEQ.length, c.length);
        }
        i++;
      }
      return null;
    };
    deleteCookie = function(name) {
      return setCookie(name, "", -1);
    };
    clearCookies = function() {
      var cookie, cookieBase, cookies, j, len, pathBits, results;
      cookies = document.cookie.split('; ');
      results = [];
      for (j = 0, len = cookies.length; j < len; j++) {
        cookie = cookies[j];
        cookieBase = encodeURIComponent(cookie.split(";")[0].split("=")[0]) + '=; expires=Thu, 01-Jan-1970 00:00:01 GMT; domain=' + d.join('.') + ' ;path=';
        pathBits = location.pathname.split('/');
        results.push((function() {
          var results1;
          results1 = [];
          while (pathBits.length > 0) {
            document.cookie = cookieBase + pathBits.join('/');
            results1.push(pathBits.pop());
          }
          return results1;
        })());
      }
      return results;
    };
    setItem = function(name, value, minutes) {
      var error, error1;
      try {
        return store.set(name, value, new Date().getTime() + minutes);
      } catch (error1) {
        error = error1;
        return console.error("SetItem '" + name + "'", value, error);
      }
    };
    getItem = function(name) {
      var error, error1;
      try {
        return store.get(name);
      } catch (error1) {
        error = error1;
        console.error("GetItem '" + name + "'", error);
        return null;
      }
    };
    removeItem = function(name) {
      return store.remove(name);
    };
    clearItems = function() {
      return store.clearAll();
    };
    return {
      init: function(options) {
        settings = this.extend(settings, options);
        checkDisplayOptions();
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
      isJwksDone: function() {
        return jwks !== null;
      },
      getConfiguredScope: function() {
        return settings.scope;
      },
      getConfiguredAPI: function() {
        return settings.base_url;
      },
      getClientId: function() {
        return settings.client_id;
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
      ajaxq: function(type, url, options) {
        var base_url, sets;
        if (options == null) {
          options = {};
        }
        base_url = options.base_url || settings.base_url;
        delete options.base_url;
        sets = this.extend(options, this.baseSettings(), {
          type: type
        });
        if (options.auth !== void 0 && options.auth === false) {
          if (sets.headers.Authorization) {
            delete sets.headers.Authorization;
          }
          delete sets.auth;
        }
        return this.ajax(base_url + url, sets);
      },
      get: function(url, options) {
        return this.ajaxq('GET', url, options);
      },
      post: function(url, options) {
        return this.ajaxq('POST', url, options);
      },
      update: function(url, options) {
        return this.ajaxq('PUT', url, options);
      },
      "delete": function(url, options) {
        return this.ajaxq('DELETE', url, options);
      },
      discover: function(host_port) {
        var gameThis;
        host_port = host_port || settings.base_is_host;
        gameThis = this;
        return this.get('/.well-known/openid-configuration', {
          base_url: host_port,
          auth: false,
          success: function(data) {
            if (typeof data === 'object') {
              discovery_obj = data;
            } else {
              discovery_obj = JSON.parse(data);
            }
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
            if (typeof data === 'object') {
              jwks = data.keys;
            } else {
              jwks = JSON.parse(data).keys;
            }
            if (settings.display !== 'popup') {
              return signinCallback(gameThis);
            }
          },
          error: function() {
            console.error("error JWKS", arguments);
            if (arguments.length > 0) {
              console.error("error JWKS => " + arguments[0]);
            }
            if (arguments.length > 0) {
              return console.error("error JWKS => " + arguments[0].statusText);
            }
          }
        });
      },
      signIn: function(options) {
        var gameThis, k, ref, v;
        state = getCryptoValue();
        nonce = getCryptoValue();
        setItem('state', state, 100);
        setItem('nonce', nonce, 100);
        settings.callback_signin_success = options.success || settings.callback_signin_success;
        settings.callback_signin_error = options.error || settings.callback_signin_error;
        options.path = this.auth_endpoint() + '?display=' + settings.display + '&response_type=' + encodeURI(settings.response_type) + '&state=' + state + '&client_id=' + settings.client_id + '&scope=' + settings.scope;
        if (settings.redirect_uri) {
          options.path += '&redirect_uri=' + encodeURI(settings.redirect_uri);
        }
        if (settings.response_type.search('id_token') >= 0) {
          options.path += '&nonce=' + nonce;
        }
        if (Object.keys(settings.display_options).length > 0) {
          ref = settings.display_options;
          for (k in ref) {
            v = ref[k];
            options.path += '&display_opts[' + k + ']=' + (v ? '1' : '0');
          }
        }
        if (settings.cancel_uri) {
          options.path += '&cancel_uri=' + encodeURI(settings.cancel_uri);
        }
        gameThis = this;
        options.callback = function() {
          var hash, item, j, l, len, len1, splitted, t;
          item = getItem('gd_connect_hash');
          if (!item) {
            if (settings.display === 'popup') {
              return settings.callback_signin_error("popup closed without signin");
            }
          } else {
            removeItem('gd_connect_hash');
            hash = {};
            splitted = null;
            if (item.search(/^#/) === 0) {
              splitted = item.replace(/^#/, '').split('&');
              for (j = 0, len = splitted.length; j < len; j++) {
                t = splitted[j];
                t = t.split('=');
                hash[t[0]] = t[1];
              }
              if (hash.token_type && hash.token_type === 'bearer') {
                state = getItem('state');
                nonce = getItem('nonce');
                if (hash.state && hash.state === state) {
                  hash.scope = hash.scope.split('+');
                  checkErrors = [];
                  if (checkTokens(nonce, hash)) {
                    removeItem('state');
                    removeItem('nonce');
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
              for (l = 0, len1 = splitted.length; l < len1; l++) {
                t = splitted[l];
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
        if (!this.isConnected()) {
          if (options && options.error) {
            options.error('Identity error. Not connected', null, null, 'Not Connected');
          } else {
            console.error('identity error', 'You\'re not connected');
          }
          return false;
        }
        if (this.isConnected() && identity_obj) {
          if (options && options.success) {
            return options.success(identity_obj, AsmodeeNet.getCode());
          }
        } else {
          return this.get('', {
            base_url: this.ident_endpoint(),
            success: function(data) {
              identity_obj = data;
              if (options && options.success) {
                return options.success(identity_obj, AsmodeeNet.getCode());
              }
            },
            error: function(context, xhr, type, error) {
              if (options && options.error) {
                return options.error(context, xhr, type, error);
              } else {
                return console.error('identity error', context, xhr, type, error);
              }
            }
          });
        }
      },
      restoreTokens: function(saved_access_token, saved_id_token, call_identity, cbdone) {
        var hash;
        if (call_identity == null) {
          call_identity = true;
        }
        if (cbdone == null) {
          cbdone = null;
        }
        if (saved_access_token && access_token) {
          saved_access_token = null;
        }
        if (saved_id_token && id_token) {
          id_token = null;
        }
        if (saved_access_token) {
          hash = {
            access_token: saved_access_token,
            id_token: saved_id_token
          };
          if (this.isJwksDone()) {
            if (checkTokens(null, hash)) {
              authorized(hash);
              if (call_identity) {
                this.identity({
                  success: settings.callback_signin_success,
                  error: settings.callback_signin_error
                });
              }
              if (cbdone) {
                cbdone(true);
              } else {
                return true;
              }
            } else {
              if (cbdone) {
                cbdone(false);
              } else {
                return false;
              }
            }
          } else {
            setTimeout(function() {
              return AsmodeeNet.restoreTokens(saved_access_token, saved_id_token, call_identity, cbdone);
            }, 200);
          }
        }
        return null;
      },
      setAccessToken: function(saved_access_token) {
        return access_token = saved_access_token;
      },
      setIdToken: function(save_id_token) {
        return id_token = save_id_token;
      },
      signOut: function(options) {
        if (this.isConnected()) {
          if (settings.logout_redirect_uri) {
            state = getCryptoValue();
            setItem('logout_state', state, 100);
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
          setItem('gd_connect_hash', window.location.hash, 100);
        } else if (window.location.search !== "") {
          setItem('gd_connect_hash', window.location.search, 100);
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
