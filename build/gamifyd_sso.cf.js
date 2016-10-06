(function() {
  window.GamifyDigital = (function() {
    var access_hash, access_token, authorized, checkTokens, disconnect, discovery_obj, id_token, identity_obj, jwks, oauthpopup, settings;
    settings = {
      base_is_host: 'https://account.playreal.live',
      base_is_path: '/main/v2/oauth',
      base_url: 'https://api.playreal.live/main/v1',
      client_id: null,
      redirect_uri: null,
      scope: 'openid+profile',
      response_type: 'token'
    };
    access_token = id_token = access_hash = identity_obj = discovery_obj = jwks = null;
    disconnect = function(callback) {
      if (callback == null) {
        callback = false;
      }
      window.localStorage.clear();
      access_token = id_token = access_hash = identity_obj = null;
      if (callback) {
        return callback();
      } else {
        return window.location.reload();
      }
    };
    oauthpopup = function(options) {
      var that;
      if (options.windowName == null) {
        options.windowName = 'GamifyConnectWithOAuth';
      }
      if (options.windowOptions == null) {
        options.windowOptions = 'location=0,status=0,width=400,height=800';
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
        if (that._oauthWindow && that._oauthWindow.closed) {
          if (that._oauthInterval) {
            window.clearInterval(that._oauthInterval);
          }
          options.callback();
          if (that._oauthAutoCloseInterval) {
            return window.clearInterval(that._oauthAutoCloseInterval);
          }
        }
      }, 1000);
    };
    authorized = function(access_hash_clt) {
      access_hash = access_hash_clt;
      access_token = access_hash.access_token;
      return id_token = access_hash.id_token;
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
          return false;
        }
        if (it_head.alg !== 'RS256') {
          return false;
        }
        if (it_dec.nonce !== nonce) {
          return false;
        }
        if (it_dec.iss !== settings.base_is_host) {
          return false;
        }
        if (it_dec.aud !== settings.client_id) {
          return false;
        }
        if (it_dec.exp < (Date.now() / 1000).toPrecision(10)) {
          return false;
        }
        alg = [it_head.alg];
        for (i = 0, len = jwks.length; i < len; i++) {
          key = jwks[i];
          if (KJUR.jws.JWS.verify(hash.id_token, KEYUTIL.getKey(key), alg)) {
            return true;
          }
        }
        return false;
      }
      return true;
    };
    return {
      init: function(options) {
        settings = this.extend(settings, options);
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
            return gameThis.getJwks();
          },
          error: function() {
            return console.log("error Discovery ", arguments);
          }
        });
      },
      getJwks: function() {
        return this.get('', {
          base_url: discovery_obj.jwks_uri,
          auth: false,
          success: function(data) {
            return jwks = data.keys;
          },
          error: function() {
            return console.log("error JWKS", arguments);
          }
        });
      },
      signIn: function(options) {
        var error_cb, gameThis, main_cb, nonce, pr_callback, state;
        state = (Math.random().toString(36) + '00000000000000000').slice(2, 16 + 2);
        nonce = (Math.random().toString(36) + '00000000000000000').slice(2, 16 + 2);
        main_cb = options.success || function() {
          return console.log(arguments);
        };
        error_cb = options.error || function() {
          return console.log('error', arguments);
        };
        options.path = this.auth_endpoint() + '?response_type=' + encodeURI(settings.response_type) + '&state=' + state + '&client_id=' + settings.client_id + '&redirect_uri=' + encodeURI(settings.redirect_uri) + '&scope=' + settings.scope;
        if (settings.response_type.search('id_token') >= 0) {
          options.path += '&nonce=' + nonce;
        }
        gameThis = this;
        pr_callback = function() {
          var hash, i, item, j, len, len1, splitted, t;
          item = window.localStorage.getItem('gd_connect_hash');
          if (item) {
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
                if (hash.state && hash.state === state) {
                  hash.scope = hash.scope.split('+');
                  if (checkTokens(nonce, hash)) {
                    authorized(hash);
                    return gameThis.identity({
                      success: main_cb,
                      error: error_cb
                    });
                  } else {
                    return error_cb("Tokens validation issue");
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
                return error_cb(hash.error + ' : ' + hash.error_description.replace(/\+/g, ' '));
              }
            }
          }
        };
        options.callback = pr_callback;
        return oauthpopup(options);
      },
      identity: function(options) {
        if (this.isConnected() && identity_obj) {
          if (options.success) {
            return options.success(identity_obj);
          }
        } else {
          return this.get('', {
            base_url: this.ident_endpoint(),
            success: function(data) {
              identity_obj = data;
              if (options.success) {
                return options.success(identity_obj);
              }
            },
            error: function(context, xhr, type, error) {
              console.log('identity error', context, xhr, type, error);
              if (options.error) {
                return options.error(context, xhr, type, error);
              }
            }
          });
        }
      },
      signOut: function(options) {
        var cb, so_path;
        if (this.isConnected()) {
          so_path = options.path || settings.base_is_host + '/signout';
          cb = options.success || false;
          return oauthpopup({
            path: so_path,
            autoclose: true,
            callback: function() {
              return disconnect(cb);
            }
          });
        }
      },
      trackCb: function() {
        if (window.name === 'GamifyConnectWithOAuth') {
          if (window.location.hash !== "") {
            window.localStorage.setItem('gd_connect_hash', window.location.hash);
          } else if (window.location.search !== "") {
            window.localStorage.setItem('gd_connect_hash', window.location.search);
          }
          return window.close();
        }
      }
    };
  })();

}).call(this);
