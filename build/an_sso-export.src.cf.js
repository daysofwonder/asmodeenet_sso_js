(function() {
  var AsmodeeNet, ajaxCl,
    indexOf = [].indexOf;

  ajaxCl = function(url, settings) {
    var args, complete, defaultSettings, emptyFunction, error, key, mimeTypes, readyStateChange, success, xhr;
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
    settings = window.AsmodeeNet.extend(defaultSettings, settings || {});
    mimeTypes = {
      'application/json': 'json',
      'text/html': 'html',
      'text/plain': 'text'
    };
    if (!settings.cache) {
      settings.url = settings.url + (settings.url.indexOf('?') ? '&' : '?') + 'noCache=' + Math.floor(Math.random() * 9e9);
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
    readyStateChange = function() {
      var dataType, e, mime, result;
      if (xhr.readyState === 4) {
        result = null;
        mime = xhr.getResponseHeader('content-type');
        dataType = mimeTypes[mime] || 'text';
        if ((xhr.status >= 200 && xhr.status < 300) || xhr.status === 304) {
          result = xhr.responseText;
          try {
            if (dataType === 'json') {
              result = JSON.parse(result);
            }
          } catch (error1) {
            e = error1;
            error(e.message, 'parsererror', xhr, settings);
            return;
          }
          success(result, xhr, settings);
          return;
        } else {
          result = xhr.responseText;
          try {
            if (dataType === 'json') {
              result = JSON.parse(result);
            }
            error(result, 'error', xhr, settings);
            return;
          } catch (error1) {
            e = error1;
            error(e.message, 'parsererror', xhr, settings);
            return;
          }
        }
        return error(result, 'error', xhr, settings);
      }
    };
    if (xhr.addEventListener) {
      xhr.addEventListener('readystatechange', readyStateChange, false);
    } else if (xhr.attachEvent) {
      xhr.attachEvent('onreadystatechange', readyStateChange);
    }
    xhr.open(settings.type, settings.url);
    if (settings.type === 'POST') {
      settings.headers = window.AsmodeeNet.extend({
        'Content-type': 'application/x-www-form-urlencoded'
      }, settings.headers, {
        'X-Requested-With': 'XMLHttpRequest'
      });
    }
    for (key in settings.headers) {
      xhr.setRequestHeader(key, settings.headers[key]);
    }
    xhr.send(settings.data);
    return this;
  };

  AsmodeeNet = (function() {
    var _oauthWindow, acceptableLocales, access_hash, access_token, authorized, baseLinkAction, catHashCheck, checkDisplayOptions, checkErrors, checkLogoutRedirect, checkTokens, checkUrlOptions, clearCookies, clearItems, code, defaultErrorCallback, defaultSuccessCallback, default_settings, deleteCookie, disconnect, discovery_obj, getCookie, getCryptoValue, getItem, getLocation, getPopup, iFrame, id_token, identityEvent, identity_obj, jwks, localStorageIsOk, nonce, notConnectedEvent, oauth, oauthiframe, oauthpopup, popupIframeWindowName, removeItem, sendEvent, setCookie, setItem, settings, signinCallback, state, try_refresh_name;
    defaultSuccessCallback = function() {
      return console.log(arguments);
    };
    defaultErrorCallback = function() {
      return console.error(arguments);
    };
    acceptableLocales = ['fr', 'de', 'en', 'it', 'es'];
    default_settings = {
      base_is_host: 'https://account.asmodee.net',
      base_is_path: '/main/v2/oauth',
      logout_endpoint: '/main/v2/logout',
      base_url: 'https://api.asmodee.net/main/v1',
      client_id: null,
      redirect_uri: null,
      cancel_uri: null, // Only used in touch mode by the IS
      logout_redirect_uri: null, // if not provided, and not configured in Studio manager for this app, the IS will redirect the user on IS page only!
      callback_post_logout_redirect: null, // the only one solution for callback success in 'page' or 'touch' display mode
      base_uri_for_iframe: null,
      scope: 'openid+profile',
      response_type: 'id_token token',
      display: 'popup',
      display_options: {},
      iframe_css: null, // only used un 'iframe' display mode
      callback_signin_success: defaultSuccessCallback, // the only one solution for callback success in 'page' or 'touch' display mode
      callback_signin_error: defaultErrorCallback, // the only one solution for callback error in 'page' or 'touch' display mode
      extraparam: null
    };
    settings = {};
    state = nonce = null;
    access_token = id_token = access_hash = identity_obj = discovery_obj = jwks = code = null;
    checkErrors = [];
    localStorageIsOk = null;
    popupIframeWindowName = 'AsmodeeNetConnectWithOAuth';
    try_refresh_name = 'try_refresh';
    _oauthWindow = null;
    iFrame = {
      element: null,
      receiveMessageCallback: null,
      saveOptions: null
    };
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
        callback();
        if (settings.display === 'iframe') {
          return window.AsmodeeNet.signIn(iFrame.saveOptions);
        }
      } else {
        return window.location.reload();
      }
    };
    oauth = function(options) {
      if (settings.display === 'popup') {
        return oauthpopup(options);
      } else if (settings.display === 'iframe') {
        return oauthiframe(options);
      } else {
        return window.location.assign(options.path);
      }
    };
    sendEvent = function(type, detailEvent) {
      var event;
      event = null;
      if (CustomEvent) {
        event = new CustomEvent(type, {
          bubbles: true,
          detail: detailEvent
        });
      } else if (document.createEvent) {
        event = document.createEvent('Event');
        event.initEvent(type, true, true);
        event.eventName = type;
        if (detailEvent) {
          event.detail = detailEvent;
        }
      } else {
        return;
      }
      return document.dispatchEvent(event);
    };
    identityEvent = function(iobj) {
      return sendEvent('AsmodeeNetIdentity', iobj);
    };
    notConnectedEvent = function() {
      return sendEvent('AsmodeeNetNotConnected', null);
    };
    getPopup = function(options) {
      if (options.width == null) {
        options.width = 475;
      }
      if (options.height == null) {
        options.height = 500;
      }
      if (options.windowName == null) {
        options.windowName = popupIframeWindowName;
      }
      if (options.windowOptions == null) {
        options.windowOptions = 'location=0,status=0,width=' + options.width + ',height=' + options.height;
      }
      if (options.callback == null) {
        options.callback = function() {
          return window.location.reload();
        };
      }
      return this._oauthWindow = window.open(options.path, options.windowName, options.windowOptions);
    };
    oauthpopup = function(options) {
      var that;
      getPopup(options);
      that = this;
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
    oauthiframe = function(options) {
      var redirect_uri;
      if (options.width == null) {
        options.width = 475;
      }
      if (options.height == null) {
        options.height = 500;
      }
      if (options.callback == null) {
        options.callback = function() {
          return window.location.reload();
        };
      }
      iFrame.element = settings.iframe_css.indexOf('#') !== -1 ? window.document.getElementById(settings.iframe_css.replace('#', '')) : window.document.getElementsByClassName(settings.iframe_css)[0];
      if (iFrame.element) {
        iFrame.element.name = popupIframeWindowName;
        iFrame.element.width = options.width;
        iFrame.element.height = options.height;
        iFrame.element.src = options.path;
        redirect_uri = settings.redirect_uri;
        if (iFrame.element && !iFrame.element.closed) {
          iFrame.element.focus();
        }
        if (iFrame.receiveMessageCallback) {
          iFrame.element.removeEventListener('load', iFrame.receiveMessageCallback);
        }
        iFrame.receiveMessageCallback = function(e) {
          var d, item;
          if (e.currentTarget.name === popupIframeWindowName) {
            d = e.currentTarget.contentWindow || e.currentTarget.contentDocument;
            item = getItem('gd_connect_hash');
            if (item) {
              return options.callback();
            }
          }
        };
        return iFrame.element.addEventListener('load', iFrame.receiveMessageCallback, false);
      }
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
      window.AsmodeeNet.verifyBHash(b_hash);
      return b_hash === btoa(mdHex);
    };
    checkTokens = function(nonce, hash) {
      var alg, at_dec, at_head, e, errdecode, it_dec, it_head, j, key, len;
      if (hash.access_token) {
        try {
          at_dec = window.AsmodeeNet.jwt_decode(hash.access_token);
          at_head = window.AsmodeeNet.jwt_decode(hash.access_token, {
            header: true
          });
        } catch (error1) {
          errdecode = error1;
          checkErrors.push("access_token decode error : " + errdecode);
          return false;
        }
      }
      if (settings.response_type.search('id_token') >= 0) {
        if (typeof hash.id_token === void 0) {
          return false;
        }
        try {
          it_dec = window.AsmodeeNet.jwt_decode(hash.id_token);
          it_head = window.AsmodeeNet.jwt_decode(hash.id_token, {
            header: true
          });
        } catch (error1) {
          errdecode = error1;
          checkErrors.push("id_token decode error : " + errdecode);
          return false;
        }
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
        if (URI(it_dec.iss).normalize().toString() !== URI(settings.base_is_host).normalize().toString()) {
          checkErrors.push('Invalid issuer');
          return false;
        }
        if (it_dec.aud !== settings.client_id && (!Array.isArray(it_dec.aud) || id_dec.aud.indexOf(settings.client_id) === -1)) {
          checkErrors.push('Invalid auditor');
          return false;
        }
        if (it_dec.exp < window.AsmodeeNet.limit_exp_time()) {
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
          if (key.alg && key.alg === alg[0]) {
            try {
              if (KJUR.jws.JWS.verify(hash.id_token, KEYUTIL.getKey(key), alg)) {
                return true;
              }
            } catch (error1) {
              e = error1;
              console.error('JWS verify error', e);
            }
          }
        }
        checkErrors.push('Invalid JWS key');
        return false;
      }
      return true;
    };
    checkUrlOptions = function() {
      var u;
      if (settings.base_is_host) {
        u = URI(settings.base_is_host);
        settings.base_is_host = u.protocol() + '://' + u.host();
      }
      if (settings.base_url) {
        settings.base_url = URI(settings.base_url).normalize().toString();
      }
      if (settings.logout_redirect_uri) {
        return settings.logout_redirect_uri = URI(settings.logout_redirect_uri).normalize().toString();
      }
    };
    checkLogoutRedirect = function() {
      var found_state, re;
      if (settings.logout_redirect_uri) {
        re = new RegExp(settings.logout_redirect_uri.replace(/([?.+*()])/g, "\\$1"));
        if (re.test(window.location.href) && settings.display !== 'iframe') {
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
    getLocation = function(href) {
      var l;
      l = document.createElement("a");
      return l.href = href;
    };
    baseLinkAction = function(that, endpoint, options) {
      var gameThis, k, locale, localizedEndpoint, ref, ruri, urlParsed, v;
      options = options || {};
      locale = options.locale ? '/' + options.locale : '';
      if (locale !== '' && acceptableLocales.indexOf(locale) === -1) {
        locale = 'en';
      }
      if (settings.display === 'iframe') {
        iFrame.saveOptions = window.AsmodeeNet.extend({}, options);
      }
      state = getCryptoValue();
      nonce = getCryptoValue();
      setItem('state', state, settings.display === 'iframe' ? 1440 : 20);
      setItem('nonce', nonce, settings.display === 'iframe' ? 1440 : 20);
      settings.callback_signin_success = options.success || settings.callback_signin_success;
      settings.callback_signin_error = options.error || settings.callback_signin_error;
      urlParsed = getLocation(endpoint);
      localizedEndpoint = endpoint.replace(urlParsed.pathname, options.locale + urlParsed.pathname);
      options.path = localizedEndpoint + '?display=' + settings.display + '&response_type=' + encodeURI(settings.response_type) + '&state=' + state + '&client_id=' + settings.client_id + '&scope=' + settings.scope;
      if (typeof options.gatrack !== 'undefined') {
        options.path += '&_ga=' + options.gatrack;
      }
      if (settings.redirect_uri) {
        ruri = settings.redirect_uri;
        if (options.redirect_extra) {
          ruri += options.redirect_extra;
        }
        options.path += '&redirect_uri=' + encodeURI(ruri);
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
      if (options.extraparam) {
        options.path += '&extraparam=' + encodeURI(options.extraparam);
      }
      if (!options.extraparam && settings.extraparam) {
        options.path += '&extraparam=' + encodeURI(settings.extraparam);
      }
      gameThis = that;
      options.callback = function() {
        removeItem(try_refresh_name);
        return signinCallback(gameThis);
      };
      return oauth(options);
    };
    signinCallback = function(gameThis) {
      var hash, item, j, len, len1, m, splitted, t;
      item = getItem('gd_connect_hash');
      if (!item) {
        if (settings.display === 'popup') {
          settings.callback_signin_error("popup closed without signin");
        }
        return notConnectedEvent();
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
            if (hash.state) {
              if (hash.state === state) {
                hash.scope = hash.scope.split('+');
                hash.expires = window.AsmodeeNet.jwt_decode(hash.access_token)['exp'];
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
                  notConnectedEvent();
                  return settings.callback_signin_error('Tokens validation issue : ', checkErrors);
                }
              } else {
                notConnectedEvent();
                return settings.callback_signin_error('Tokens validation issue : ', 'Invalid state');
              }
            }
          }
        } else if (item.search(/^\?/) === 0) {
          splitted = item.replace(/^\?/, '').split('&');
          for (m = 0, len1 = splitted.length; m < len1; m++) {
            t = splitted[m];
            t = t.split('=');
            hash[t[0]] = t[1];
          }
          state = getItem('state');
          removeItem('state');
          if (hash.state && hash.state === state) {
            settings.callback_signin_error(parseInt(hash.status), hash.error, hash.error_description.replace(/\+/g, ' '));
            return notConnectedEvent();
          }
        }
      }
    };
    checkDisplayOptions = function() {
      var opt, ref, ref1, tmpopts, val;
      tmpopts = null;
      if ((ref = settings.display) === 'touch' || ref === 'iframe') {
        tmpopts = {
          noheader: true,
          nofooter: true,
          lnk2bt: true,
          leglnk: false,
          cookies: true
        };
      } else if (settings.display === 'popup') {
        tmpopts = {
          noheader: false,
          nofooter: false,
          lnk2bt: false,
          leglnk: true
        };
      }
      if (Object.keys(settings.display_options).length > 0) {
        if (tmpopts) {
          ref1 = settings.display_options;
          for (opt in ref1) {
            val = ref1[opt];
            if (indexOf.call(Object.keys(tmpopts), opt) < 0) {
              delete settings.display_options[opt];
            }
          }
        }
      }
      settings.display_options = window.AsmodeeNet.extend(tmpopts, settings.display_options);
      if (indexOf.call(Object.keys(settings.display_options), 'cookies') >= 0 && settings.display_options.cookies === true) {
        delete settings.display_options.cookies;
      }
      if (settings.display === 'touch') {
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
      var error;
      try {
        return store.set(name, value, new Date().getTime() + (minutes * 60000));
      } catch (error1) {
        error = error1;
        return console.error("SetItem '" + name + "'", value, error);
      }
    };
    getItem = function(name) {
      var error;
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
      verifyBHash: function(b_hash) {
        return b_hash; // internal use for tests
      },
      init: function(options) {
        settings = window.AsmodeeNet.extend(default_settings, options);
        checkUrlOptions();
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
      getSettings: function() {
        return window.AsmodeeNet.extend({}, settings);
      },
      getIdentity: function() {
        return identity_obj;
      },
      getScopes: function() {
        if (!this.isConnected()) {
          return null;
        }
        return this.getAccessHash()['scope'];
      },
      getExpires: function() {
        if (!this.isConnected()) {
          return null;
        }
        return this.getAccessHash()['expires'];
      },
      getExpiresDate: function() {
        if (!this.isConnected()) {
          return null;
        }
        return new Date(this.getAccessHash()['expires'] * 1000);
      },
      auth_endpoint: function() {
        if (discovery_obj) {
          return URI(discovery_obj.authorization_endpoint).normalize().toString();
        }
        return URI(settings.base_is_host + settings.base_is_path + '/authorize').normalize().toString();
      },
      ident_endpoint: function() {
        if (discovery_obj) {
          return URI(discovery_obj.userinfo_endpoint).normalize().toString();
        }
        return URI(settings.base_is_host + settings.base_is_path + '/identity').normalize().toString();
      },
      ajaxq: function(type, url, options) {
        var base_url, sets;
        if (options == null) {
          options = {};
        }
        base_url = options.base_url || settings.base_url || default_settings.base_url;
        delete options.base_url;
        sets = window.AsmodeeNet.extend(options, this.baseSettings(), {
          type: type
        });
        if (options.auth !== void 0 && options.auth === false) {
          if (sets.headers.Authorization) {
            delete sets.headers.Authorization;
          }
          delete sets.auth;
        }
        return window.AsmodeeNet.ajax(base_url + url, sets);
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
      delete: function(url, options) {
        return this.ajaxq('DELETE', url, options);
      },
      discover: function(host_port) {
        var gameThis;
        host_port = host_port || settings.base_is_host || default_settings.base_is_host;
        host_port = URI(host_port);
        host_port = host_port.protocol() + '://' + host_port.host();
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
            settings.base_is_host = URI(discovery_obj.issuer).normalize().toString();
            settings.logout_endpoint = URI(discovery_obj.end_session_endpoint).normalize().toString();
            return gameThis.getJwks();
          },
          error: function() {
            return console.error("error Discovery on " + host_port, arguments);
          }
        });
      },
      getJwks: function() {
        var gameThis;
        gameThis = this;
        return this.get('', {
          base_url: URI(discovery_obj.jwks_uri).normalize().toString(),
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
      signUp: function(locale, options, special_host, special_path) {
        if (acceptableLocales.indexOf(locale) === -1) {
          locale = 'en';
        }
        if (!special_host) {
          special_host = discovery_obj.issuer;
        }
        if (!special_path) {
          special_path = '/signup';
        }
        return baseLinkAction(this, URI(special_host).normalize().toString() + locale + special_path, options);
      },
      resetPass: function(locale, options, special_host, special_path) {
        if (acceptableLocales.indexOf(locale) === -1) {
          locale = 'en';
        }
        if (!special_host) {
          special_host = discovery_obj.issuer;
        }
        if (!special_path) {
          special_path = '/reset';
        }
        return baseLinkAction(this, URI(discovery_obj.issuer).normalize().toString() + locale + special_path, options);
      },
      signIn: function(options, special_host, special_path) {
        if (special_host) {
          special_host = URI(special_host).normalize().toString() + locale + special_path;
        } else {
          special_host = this.auth_endpoint();
        }
        return baseLinkAction(this, special_host, options);
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
          if (settings.display === 'iframe') {
            iFrame.element.src = '';
          }
          identityEvent(identity_obj);
          if (options && options.success) {
            return options.success(identity_obj, window.AsmodeeNet.getCode());
          }
        } else {
          return this.get('', {
            base_url: this.ident_endpoint(),
            success: function(data) {
              identity_obj = data;
              if (settings.display === 'iframe') {
                iFrame.element.src = '';
              }
              identityEvent(identity_obj);
              if (options && options.success) {
                return options.success(identity_obj, window.AsmodeeNet.getCode());
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
      restoreTokens: function(saved_access_token, saved_id_token, call_identity = true, cbdone = null, clear_before_refresh = null, saved_identity = null) {
        var already_try_refresh, decoded, hash;
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
              decoded = window.AsmodeeNet.jwt_decode(saved_access_token);
              hash.scope = decoded['scope'].split(' ');
              hash.expires = decoded['exp'];
              hash.token_type = decoded['token_type'];
              removeItem(try_refresh_name);
              authorized(hash);
              if (call_identity) {
                this.identity({
                  success: settings.callback_signin_success,
                  error: settings.callback_signin_error
                });
              }
              if (saved_identity) {
                identity_obj = saved_identity;
              }
              if (cbdone) {
                cbdone(true);
              } else {
                return true;
              }
            } else {
              already_try_refresh = getItem(try_refresh_name);
              removeItem(try_refresh_name);
              if (checkErrors[0] === 'Invalid expiration date' && clear_before_refresh && !already_try_refresh) {
                console.log('try refresh token');
                setItem(try_refresh_name, true);
                clear_before_refresh() && window.AsmodeeNet.signIn({
                  success: cbdone
                });
              } else {
                notConnectedEvent();
                if (cbdone) {
                  cbdone(false, checkErrors);
                } else {
                  return false;
                }
              }
            }
          } else {
            setTimeout(function() {
              return window.AsmodeeNet.restoreTokens(saved_access_token, saved_id_token, call_identity, cbdone, clear_before_refresh, saved_identity);
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
        var id_token_hint, logout_ep, redirect_uri, successCallback;
        options = options || {};
        successCallback = options && typeof options.success !== 'undefined' ? options.success : null;
        if (this.isConnected() || options.force) {
          if (settings.logout_redirect_uri) {
            state = getCryptoValue();
            id_token_hint = id_token;
            setItem('logout_state', state, 5);
            logout_ep = settings.logout_endpoint + '?post_logout_redirect_uri=' + encodeURI(settings.logout_redirect_uri) + '&state=' + state + '&id_token_hint=' + id_token_hint;
            if (options && typeof options.gatrack !== 'undefined') {
              logout_ep += '&_ga=' + options.gatrack;
            }
            if (settings.display === 'iframe') {
              if (iFrame.element) {
                iFrame.element.src = logout_ep;
                redirect_uri = settings.logout_redirect_uri;
                if (iFrame.receiveMessageCallback) {
                  iFrame.element.removeEventListener('load', iFrame.receiveMessageCallback);
                }
                iFrame.receiveMessageCallback = function(e) {
                  if (e.currentTarget.name === popupIframeWindowName) {
                    return disconnect(successCallback);
                  }
                };
                return iFrame.element.addEventListener('load', iFrame.receiveMessageCallback, false);
              }
            } else if (settings.display === 'popup') {
              options.path = logout_ep;
              options.callback = function() {
                return disconnect(successCallback);
              };
              return oauthpopup(options);
            } else {
              return window.location = logout_ep;
            }
          } else {
            return disconnect(successCallback);
          }
        }
      },
      trackCb: function(closeit) {
        if (closeit == null) {
          closeit = true;
        }
        if (window.location.hash !== "") {
          setItem('gd_connect_hash', window.location.hash, 5);
        } else if (window.location.search !== "") {
          setItem('gd_connect_hash', window.location.search, 5);
        }
        if (window.name === 'AsmodeeNetConnectWithOAuth') {
          console.log('ok try closeit');
          if (closeit) {
            return window.close();
          }
        }
      },
      inIframe: function() {
        return window.self === window.top;
      }
    };
  });

  module.exports({
    AsmodeeNet: AsmodeeNet
  });

}).call(this);

//# sourceMappingURL=an_sso-export.src.cf.js.map
