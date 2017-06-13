(function() {
  window.AsmodeeNet.ajax = function(url, settings) {
    var args, complete, defaultSettings, emptyFunction, error, key, mimeTypes, readyStateChange, ref, success, xhr;
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
    readyStateChange = function() {
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
    };
    if (xhr.addEventListener) {
      xhr.addEventListener('readystatechange', readyStateChange, false);
    } else if (xhr.attachEvent) {
      xhr.attachEvent('onreadystatechange', readyStateChange);
    }
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
