(function() {
  window.GamifyDigital.extend = function() {
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

  window.GamifyDigital.jwt_decode = function(token, options) {
    var deco;
    deco = KJUR.jws.JWS.parse(token);
    if (options && options.header !== "undefined" && options.header === true) {
      return deco.headerObj;
    }
    return deco.payloadObj;
  };

  if (!window.jwt_decode) {
    window.jwt_decode = window.GamifyDigital.jwt_decode;
  }

}).call(this);
