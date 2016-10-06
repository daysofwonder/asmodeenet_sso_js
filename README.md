GamifyDigital-SSO JS
------------------

An OpenID Connect library to be used with the Gamify Digital Identity Server to instrument Web pages OpenID Connect authentication and user identity.

**Table of contents**

* [Description](#description)
    * [Crypto/Token](#crypto-token)
    * [OpenID Connect](#openid-connect)
* [Example](#example)


## Description

This library is designed to be an auto-suffisant tool to connect to the Gamify Digital Identity Server using the OpenID Connect protocol.

#### Crypto/Token

For this, it embeds all that it needs (micro ajax lib GamifyDigital.ajax, JWT decoder and JWS Token Signature validation).

Embedded dependencies for crypto:
* [jsrsasign](https://kjur.github.io/jsrsasign/)
* [Crypto-JS](https://code.google.com/archive/p/crypto-js/)
* [JsbnJS](http://www-cs-students.stanford.edu/~tjw/jsbn/)


This libs are used to decode and verify token signatures.

It provides a global function jwt_decode to give capacity to decode AccessToken or ID Token if you want use it. It provide the same interface that the [jwt-decode library by auth0](https://github.com/auth0/jwt-decode)

Usage:
```javascript
var token = 'eyJ0eXAiO.../// jwt token';

var decoded = jwt_decode(token);
console.log(decoded);

/* prints:
 * { foo: "bar",
 *   exp: 1393286893,
 *   iat: 1393268893  }
 */

 var headers = jwt_decode(token, {header: true});
 console.log(headers);

 /* prints:
  * { typ: "JWT",  
  *   alg: "RS256" }
  */

```

***Be careful*** : This is not the jwt-decode library, but only a simple, and small, similar function. If you use jwt_decode, and because, it will duplicate the feature, you can remove it, and use ours function.

#### OpenID Connect

The GamifyDigital Object provided should be initiate with few mandatory parameters: client_id and redirect_uri. The same as you configured in the Gamify Digital Studio manager during the app creation.

```javascript
GamifyDigital.init({
    client_id: 'my_client_id',
    redirect_uri: 'https://my_host.name/callback_page'
});
```

You could override default other paramters by pass it in this init method.
Available paramters:
* **client_id** *string*
* **redirect_uri** *string*
* **response_type** *string* Optional, default is 'token id_token'. Values could be : token, id_token or both space separate
* **scope** *string* Optional, default is 'openid+profile'. Value could be a list of `+` separate word: openid, profile, email, adress, public, private. Openid scope is mandatory if you use response_type id_token (and this is one or couple 'token id_token' are strongly advised)
* **base_is_host** *string* Optional, URL of the GD Identity Server. By default, it's https://account.gamify-digital.com but you can set https://account.staging.gamify-digital.com for your test by ex.
* **base_is_path** *string* Optional. This should be used, in futur, to use an other version of the IS oAuth API. default /main/v2/oauth.


After the init phase, you could call the discover method to use to discovery capacity of OpenID Connect to auto-configure other parts of the library.

```javascript
GamifyDigital.discover();

// Or you can chain both calls :
GamifyDigital.init({...}).discover();
```

This method will query the Identity Server to get the openid-configuration file, configure itself with datas returned and finally query the JWKS files for JWS certification keys.

After this moment you could try to Sign in with the method signIn which take 1 parmeter, an object with 2 entries success and error callbacks. Both are optionals

```javascript
GamifyDigital.signIn({
    success: function(identity) {
        /**
         * The passed parameter is a Standard JS Object
         * with value from the identity endpoint of
         * the identity server.
         *
         * {
         *   sub: 5,
         *   nickname: "USernick"
         *   ....
         * }
        */
    },
    error: function() {
        /**
         * arguments:
         *  If a query error occurs, arguments is a
         *  list a params coming from the ajax XHR request
         *
         * But that could be the message :
         *  "popup closed without signin"
         * if the user close the popup without sign in.
        */
    }
})
```

Available fields from in the identity object are listed [here](http://apidoc.gamify-digital.com/#api-openid-identity)  and may vary depending on requested scopes.

Call this method opens a popup which query the IS /authorize endpoint. If the user has already a valid session, the popup closes directly and success callback is called. If not, the signin form is displayed and the user should fill and validate it. If it's the sign in success, the popup is automaticaly closed.
If the user close the popup himself, the error callback is called with the message
```javascript
 "popup closed without signin"
 ```


When you delete the session you could call the signOut method which could take an optional parameter, an object with a success callback.

```javascript
GamifyDigital.signOut({
    success: function() {
        // User disconnected
    }
});
```

This method will open a popup querying the signout endpoint of the IdentityServer, and the popup closes directly itself.

**N.B.:** If you don't give a sucess callback, the current page is reloaded.

If you pass a callbck, and so the page isn't reload, you can directly re-call the signIn method if you want. *Init* and *discover* methods don't need to be recalled.


The object GamifyDigital provides the following methods too:

* identity: Taking an optional parameter object with success and error callbacks ( {success: ..., error: ...}). Call the identity endpoint of the Identity Server. This method is called automaticaly by the signIn if succeed.
* getAccessToken: get the access token of the current user
* getAccessHash: get the all JSON object from the authorize endpoint (included access_token, id_token, ....)
* getIdToken: get the ID token of the current user
* getDiscovery: get the discovery object return from the openid-configuration endpoint.
* trackCb: This method should be call in the "page" called by the IS as callback (the ones configured in **redirect_uri** init's field). You can see the file [examples/cbpop.html] in examples directory to see how to use it. This page could be only the same content that the cbpop file or could be a dynamic file (in PHP, Node, Ruby,...) that intercept token or messages from IS before your Web client. You should use this method. If not, your client part can't found tokens. but if you don't want include the JS gamifyd_sso lib in your callback page, you can copy the content of the trackCB method itself in the returned html page.


## Example
