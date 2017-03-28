AsmodeeNet-SSO JS
------------------

An OpenID Connect library to be used with the Asmodee.net Identity Server to instrument Web pages OpenID Connect authentication and user identity.

**Table of contents**

* [Description](#description)
    * [Crypto/Token](#crypto-token)
    * [OpenID Connect](#openid-connect)
        * [Init](#init)
        * [Discover](#discover)
        * [Sign In](#sign-in)
        * [Sign Out](#sign-out)
            * [RP Logout](#rp-logout)
            * [Simple logout](#simple-logout)
        * [Other methods](#other-methods)
        * [Backend dialog](#backend-dialog)
* [Example](#example)


## Description

This library is designed to be an auto-suffisant tool to connect to the Asmodee.net Identity Server using the OpenID Connect protocol.
You can use directly the last min-X.X.X.js present in dist directory or if you want rebuild it:

You need npm/nodeJs installed.

```shell
npm install
grunt build
```

#### Crypto/Token

For this, it embeds all that it needs (micro ajax lib AsmodeeNet.ajax, JWT decoder and JWS Token Signature validation).

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

The library provids the global object AsmodeeNet (and the alias AN if it's not already used by something else) that is the central point of communication with the Identity Server.

##### Init

The AsmodeeNet Object provided should be initiate with few mandatory parameters: client_id and redirect_uri. The same as you configured in the Asmodee.net Studio manager during the app creation.

```javascript
AsmodeeNet.init({
    client_id: 'my_client_id',
    redirect_uri: 'https://my_host.name/callback_page'
});
```

You could override default other paramters by pass it in this init method.
Available paramters:
* **client_id** *string*
* **redirect_uri** *string*
* **logout_redirect_uri** *string*
* **callback_post_logout_redirect** *callback*
* **response_type** *string* Optional, default is 'token id_token'. Values could be : token, id_token or both space separate
* **scope** *string* Optional, default is 'openid+profile'. Value could be a list of `+` separate word: openid, profile, email, adress, public, private. Openid scope is mandatory if you use response_type id_token (and this is one or couple 'token id_token' are strongly advised)
* **base_is_host** *string* Optional, URL of the AN Identity Server. By default, it's https://account.asmodee.net but you can set https://account.staging.asmodee.net for your test by ex.
* **base_is_path** *string* Optional. This should be used, in futur, to use an other version of the IS oAuth API. default /main/v2/oauth.
* **display** *string* Optional. Defines the way the OAuth flow should be handled. Possible values are `popup` (which conveniently opens a popup), and `touch` (which keeps the flow in the same window). Default is `popup`.
* **callback_signin_success** Optional. The function to call after a successful sign-in. Default is `console.log`.
* **callback_signin_error** Optional. The function to call after an unsuccessful sign-in. Default is `console.error`.

##### Discover

After the init phase, you could call the discover method to use to discovery capacity of OpenID Connect to auto-configure other parts of the library.

```javascript
AsmodeeNet.discover();

// Or you can chain both calls :
AsmodeeNet.init({...}).discover();
```

This method will query the Identity Server to get the openid-configuration file, configure itself with datas returned and finally query the JWKS files for JWS certification keys.

##### Sign in

After this moment you could try to Sign in with the method signIn which take 1 parameter, an object with following entries:

 * success callback (default: `callback_signin_success`, see above)
 * error callback (default: `callback_signin_error`, see above)
 * width of the popup (default: 475px)
 * height of the popup (default: 500px)

 All are optionals.

 **Note:** When using a display flow other than `popup`, the success and error callbacks passed to `signIn()` will not be called, so you **have** to use `init()` to set those up in such cases.

```javascript
AsmodeeNet.signIn({
    success: function(identity, code) {
        /**
         * The first parameter is a Standard JS Object
         * with value from the identity endpoint of
         * the identity server.
         *
         * {
         *   sub: 5,
         *   nickname: "USernick"
         *   ....
         * }
         *
         * The second parameter it's the code returned by IdentityServer. (same as AsmodeeNet.getCode() )
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
    },
    width: 500,
    height: 800
})
```

Available fields from in the identity object are listed [here](http://apidoc.asmodee.net/#api-openid-identity)  and may vary depending on requested scopes.

Call this method opens a popup which query the IS /authorize endpoint. If the user has already a valid session, the popup closes directly and success callback is called. If not, the signin form is displayed and the user should fill and validate it. If it's the sign in success, the popup is automaticaly closed.
If the user close the popup himself, the error callback is called with the message

```javascript
 "popup closed without signin"
 ```

##### Sign out

###### RP Logout

When you want to log out the user, since the Asmodee.net IdentityServer support the RP logout OpenId Connect feature, you should call the `signOut` method. This one call the IS `end_session` endpoint (described in the IS OpenId configuration discovery document). The user will be disconnect from Asmodee.net IdentityServer and redirected on your post logout redirect uri (passed in parameters in the `init` method and set in your application configuration on the Studio Manager).

If a callback is provided in the init setting (`callback_post_logout_redirect`), this one will be called in return of the IS and if all is OK.

Following the [OpenID Connect RP Logout specification](https://openid.net/specs/openid-connect-session-1_0.html#RPLogout), you should remove your own session before the call of `AsmodeeNet.signOut()`.

```javascript
AsmodeeNet.signOut();
```

**N.B.:** If you don't give a `callback_post_logout_redirect` callback, the root of your hostname should be loaded (`/`).


###### Simple Sign out

If you don't want to use the OpenID Connect's RP Logout feature of the IdentityServer, you must not configure `logout_redirect_uri` and `callback_post_logout_redirect` init's parameters and when you delete the session you can call the signOut method with an optional parameter: an object with a success callback.

```javascript
AsmodeeNet.signOut({
    success: function() {
        // User disconnected
    }
});
```

This method will clear stockage made by itself about the current connected user and will execute the given callback.

**N.B.:** If you don't provide a success callback, the current page is reloaded.

If you pass a callback, and so the page isn't reload, you can directly re-call the signIn method if you want. *Init* and *discover* methods don't need to be recalled.

##### Other methods

The object AsmodeeNet provides the following methods too:

* **init**: see [here](#init)
* **discover**: see [here](#discover)
* **signIn**: see [here](#sign-in)
* **signOut**: see [here](#sign-out)
* **identity**: Taking an optional parameter object with success and error callbacks ( {success: ..., error: ...}). Call the identity endpoint of the Identity Server. This method is called automaticaly by the signIn if succeed.
* **getAccessToken**: get the access token of the current user
* **getAccessHash**: get the all JSON object from the authorize endpoint (included access_token, id_token, ....)
* **getIdToken**: get the ID token of the current user
* **getDiscovery**: get the discovery object return from the openid-configuration endpoint.
* **getCode**: get the code returned by IS. (useful in hybrid flow)
* **getCheckErrors**: get list of errors during token check if it's a fail
* **trackCb**: Taking an optional parameter, boolean, default at true, which close the popup. If it's false, the popup will not be close (see [#Backend dialog](#backend-dialog)). This method should be call in the callback "page" called by the IS (the ones configured in **redirect_uri** init's field). You can see the file [examples/cbpop.html](examples/cbpop.html) in examples directory to see how to use it. This page could be only the same content that the cbpop file or could be a dynamic file (in PHP, Node, Ruby,...) that intercept IS error message (passed in query get during callback) from IS before your Web client, but can't catch tokens if authorization is ok, because there are passed in anchor only. You should use this method. If not, your client part can't found tokens. but if you don't want include the JS an_sso lib in your callback page, you can copy the content of the trackCB method itself in the returned html page.

##### Backend dialog

If you want that your backend dialog with Identity Server or API of Asmodee.net directly too, you should authorize your backend.

For this, you should use an other client_id, but one with client_secret. You can do this in your callback page.

In the popup html code,call the _trackCb_ with parameter close at *false*, or your remplacement for it, initialize normal flow openid/oauth (not implicit flow) for your backend with your client_id/client_secret couple, and so an other redirect inside the popup itself on IS. But the user juste have already a valid session opened, so the IS call the callback page directly for this 2nd client_id, and you have your backend authorization. And so, you can close the popup.

Your backend is autorized with it's own access_token, and your client too.

## Example

The example index.html show you a simple example, using cbpop.html as popup callback page. You can display error and identity in the page once logged, and you can signout. To run it, only launch a simple web server (by ex. run in the examples directory php -S localhost:XXXX , ruby -run -ehttpd . -p XXXX or others http onliners server (https://gist.github.com/willurd/5720255) or if you have node, you can do
```shell
npm install # if not done yet
grunt serve
```
).
Replace in the init call, client_id and redirect_uri with the good one (Set an app with redirect_uri value as this http://localhost:XXXX ). And enjoy!

This example don't use SSL (because onliners http server don't manage all SSL easily) but in production your page should be encapsuled with SSL!



## TODO (not ordered, not closed)

* Query Scheduler (prevent signIn call before discover end by ex)
* Promise capacities
* HTML data parser for generate Asmodee.net OpenID Connect button.
* clean Error system
* REST API capacities
* Add some tests
* ...
