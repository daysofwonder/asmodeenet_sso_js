AsmodeeNet-SSO JS
------------------

An OpenID Connect library that connects to the **Asmodee.net** Identity Server (aka **IS**) to allow a Web site to authenticate Asmodee users.

[![Maintainability](https://api.codeclimate.com/v1/badges/59c53cfaa1fae802c219/maintainability)](https://codeclimate.com/github/daysofwonder/asmodeenet_sso_js/maintainability) [![Test Coverage](https://api.codeclimate.com/v1/badges/59c53cfaa1fae802c219/test_coverage)](https://codeclimate.com/github/daysofwonder/asmodeenet_sso_js/test_coverage)

**Table of contents**

* [Description](#description)
    * [Cryptography and Tokens](#cryptography-and-tokens)
    * [OpenID Connect](#openid-connect)
    * [Initialization](#initialization)
    * [Discover](#discover)
    * [Sign-in](#sign-in)
    * [trackCb](#trackcb)
    * [Sign-out](#sign-out)
        * [RP Logout](#rp-logout)
        * [Simple Logout](#simple-logout)
    * [Restore](#restore-tokens)
    * [Other methods](#other-methods)
    * [Backend dialog](#backend-dialog)
* [Examples](#example)
* [Tests](#tests)
    * [Unit tests](#unit-tests)
    * [Acceptance tests](#acceptance-tests)

## Installation

This library is designed to be a self-sufficient stand-alone tool.

You can use directly the last `min-X.X.X.js` file located in the `dist` directory.

Otherwise, if you want rebuild it, you will need `npm/nodeJs` installed. Then type:

```shell
npm install
grunt build
```

## Description

### Cryptography and Tokens

All necessary libraries are embedded: the micro ajax lib AsmodeeNet.ajax, the JWT decoder and the JWS Token Signature validation.

Embedded dependencies for cryptography:
* [jsrsasign](https://kjur.github.io/jsrsasign/)
* [Crypto-JS](https://code.google.com/archive/p/crypto-js/)
* [JsbnJS](http://www-cs-students.stanford.edu/~tjw/jsbn/)


These libraries are used to decode and verify token signatures.

The code provides a global `jwt_decode` function that allows you to decode an Access Token or and ID Token if you need to. It provides the same interface as the [jwt-decode library by auth0](https://github.com/auth0/jwt-decode).

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

***Be careful*** : This is not the official jwt-decode library, but only a simple and small similar function. If you use the official jwt-decode library, the behavior will be the same. If you use your own `jwt_decode()` function, you will have to rename it to avoid a name clash.

### OpenID Connect

The library provides the global object `AsmodeeNet` (and the alias `AN` if it's not already used by something else). This object is the central point of communication with the Asmodee.net Identity Server.

### Various user workflow and display modes

The library is versatile in terms of user experience and display options, so that it fits your needs.

By default, it opens a pop-up window in which the whole sign-in/sign-up user interface is managed before returning to your website with a connection.

However you can choose to replace the current page instead of opening a pop-up window (`page` display mode). You can even go further and request to remove all the extra links, the headers and footers and use buttons instead of links. This is convenient for a touch-based app that requires a modal workflow. Check out the `display` and `display_options` parameters.

### Initialization

The `AsmodeeNet` object should be initialized using the `init()` function with a few mandatory parameters: `client_id` and `redirect_uri`. These should be the same as the ones you set in the Asmodee.net [Studio Manager](https://studio.asmodee.net) during the app creation.

```javascript
AsmodeeNet.init({
    client_id: 'my_client_id',
    redirect_uri: 'https://my_host.name/callback_page'
});
```

You can override the other default options by giving additional parameters to the `init()` function.

Parameters:
* **client_id** *string* Mandatory. The app client ID.
* **redirect_uri** *string* Mandatory. The redirection URI.
* **cancel_uri** *string* Optional. Used only if `display` is set to `touch` or `popup` and `display_options.lnk2bt` is true. In this case, if `cancel_uri` is not set, it takes the value of redirect_uri. This value will be used by the Identity Server for the cancel button. See the `display` and `display_options` parameters for more information.
* **logout_redirect_uri** *string* Optional.
* **callback_post_logout_redirect** *callback* Optional. This callback function will be called after a logout.
* **response_type** *string* Optional, default is `'token id_token'`. Values can be: `code`, `token`, `id_token` or any space-separated combination. We strongly recommend that you use the default combination value.
* **scope** *string* Optional, default is `'openid+profile'`. Value could be a list of `+` separated words: `openid`, `profile`, `email`, `address`, `public`, and `private`. The `openid` scope is mandatory if you use the `id_token` response_type. Use the `private` scope if you intend to access the user's private data using the REST API later on.
* **base_is_host** *string* Optional, URL of the AN Identity Server. By default, it's https://account.asmodee.net but you can set it to https://account.staging.asmodee.net if you perform tests on our staging server. We still recommend that you test on our production server: it does not cost anything to create a test account at https://account.asmodee.net and you will be sure that what you do actually works in production.
* **base_is_path** *string* Optional. May be used in the future to use another version of the IS OAuth API. Default is `/main/v2/oauth`.
* **display** *string* Optional. Defines the way the user workflow should be handled. Possible values are `popup`, `touch`, `iframe`and `page`:
    * `popup` (default) opens a popup window which dimensions can be set up with the `signIn()` method (see below);
    * `iframe` keeps the user in the same window or tab and provides an iframe to integrate in your client side page, to display the Identity Server account page. The iframe itself will be initialized only after the call to the `signIn()` method, so you can chain the call directly after the call to the `discover()` method;
    * `touch` keeps the user in the same window or tab and provides a clean layout for the sign-in and sign-up page, suitable for mobile displays (phones or tablets);
    * `page` keeps the user in the same window or tab and provides a standard layout for the sign-in and sign-up pages;
* **display_options** *object* Optional. Defines additional display options for sign-in/sign-up pages. Used only when `display` is set to `popup` or `touch`. Available options are (see default values after):
    * `noheader` **boolean**. If true, the navigation bar and the header of the IS pages are not displayed.
    * `nofooter` **boolean**. If true, the footer of the IS pages are not displayed.
    * `lnk2bt` **boolean**. If true, form links will be turned into buttons.
    * `leglnk` **boolean**. If false, legals links are not displayed.

Default values:

| `display` value | `noheader` | `nofooter` | `lnk2bt` | `leglnk` |
|:---------------:|:----------:|:----------:|:--------:|:--------:|
| `popup` | false | false | false | true |
| `touch` | true | true | true | false |
| `iframe` | true | true | true | false |
| `page` | n/a | n/a | n/a | n/a |


* **callback_signin_success** *callback* Optional. The JS function to call after a successful sign-in. Default is `console.log`.
* **callback_signin_error** *callback* Optional. The JS function to call after an unsuccessful sign-in. Default is `console.error`.

```javascript
AsmodeeNet.init({
    ....,
    callback_signin_success: function(identity, code) {
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
         * The second parameter is the code returned by the Identity Server (same as AsmodeeNet.getCode() )
        */
    },
    callback_signin_error: function() {
        /**
         * arguments:
         *  If a query error occurs, arguments is a
         *  list a params coming from the ajax XHR request
         *
         * If the errors occurs for not authorized scope for the user (but user is good), the arguments are, in order, the html status code (403), "invalid_scope", "The scope requested is invalid for this user". In this case, the user is connected on the IS, but not token is returned. With iframe could be problematic if you don't manage this case, in the error callback.
         *
         * But that could be the message:
         *  "popup closed without signin"
         * if the user closes the popup without sign-in.
        */
    }
})
```
Available fields from the `identity` object of the callback_signin_success callback are listed [here](http://apidoc.asmodee.net/#api-openid-identity) and may vary depending on requested scopes.

### Discover

After the init phase, you should call the `discover()` method to use to discovery capacity of OpenID Connect to auto-configure other parts of the library.

```javascript
AsmodeeNet.discover();

// Or you can chain both calls :
AsmodeeNet.init({...}).discover();
```

This method will query the Identity Server to get the openid-configuration file, configure itself with data returned and finally query the JWKS files for JWS certification keys.

Unless you know what you are doing and need to specifically adjust some OpenID Connect settings, we must call this method to have everything set-up for you.

### Sign-in

After you are done with initialization and discovery, you can sign-in with the `signIn()` method which takes one parameter, as an object with the following entries:

 * `success` callback. Optional, default: `callback_signin_success`, see above.
 * `error` callback. Optional, default: `callback_signin_error`, see above.
 * `width` of the popup or of the iframe. Optional, default: 475px. Only makes sense for popup and iframe modes.
 * `height` of the popup or of the iframe. Optional, default: 500px. Only makes sense for popup and iframe modes.

 All these parameters are optional.

 **Note:** The `success` and `error` parameters are provided only for backward compatibility with previous versions of the library. They are ignored when the display mode is set to `page` or `touch`. Therefore we strongly recommend that you set these in the call to `AsmodeeNet.init()` in all cases.

```javascript
// Open the sign-in UI in a pop-up window
AsmodeeNet.init({
    client_id: 'my_client_id',
    redirect_uri: 'https://my_host.name/callback_page'
});
AsmodeeNet.discover();
AsmodeeNet.trackCb();
if (...user pushes a Sign-in button...) {
    AsmodeeNet.signIn({
        width: 500,
        height: 800
    })
}
```

If the user is already connected, no user interface will be displayed to the user and the success callback will be called immediately.

In popup mode, if the user closes the popup himself, the error callback will be called with the message `'popup closed without signin'`.

### Sign-Up

After you are done with initialization and discovery, you can sign-up with the `signUp()` method which takes two parameters. The first is a string with the locale wanted for the current user (Authorized locales are `de`, `en`, `es`, `fr` and `it`. The default if you give an other locale is `en`) and the second parameter is optional and is an object with the following entries:

 * `success` callback. Optional, default: `callback_signin_success`, see above.
 * `error` callback. Optional, default: `callback_signin_error`, see above.
 * `width` of the popup or of the iframe. Optional, default: 475px. Only makes sense for popup and iframe modes.
 * `height` of the popup or of the iframe. Optional, default: 500px. Only makes sense for popup and iframe modes.

 All these configuration entries for this second paramters are optional.

 **Note:** The `success` and `error` parameters are provided only for backward compatibility with previous versions of the library. They are ignored when the display mode is set to `page` or `touch`. Therefore we strongly recommend that you set these in the call to `AsmodeeNet.init()` in all cases.

```javascript
// Open the sign-in UI in a pop-up window
AsmodeeNet.init({
    client_id: 'my_client_id',
    redirect_uri: 'https://my_host.name/callback_page'
});
AsmodeeNet.discover();
AsmodeeNet.trackCb();
if (...user pushes a Sign-Up button...) {
    AsmodeeNet.signUp('fr', {
        width: 500,
        height: 800
    })
}
```

If the user is already connected, no user interface will be displayed to the user and the success callback will be called immediately.

In popup mode, if the user closes the popup himself, the error callback will be called with the message `'popup closed without signin'`.

### Reset my Password

After you are done with initialization and discovery, you can call reset my password form from Asmodee.net with the `resetPass()` method which takes two parameters. The first is a string with the locale wanted for the current user (Authorized locales are `de`, `en`, `es`, `fr` and `it`. The default if you give an other locale is `en`) and the second parameter is optional and is an object with the following entries:

 * `success` callback. Optional, default: `callback_signin_success`, see above.
 * `error` callback. Optional, default: `callback_signin_error`, see above.
 * `width` of the popup or of the iframe. Optional, default: 475px. Only makes sense for popup and iframe modes.
 * `height` of the popup or of the iframe. Optional, default: 500px. Only makes sense for popup and iframe modes.

 All these configuration entries for this second paramters are optional.

 **Note:** The `success` and `error` parameters are provided only for backward compatibility with previous versions of the library. They are ignored when the display mode is set to `page` or `touch`. Therefore we strongly recommend that you set these in the call to `AsmodeeNet.init()` in all cases.

```javascript
// Open the sign-in UI in a pop-up window
AsmodeeNet.init({
    client_id: 'my_client_id',
    redirect_uri: 'https://my_host.name/callback_page'
});
AsmodeeNet.discover();
AsmodeeNet.trackCb();
if (...user pushes a Reset my password button...) {
    AsmodeeNet.resetPass('de', {
        width: 500,
        height: 800
    })
}
```

In popup mode, if the user closes the popup himself, the error callback will be called with the message `'popup closed without signin'`.

### trackCb

This function ("Track Call-back") detects if the current page was called from the Identity Server, as the result of a sign-in or sign-up interaction. In this case, it stores temporarily the resulting connection data inside the browser local storage.

It takes an optional boolean parameter (default to true), which is relevant only in the popup display mode. If it's false, the popup window will not be closed. This is useful for debugging or in the case of an hybrid flow (see [Backend dialog](#backend-dialog) later for more details).

In all situations, the connection data is verified (JWT token verifications), and depending on its verification, the `callback_signin_success` or the `callback_signin_error` callback functions are called.

Therefore, you **must** call trackCb if you want the whole thing to work when returning from the Identity Server.

If you are looking for a super simple popup example, look at the [examples/index_popup.html](examples/index_popup.html) and [examples/cbpop.html](examples/cbpop.html) files.

Note that it's OK to place the call to trackCb at the very top of your HTML page (i.e. even before calling Asmodee.init() ). This will ensure the fastest closing of the popup window. The code is smart enough to work even without the initialization yet.

Please note that the OpenID Connect specifications require the connection data to be returned as an anchor in the redirect_uri. As a result, server-code won't be exposed to them.

### Sign-out

#### RP Logout

The Asmodee.net Identity Server supports the RP logout OpenID Connect feature. Therefore you can simply call the `signOut()` method to log out the user.

The IS `end_session` endpoint (described in the IS OpenID configuration discovery document) will be called. The user will be disconnect from the Asmodee.net Identity Server and redirected on your post-logout redirect uri (passed in parameters in the `init` method and set in your application configuration in the Studio Manager).


If a JS callback is provided in the init setting (`callback_post_logout_redirect`), it will be called in return of the IS in case of success.

In accordance with the [OpenID Connect RP Logout specification](https://openid.net/specs/openid-connect-session-1_0.html#RPLogout), you should remove your own session before the call of `AsmodeeNet.signOut()`.

```javascript
// Log out the user
AsmodeeNet.signOut();
```

**Note:** If you don't give a `callback_post_logout_redirect` callback, the root of your hostname will be loaded (`/`).


#### Simple Logout

If you don't want to use the OpenID Connect RP Logout feature of the Identity Server, you must not configure the `logout_redirect_uri` and `callback_post_logout_redirect` init's parameters. After you delete your session, call the `signOut()` method with an optional parameter: an object with a success callback.

```javascript
AsmodeeNet.signOut({
    success: function() {
        // User disconnected
    }
});
```

This method will clear the local storage containing the current connected user and will execute your callback.

**Note:** If you don't provide a success callback, the current page will be reloaded.

If you pass a callback, the page won't be reload. As a result, you can directly call the `signIn()` method again if you want. The `init()` and `discover()` methods don't need to be called again.

### Restore tokens

If you refresh your page, or after a restart of the browser, it could happens that the JS library lost the tokens of the user. So after, you can't call the identity method, or the signOut by example.

To prevent this, if you have saved the access token and id token in one way or another, in your session system by example, or in the app device, you can restore the "connected" status of the libray calling the method restoreTokens with the two tokens in arguments.

```javascript
AsmodeeNet.restoreTokens('eY[...]', 'eJ5[...]');
```

After this call, the JS Library has the same behavior as if it just do the sign-in call.

If you are in this situation, the right way is to call `restoreTokens` just after the `init` / `discover` calls.

Parameters of the method `restoreTokens`:
* **saved_access_token**: The **access token** as string, you stocked in your side (as cookie or local storage)
* **saved_id_token**: The **id token** as string, you stocked in your side (as cookie or local storage)
* **call_identity**: *optional* you can pass a third parameter, boolean, true by default. If it's true, after it validates the tokens, call the identity() method with the callback configured in the init method for signin callback (callback_signin_success and callback_signin_error)
* **cbdone**: *optional* A callback if resotre is a success. If a callback is passed, it will be call with one parameter (a boolean worth true). In default situation, `restoreTokens` return itself true
* **clear_before_refresh**: *optional* A callback for refresh tokens. If you have stocked the token as a cookie or in local storage in your code, and call `restoreTokens` with this tokens, and if tokens are expired, the `restoreTokens` method could try to refresh them (only once). To do it, it call first this *clear_before_refresh* callback, and you **must** remove your cookie/local storage for this tokens and return a boolean, if it's *true*, the `signIn` will be call to try to refresh the tokens, if it's false *nothing* is done.

### Other methods

The object `AsmodeeNet` provides the following additional methods:

* **identity**: Taking an optional parameter object with success and error callbacks ( {success: ..., error: ...}), calls the `identity` endpoint of the Identity Server. This method is called automatically by the `signIn()` method if successful. In most situations, you won't have to call this.
* **getAccessToken**: get the Access Token of the current user. Useful if you need to talk to the REST API after sign-in.
* **getAccessHash**: get the whole JSON object from the `authorize` endpoint (including access_token, id_token, etc.).
* **getIdToken**: get the ID Token of the current user. Use this if you want information about the user but don't care about talking to the REST API.
* **getDiscovery**: get the `discovery` object return from the `openid-configuration` endpoint. Can be useful for debugging.
* **getCode**: get the OpenID Connect "code" returned by the Identity Server. Useful in an hybrid flow.
* **getCheckErrors**: get the list of errors during the token check - if it failed.
* **getScopes**: get the OpenID Connect scopes returned by the Identity Server for the current user. It's an array of string.
* **getExpires**: get The expires date time of the current token, in unix timestamp format.
* **getExpiresDate**: get The expires date time of the current token, Javascript Date object.

### Backend dialog

If you want your backend to dialog with the Identity Server or API of Asmodee.net directly (server-to-server connection), you will have to authorize your backend as well.

This is accomplished by creating another app in the Studio Manager, with another client_id and its own client_secret. You can do this in your callback page.

As explained above in the `trackCb()` function, if you are in popup mode and that you perform a server-to-server authentication (OpenID Connect hybrid flow), you will want to keep the pop-up window open until the authentication completes. To do this, remember to set the `close` parameter to false when calling  `trackCb()`.

## Example

You will find one example per display mode in the directory examples.
The file index.html shows a simple example in `page` mode.
The file index_touch.html a simple example in `touch` mode.
The file index_popup.html a simple example in `popup` mode, using cbpop.html as the popup callback page.
The file index_iframe.html a simple example in `iframe` mode, using cbpop.html as the iframe callback page.

You can display errors and the identity in the page once logged, and you can sign-out. To run it, launch a simple Web server. For example, run in the examples directory `php -S localhost:XXXX`, or `ruby -run -ehttpd . -p XXXX` or another similar http server (see https://gist.github.com/willurd/5720255). If you have node, you can do:
```shell
npm install # if not done yet
grunt serve
```

Replace in the init call the `client_id` and `redirect_uri` parameters with the correct ones (set up an app with a redirect_uri value like http://localhost:XXXX ). And enjoy!

This example does not use SSL (because http servers don't manage SSL easily) but in production your page should be encapsulated with SSL of course!


## Tests

### Unit tests

Unit tests use Jasmine 2.8 as test framework with some usefull extends, jasmine-ajax 1.3.1 which can mimic and capture xhr query, and jasmine-expect based on Jasmine-Matchers which extends assertion and matchers

[Jasmine base page ](https://jasmine.github.io/pages/getting_started.html)
[Jasmine-ajax](https://github.com/jasmine/jasmine-ajax/tree/v1.3.1)
[Jasmine-expect/jasmine-matchers](https://github.com/JamieMason/Jasmine-Matchers)

After the command `npm install`, you can launch unit test with the command:
```
grunt test:unit
```

This command launch test in terminal and output result in terminal and reports them in tests/unit/junit/ in XML format compatible with Jenkins and you have test coverage in tests/unit/reports/coverage.xml

You can launch tests in real browser too:
```
grunt test:server
```

It will launch a node server and open default browser page on file tests/unit/SpecRunner.html. And you can saw test and test results in html page. You can launch specific test by the UI.

### Acceptance tests

Also called end-to-end (e2e) tests, this tests use [nightwatchjs](http://nightwatchjs.org). This test launch a node server will serve files of the directory tests/e2e/server, and execute acceptance tests on differente use cases of the AsmodeeNet SSO js library.

You can launch them by:
```
grunt test:e2e
```

This will output results in terminal (nightwatchjs is configured to use PhantomJS) and reports will be find in tests/e2e/reports in format usable by Jenkins.

This tests use Asmodee.net staging account server [https://account-staging.asmodee.net](https://account-staging.asmodee.net)

For testing this project depends on the [local-backends](https://github.com/daysofwonder/local-backends) project.
Before running the tests you have to install the local-backends root certificate in your system:

```sh
composer install # install the local-backends in vendor if not already done
make -C vendor/daysofwonder/local-backends init-ca
```

Note that this last command might ask you for your password to gain elevated privileges on some systems.

## TODO (not ordered, not closed)

* Query Scheduler (prevent signIn call before discover end by ex)
* Promise capacities
* Add events
* HTML data parser to generate an Asmodee.net OpenID Connect button.
* clean Error system
* REST API capacities
* ~~And some tests~~
* ...
