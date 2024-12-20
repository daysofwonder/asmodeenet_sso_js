/*!
 * https://github.com/es-shims/es5-shim
 * @license es5-shim Copyright 2009-2015 by contributors, MIT License
 * see https://github.com/es-shims/es5-shim/blob/master/LICENSE
 */
(function(t,r){"use strict";if(typeof define==="function"&&define.amd){define(r)}else if(typeof exports==="object"){module.exports=r()}else{t.returnExports=r()}})(this,function(){var t=Array;var r=t.prototype;var e=Object;var n=e.prototype;var i=Function;var a=i.prototype;var o=String;var f=o.prototype;var u=Number;var l=u.prototype;var s=r.slice;var c=r.splice;var v=r.push;var h=r.unshift;var p=r.concat;var y=r.join;var d=a.call;var g=a.apply;var w=Math.max;var b=Math.min;var T=n.toString;var m=typeof Symbol==="function"&&typeof Symbol.toStringTag==="symbol";var D;var S=Function.prototype.toString,x=/^\s*class /,O=function isES6ClassFn(t){try{var r=S.call(t);var e=r.replace(/\/\/.*\n/g,"");var n=e.replace(/\/\*[.\s\S]*\*\//g,"");var i=n.replace(/\n/gm," ").replace(/ {2}/g," ");return x.test(i)}catch(a){return false}},E=function tryFunctionObject(t){try{if(O(t)){return false}S.call(t);return true}catch(r){return false}},j="[object Function]",I="[object GeneratorFunction]",D=function isCallable(t){if(!t){return false}if(typeof t!=="function"&&typeof t!=="object"){return false}if(m){return E(t)}if(O(t)){return false}var r=T.call(t);return r===j||r===I};var M;var U=RegExp.prototype.exec,$=function tryRegexExec(t){try{U.call(t);return true}catch(r){return false}},F="[object RegExp]";M=function isRegex(t){if(typeof t!=="object"){return false}return m?$(t):T.call(t)===F};var N;var C=String.prototype.valueOf,k=function tryStringObject(t){try{C.call(t);return true}catch(r){return false}},A="[object String]";N=function isString(t){if(typeof t==="string"){return true}if(typeof t!=="object"){return false}return m?k(t):T.call(t)===A};var R=e.defineProperty&&function(){try{var t={};e.defineProperty(t,"x",{enumerable:false,value:t});for(var r in t){return false}return t.x===t}catch(n){return false}}();var P=function(t){var r;if(R){r=function(t,r,n,i){if(!i&&r in t){return}e.defineProperty(t,r,{configurable:true,enumerable:false,writable:true,value:n})}}else{r=function(t,r,e,n){if(!n&&r in t){return}t[r]=e}}return function defineProperties(e,n,i){for(var a in n){if(t.call(n,a)){r(e,a,n[a],i)}}}}(n.hasOwnProperty);var J=function isPrimitive(t){var r=typeof t;return t===null||r!=="object"&&r!=="function"};var Y=u.isNaN||function isActualNaN(t){return t!==t};var z={ToInteger:function ToInteger(t){var r=+t;if(Y(r)){r=0}else if(r!==0&&r!==1/0&&r!==-(1/0)){r=(r>0||-1)*Math.floor(Math.abs(r))}return r},ToPrimitive:function ToPrimitive(t){var r,e,n;if(J(t)){return t}e=t.valueOf;if(D(e)){r=e.call(t);if(J(r)){return r}}n=t.toString;if(D(n)){r=n.call(t);if(J(r)){return r}}throw new TypeError},ToObject:function(t){if(t==null){throw new TypeError("can't convert "+t+" to object")}return e(t)},ToUint32:function ToUint32(t){return t>>>0}};var Z=function Empty(){};P(a,{bind:function bind(t){var r=this;if(!D(r)){throw new TypeError("Function.prototype.bind called on incompatible "+r)}var n=s.call(arguments,1);var a;var o=function(){if(this instanceof a){var i=g.call(r,this,p.call(n,s.call(arguments)));if(e(i)===i){return i}return this}else{return g.call(r,t,p.call(n,s.call(arguments)))}};var f=w(0,r.length-n.length);var u=[];for(var l=0;l<f;l++){v.call(u,"$"+l)}a=i("binder","return function ("+y.call(u,",")+"){ return binder.apply(this, arguments); }")(o);if(r.prototype){Z.prototype=r.prototype;a.prototype=new Z;Z.prototype=null}return a}});var G=d.bind(n.hasOwnProperty);var H=d.bind(n.toString);var W=d.bind(s);var B=g.bind(s);if(typeof document==="object"&&document&&document.documentElement){try{W(document.documentElement.childNodes)}catch(X){var L=W;var q=B;W=function arraySliceIE(t){var r=[];var e=t.length;while(e-- >0){r[e]=t[e]}return q(r,L(arguments,1))};B=function arraySliceApplyIE(t,r){return q(W(t),r)}}}var K=d.bind(f.slice);var Q=d.bind(f.split);var V=d.bind(f.indexOf);var _=d.bind(v);var tt=d.bind(n.propertyIsEnumerable);var rt=d.bind(r.sort);var et=t.isArray||function isArray(t){return H(t)==="[object Array]"};var nt=[].unshift(0)!==1;P(r,{unshift:function(){h.apply(this,arguments);return this.length}},nt);P(t,{isArray:et});var it=e("a");var at=it[0]!=="a"||!(0 in it);var ot=function properlyBoxed(t){var r=true;var e=true;var n=false;if(t){try{t.call("foo",function(t,e,n){if(typeof n!=="object"){r=false}});t.call([1],function(){"use strict";e=typeof this==="string"},"x")}catch(i){n=true}}return!!t&&!n&&r&&e};P(r,{forEach:function forEach(t){var r=z.ToObject(this);var e=at&&N(this)?Q(this,""):r;var n=-1;var i=z.ToUint32(e.length);var a;if(arguments.length>1){a=arguments[1]}if(!D(t)){throw new TypeError("Array.prototype.forEach callback must be a function")}while(++n<i){if(n in e){if(typeof a==="undefined"){t(e[n],n,r)}else{t.call(a,e[n],n,r)}}}}},!ot(r.forEach));P(r,{map:function map(r){var e=z.ToObject(this);var n=at&&N(this)?Q(this,""):e;var i=z.ToUint32(n.length);var a=t(i);var o;if(arguments.length>1){o=arguments[1]}if(!D(r)){throw new TypeError("Array.prototype.map callback must be a function")}for(var f=0;f<i;f++){if(f in n){if(typeof o==="undefined"){a[f]=r(n[f],f,e)}else{a[f]=r.call(o,n[f],f,e)}}}return a}},!ot(r.map));P(r,{filter:function filter(t){var r=z.ToObject(this);var e=at&&N(this)?Q(this,""):r;var n=z.ToUint32(e.length);var i=[];var a;var o;if(arguments.length>1){o=arguments[1]}if(!D(t)){throw new TypeError("Array.prototype.filter callback must be a function")}for(var f=0;f<n;f++){if(f in e){a=e[f];if(typeof o==="undefined"?t(a,f,r):t.call(o,a,f,r)){_(i,a)}}}return i}},!ot(r.filter));P(r,{every:function every(t){var r=z.ToObject(this);var e=at&&N(this)?Q(this,""):r;var n=z.ToUint32(e.length);var i;if(arguments.length>1){i=arguments[1]}if(!D(t)){throw new TypeError("Array.prototype.every callback must be a function")}for(var a=0;a<n;a++){if(a in e&&!(typeof i==="undefined"?t(e[a],a,r):t.call(i,e[a],a,r))){return false}}return true}},!ot(r.every));P(r,{some:function some(t){var r=z.ToObject(this);var e=at&&N(this)?Q(this,""):r;var n=z.ToUint32(e.length);var i;if(arguments.length>1){i=arguments[1]}if(!D(t)){throw new TypeError("Array.prototype.some callback must be a function")}for(var a=0;a<n;a++){if(a in e&&(typeof i==="undefined"?t(e[a],a,r):t.call(i,e[a],a,r))){return true}}return false}},!ot(r.some));var ft=false;if(r.reduce){ft=typeof r.reduce.call("es5",function(t,r,e,n){return n})==="object"}P(r,{reduce:function reduce(t){var r=z.ToObject(this);var e=at&&N(this)?Q(this,""):r;var n=z.ToUint32(e.length);if(!D(t)){throw new TypeError("Array.prototype.reduce callback must be a function")}if(n===0&&arguments.length===1){throw new TypeError("reduce of empty array with no initial value")}var i=0;var a;if(arguments.length>=2){a=arguments[1]}else{do{if(i in e){a=e[i++];break}if(++i>=n){throw new TypeError("reduce of empty array with no initial value")}}while(true)}for(;i<n;i++){if(i in e){a=t(a,e[i],i,r)}}return a}},!ft);var ut=false;if(r.reduceRight){ut=typeof r.reduceRight.call("es5",function(t,r,e,n){return n})==="object"}P(r,{reduceRight:function reduceRight(t){var r=z.ToObject(this);var e=at&&N(this)?Q(this,""):r;var n=z.ToUint32(e.length);if(!D(t)){throw new TypeError("Array.prototype.reduceRight callback must be a function")}if(n===0&&arguments.length===1){throw new TypeError("reduceRight of empty array with no initial value")}var i;var a=n-1;if(arguments.length>=2){i=arguments[1]}else{do{if(a in e){i=e[a--];break}if(--a<0){throw new TypeError("reduceRight of empty array with no initial value")}}while(true)}if(a<0){return i}do{if(a in e){i=t(i,e[a],a,r)}}while(a--);return i}},!ut);var lt=r.indexOf&&[0,1].indexOf(1,2)!==-1;P(r,{indexOf:function indexOf(t){var r=at&&N(this)?Q(this,""):z.ToObject(this);var e=z.ToUint32(r.length);if(e===0){return-1}var n=0;if(arguments.length>1){n=z.ToInteger(arguments[1])}n=n>=0?n:w(0,e+n);for(;n<e;n++){if(n in r&&r[n]===t){return n}}return-1}},lt);var st=r.lastIndexOf&&[0,1].lastIndexOf(0,-3)!==-1;P(r,{lastIndexOf:function lastIndexOf(t){var r=at&&N(this)?Q(this,""):z.ToObject(this);var e=z.ToUint32(r.length);if(e===0){return-1}var n=e-1;if(arguments.length>1){n=b(n,z.ToInteger(arguments[1]))}n=n>=0?n:e-Math.abs(n);for(;n>=0;n--){if(n in r&&t===r[n]){return n}}return-1}},st);var ct=function(){var t=[1,2];var r=t.splice();return t.length===2&&et(r)&&r.length===0}();P(r,{splice:function splice(t,r){if(arguments.length===0){return[]}else{return c.apply(this,arguments)}}},!ct);var vt=function(){var t={};r.splice.call(t,0,0,1);return t.length===1}();P(r,{splice:function splice(t,r){if(arguments.length===0){return[]}var e=arguments;this.length=w(z.ToInteger(this.length),0);if(arguments.length>0&&typeof r!=="number"){e=W(arguments);if(e.length<2){_(e,this.length-t)}else{e[1]=z.ToInteger(r)}}return c.apply(this,e)}},!vt);var ht=function(){var r=new t(1e5);r[8]="x";r.splice(1,1);return r.indexOf("x")===7}();var pt=function(){var t=256;var r=[];r[t]="a";r.splice(t+1,0,"b");return r[t]==="a"}();P(r,{splice:function splice(t,r){var e=z.ToObject(this);var n=[];var i=z.ToUint32(e.length);var a=z.ToInteger(t);var f=a<0?w(i+a,0):b(a,i);var u=b(w(z.ToInteger(r),0),i-f);var l=0;var s;while(l<u){s=o(f+l);if(G(e,s)){n[l]=e[s]}l+=1}var c=W(arguments,2);var v=c.length;var h;if(v<u){l=f;var p=i-u;while(l<p){s=o(l+u);h=o(l+v);if(G(e,s)){e[h]=e[s]}else{delete e[h]}l+=1}l=i;var y=i-u+v;while(l>y){delete e[l-1];l-=1}}else if(v>u){l=i-u;while(l>f){s=o(l+u-1);h=o(l+v-1);if(G(e,s)){e[h]=e[s]}else{delete e[h]}l-=1}}l=f;for(var d=0;d<c.length;++d){e[l]=c[d];l+=1}e.length=i-u+v;return n}},!ht||!pt);var yt=r.join;var dt;try{dt=Array.prototype.join.call("123",",")!=="1,2,3"}catch(X){dt=true}if(dt){P(r,{join:function join(t){var r=typeof t==="undefined"?",":t;return yt.call(N(this)?Q(this,""):this,r)}},dt)}var gt=[1,2].join(undefined)!=="1,2";if(gt){P(r,{join:function join(t){var r=typeof t==="undefined"?",":t;return yt.call(this,r)}},gt)}var wt=function push(t){var r=z.ToObject(this);var e=z.ToUint32(r.length);var n=0;while(n<arguments.length){r[e+n]=arguments[n];n+=1}r.length=e+n;return e+n};var bt=function(){var t={};var r=Array.prototype.push.call(t,undefined);return r!==1||t.length!==1||typeof t[0]!=="undefined"||!G(t,0)}();P(r,{push:function push(t){if(et(this)){return v.apply(this,arguments)}return wt.apply(this,arguments)}},bt);var Tt=function(){var t=[];var r=t.push(undefined);return r!==1||t.length!==1||typeof t[0]!=="undefined"||!G(t,0)}();P(r,{push:wt},Tt);P(r,{slice:function(t,r){var e=N(this)?Q(this,""):this;return B(e,arguments)}},at);var mt=function(){try{[1,2].sort(null)}catch(t){try{[1,2].sort({})}catch(r){return false}}return true}();var Dt=function(){try{[1,2].sort(/a/);return false}catch(t){}return true}();var St=function(){try{[1,2].sort(undefined);return true}catch(t){}return false}();P(r,{sort:function sort(t){if(typeof t==="undefined"){return rt(this)}if(!D(t)){throw new TypeError("Array.prototype.sort callback must be a function")}return rt(this,t)}},mt||!St||!Dt);var xt=!tt({toString:null},"toString");var Ot=tt(function(){},"prototype");var Et=!G("x","0");var jt=function(t){var r=t.constructor;return r&&r.prototype===t};var It={$applicationCache:true,$console:true,$external:true,$frame:true,$frameElement:true,$frames:true,$innerHeight:true,$innerWidth:true,$onmozfullscreenchange:true,$onmozfullscreenerror:true,$outerHeight:true,$outerWidth:true,$pageXOffset:true,$pageYOffset:true,$parent:true,$scrollLeft:true,$scrollTop:true,$scrollX:true,$scrollY:true,$self:true,$webkitIndexedDB:true,$webkitStorageInfo:true,$window:true,$width:true,$height:true,$top:true,$localStorage:true};var Mt=function(){if(typeof window==="undefined"){return false}for(var t in window){try{if(!It["$"+t]&&G(window,t)&&window[t]!==null&&typeof window[t]==="object"){jt(window[t])}}catch(r){return true}}return false}();var Ut=function(t){if(typeof window==="undefined"||!Mt){return jt(t)}try{return jt(t)}catch(r){return false}};var $t=["toString","toLocaleString","valueOf","hasOwnProperty","isPrototypeOf","propertyIsEnumerable","constructor"];var Ft=$t.length;var Nt=function isArguments(t){return H(t)==="[object Arguments]"};var Ct=function isArguments(t){return t!==null&&typeof t==="object"&&typeof t.length==="number"&&t.length>=0&&!et(t)&&D(t.callee)};var kt=Nt(arguments)?Nt:Ct;P(e,{keys:function keys(t){var r=D(t);var e=kt(t);var n=t!==null&&typeof t==="object";var i=n&&N(t);if(!n&&!r&&!e){throw new TypeError("Object.keys called on a non-object")}var a=[];var f=Ot&&r;if(i&&Et||e){for(var u=0;u<t.length;++u){_(a,o(u))}}if(!e){for(var l in t){if(!(f&&l==="prototype")&&G(t,l)){_(a,o(l))}}}if(xt){var s=Ut(t);for(var c=0;c<Ft;c++){var v=$t[c];if(!(s&&v==="constructor")&&G(t,v)){_(a,v)}}}return a}});var At=e.keys&&function(){return e.keys(arguments).length===2}(1,2);var Rt=e.keys&&function(){var t=e.keys(arguments);return arguments.length!==1||t.length!==1||t[0]!==1}(1);var Pt=e.keys;P(e,{keys:function keys(t){if(kt(t)){return Pt(W(t))}else{return Pt(t)}}},!At||Rt);var Jt=new Date(-0xc782b5b342b24).getUTCMonth()!==0;var Yt=new Date(-0x55d318d56a724);var zt=new Date(14496624e5);var Zt=Yt.toUTCString()!=="Mon, 01 Jan -45875 11:59:59 GMT";var Gt;var Ht;var Wt=Yt.getTimezoneOffset();if(Wt<-720){Gt=Yt.toDateString()!=="Tue Jan 02 -45875";Ht=!/^Thu Dec 10 2015 \d\d:\d\d:\d\d GMT[-+]\d\d\d\d(?: |$)/.test(String(zt))}else{Gt=Yt.toDateString()!=="Mon Jan 01 -45875";Ht=!/^Wed Dec 09 2015 \d\d:\d\d:\d\d GMT[-+]\d\d\d\d(?: |$)/.test(String(zt))}var Bt=d.bind(Date.prototype.getFullYear);var Xt=d.bind(Date.prototype.getMonth);var Lt=d.bind(Date.prototype.getDate);var qt=d.bind(Date.prototype.getUTCFullYear);var Kt=d.bind(Date.prototype.getUTCMonth);var Qt=d.bind(Date.prototype.getUTCDate);var Vt=d.bind(Date.prototype.getUTCDay);var _t=d.bind(Date.prototype.getUTCHours);var tr=d.bind(Date.prototype.getUTCMinutes);var rr=d.bind(Date.prototype.getUTCSeconds);var er=d.bind(Date.prototype.getUTCMilliseconds);var nr=["Sun","Mon","Tue","Wed","Thu","Fri","Sat"];var ir=["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];var ar=function daysInMonth(t,r){return Lt(new Date(r,t,0))};P(Date.prototype,{getFullYear:function getFullYear(){if(!this||!(this instanceof Date)){throw new TypeError("this is not a Date object.")}var t=Bt(this);if(t<0&&Xt(this)>11){return t+1}return t},getMonth:function getMonth(){if(!this||!(this instanceof Date)){throw new TypeError("this is not a Date object.")}var t=Bt(this);var r=Xt(this);if(t<0&&r>11){return 0}return r},getDate:function getDate(){if(!this||!(this instanceof Date)){throw new TypeError("this is not a Date object.")}var t=Bt(this);var r=Xt(this);var e=Lt(this);if(t<0&&r>11){if(r===12){return e}var n=ar(0,t+1);return n-e+1}return e},getUTCFullYear:function getUTCFullYear(){if(!this||!(this instanceof Date)){throw new TypeError("this is not a Date object.")}var t=qt(this);if(t<0&&Kt(this)>11){return t+1}return t},getUTCMonth:function getUTCMonth(){if(!this||!(this instanceof Date)){throw new TypeError("this is not a Date object.")}var t=qt(this);var r=Kt(this);if(t<0&&r>11){return 0}return r},getUTCDate:function getUTCDate(){if(!this||!(this instanceof Date)){throw new TypeError("this is not a Date object.")}var t=qt(this);var r=Kt(this);var e=Qt(this);if(t<0&&r>11){if(r===12){return e}var n=ar(0,t+1);return n-e+1}return e}},Jt);P(Date.prototype,{toUTCString:function toUTCString(){if(!this||!(this instanceof Date)){throw new TypeError("this is not a Date object.")}var t=Vt(this);var r=Qt(this);var e=Kt(this);var n=qt(this);var i=_t(this);var a=tr(this);var o=rr(this);return nr[t]+", "+(r<10?"0"+r:r)+" "+ir[e]+" "+n+" "+(i<10?"0"+i:i)+":"+(a<10?"0"+a:a)+":"+(o<10?"0"+o:o)+" GMT"}},Jt||Zt);P(Date.prototype,{toDateString:function toDateString(){if(!this||!(this instanceof Date)){throw new TypeError("this is not a Date object.")}var t=this.getDay();var r=this.getDate();var e=this.getMonth();var n=this.getFullYear();return nr[t]+" "+ir[e]+" "+(r<10?"0"+r:r)+" "+n}},Jt||Gt);if(Jt||Ht){Date.prototype.toString=function toString(){if(!this||!(this instanceof Date)){throw new TypeError("this is not a Date object.")}var t=this.getDay();var r=this.getDate();var e=this.getMonth();var n=this.getFullYear();var i=this.getHours();var a=this.getMinutes();var o=this.getSeconds();var f=this.getTimezoneOffset();var u=Math.floor(Math.abs(f)/60);var l=Math.floor(Math.abs(f)%60);return nr[t]+" "+ir[e]+" "+(r<10?"0"+r:r)+" "+n+" "+(i<10?"0"+i:i)+":"+(a<10?"0"+a:a)+":"+(o<10?"0"+o:o)+" GMT"+(f>0?"-":"+")+(u<10?"0"+u:u)+(l<10?"0"+l:l)};if(R){e.defineProperty(Date.prototype,"toString",{configurable:true,enumerable:false,writable:true})}}var or=-621987552e5;var fr="-000001";var ur=Date.prototype.toISOString&&new Date(or).toISOString().indexOf(fr)===-1;var lr=Date.prototype.toISOString&&new Date(-1).toISOString()!=="1969-12-31T23:59:59.999Z";var sr=d.bind(Date.prototype.getTime);P(Date.prototype,{toISOString:function toISOString(){if(!isFinite(this)||!isFinite(sr(this))){throw new RangeError("Date.prototype.toISOString called on non-finite value.")}var t=qt(this);var r=Kt(this);t+=Math.floor(r/12);r=(r%12+12)%12;var e=[r+1,Qt(this),_t(this),tr(this),rr(this)];t=(t<0?"-":t>9999?"+":"")+K("00000"+Math.abs(t),0<=t&&t<=9999?-4:-6);for(var n=0;n<e.length;++n){e[n]=K("00"+e[n],-2)}return t+"-"+W(e,0,2).join("-")+"T"+W(e,2).join(":")+"."+K("000"+er(this),-3)+"Z"}},ur||lr);var cr=function(){try{return Date.prototype.toJSON&&new Date(NaN).toJSON()===null&&new Date(or).toJSON().indexOf(fr)!==-1&&Date.prototype.toJSON.call({toISOString:function(){return true}})}catch(t){return false}}();if(!cr){Date.prototype.toJSON=function toJSON(t){var r=e(this);var n=z.ToPrimitive(r);if(typeof n==="number"&&!isFinite(n)){return null}var i=r.toISOString;if(!D(i)){throw new TypeError("toISOString property is not callable")}return i.call(r)}}var vr=Date.parse("+033658-09-27T01:46:40.000Z")===1e15;var hr=!isNaN(Date.parse("2012-04-04T24:00:00.500Z"))||!isNaN(Date.parse("2012-11-31T23:59:59.000Z"))||!isNaN(Date.parse("2012-12-31T23:59:60.000Z"));var pr=isNaN(Date.parse("2000-01-01T00:00:00.000Z"));if(pr||hr||!vr){var yr=Math.pow(2,31)-1;var dr=Y(new Date(1970,0,1,0,0,0,yr+1).getTime());Date=function(t){var r=function Date(e,n,i,a,f,u,l){var s=arguments.length;var c;if(this instanceof t){var v=u;var h=l;if(dr&&s>=7&&l>yr){var p=Math.floor(l/yr)*yr;var y=Math.floor(p/1e3);v+=y;h-=y*1e3}c=s===1&&o(e)===e?new t(r.parse(e)):s>=7?new t(e,n,i,a,f,v,h):s>=6?new t(e,n,i,a,f,v):s>=5?new t(e,n,i,a,f):s>=4?new t(e,n,i,a):s>=3?new t(e,n,i):s>=2?new t(e,n):s>=1?new t(e instanceof t?+e:e):new t}else{c=t.apply(this,arguments)}if(!J(c)){P(c,{constructor:r},true)}return c};var e=new RegExp("^"+"(\\d{4}|[+-]\\d{6})"+"(?:-(\\d{2})"+"(?:-(\\d{2})"+"(?:"+"T(\\d{2})"+":(\\d{2})"+"(?:"+":(\\d{2})"+"(?:(\\.\\d{1,}))?"+")?"+"("+"Z|"+"(?:"+"([-+])"+"(\\d{2})"+":(\\d{2})"+")"+")?)?)?)?"+"$");var n=[0,31,59,90,120,151,181,212,243,273,304,334,365];var i=function dayFromMonth(t,r){var e=r>1?1:0;return n[r]+Math.floor((t-1969+e)/4)-Math.floor((t-1901+e)/100)+Math.floor((t-1601+e)/400)+365*(t-1970)};var a=function toUTC(r){var e=0;var n=r;if(dr&&n>yr){var i=Math.floor(n/yr)*yr;var a=Math.floor(i/1e3);e+=a;n-=a*1e3}return u(new t(1970,0,1,0,0,e,n))};for(var f in t){if(G(t,f)){r[f]=t[f]}}P(r,{now:t.now,UTC:t.UTC},true);r.prototype=t.prototype;P(r.prototype,{constructor:r},true);var l=function parse(r){var n=e.exec(r);if(n){var o=u(n[1]),f=u(n[2]||1)-1,l=u(n[3]||1)-1,s=u(n[4]||0),c=u(n[5]||0),v=u(n[6]||0),h=Math.floor(u(n[7]||0)*1e3),p=Boolean(n[4]&&!n[8]),y=n[9]==="-"?1:-1,d=u(n[10]||0),g=u(n[11]||0),w;var b=c>0||v>0||h>0;if(s<(b?24:25)&&c<60&&v<60&&h<1e3&&f>-1&&f<12&&d<24&&g<60&&l>-1&&l<i(o,f+1)-i(o,f)){w=((i(o,f)+l)*24+s+d*y)*60;w=((w+c+g*y)*60+v)*1e3+h;if(p){w=a(w)}if(-864e13<=w&&w<=864e13){return w}}return NaN}return t.parse.apply(this,arguments)};P(r,{parse:l});return r}(Date)}if(!Date.now){Date.now=function now(){return(new Date).getTime()}}var gr=l.toFixed&&(8e-5.toFixed(3)!=="0.000"||.9.toFixed(0)!=="1"||1.255.toFixed(2)!=="1.25"||(1000000000000000128).toFixed(0)!=="1000000000000000128");var wr={base:1e7,size:6,data:[0,0,0,0,0,0],multiply:function multiply(t,r){var e=-1;var n=r;while(++e<wr.size){n+=t*wr.data[e];wr.data[e]=n%wr.base;n=Math.floor(n/wr.base)}},divide:function divide(t){var r=wr.size;var e=0;while(--r>=0){e+=wr.data[r];wr.data[r]=Math.floor(e/t);e=e%t*wr.base}},numToString:function numToString(){var t=wr.size;var r="";while(--t>=0){if(r!==""||t===0||wr.data[t]!==0){var e=o(wr.data[t]);if(r===""){r=e}else{r+=K("0000000",0,7-e.length)+e}}}return r},pow:function pow(t,r,e){return r===0?e:r%2===1?pow(t,r-1,e*t):pow(t*t,r/2,e)},log:function log(t){var r=0;var e=t;while(e>=4096){r+=12;e/=4096}while(e>=2){r+=1;e/=2}return r}};var br=function toFixed(t){var r,e,n,i,a,f,l,s;r=u(t);r=Y(r)?0:Math.floor(r);if(r<0||r>20){throw new RangeError("Number.toFixed called with invalid number of decimals")}e=u(this);if(Y(e)){return"NaN"}if(e<=-1e21||e>=1e21){return o(e)}n="";if(e<0){n="-";e=-e}i="0";if(e>1e-21){a=wr.log(e*wr.pow(2,69,1))-69;f=a<0?e*wr.pow(2,-a,1):e/wr.pow(2,a,1);f*=4503599627370496;a=52-a;if(a>0){wr.multiply(0,f);l=r;while(l>=7){wr.multiply(1e7,0);l-=7}wr.multiply(wr.pow(10,l,1),0);l=a-1;while(l>=23){wr.divide(1<<23);l-=23}wr.divide(1<<l);wr.multiply(1,1);wr.divide(2);i=wr.numToString()}else{wr.multiply(0,f);wr.multiply(1<<-a,0);i=wr.numToString()+K("0.00000000000000000000",2,2+r)}}if(r>0){s=i.length;if(s<=r){i=n+K("0.0000000000000000000",0,r-s+2)+i}else{i=n+K(i,0,s-r)+"."+K(i,s-r)}}else{i=n+i}return i};P(l,{toFixed:br},gr);var Tr=function(){try{return 1..toPrecision(undefined)==="1"}catch(t){return true}}();var mr=l.toPrecision;P(l,{toPrecision:function toPrecision(t){return typeof t==="undefined"?mr.call(this):mr.call(this,t)}},Tr);if("ab".split(/(?:ab)*/).length!==2||".".split(/(.?)(.?)/).length!==4||"tesst".split(/(s)*/)[1]==="t"||"test".split(/(?:)/,-1).length!==4||"".split(/.?/).length||".".split(/()()/).length>1){(function(){var t=typeof/()??/.exec("")[1]==="undefined";var r=Math.pow(2,32)-1;f.split=function(e,n){var i=String(this);if(typeof e==="undefined"&&n===0){return[]}if(!M(e)){return Q(this,e,n)}var a=[];var o=(e.ignoreCase?"i":"")+(e.multiline?"m":"")+(e.unicode?"u":"")+(e.sticky?"y":""),f=0,u,l,s,c;var h=new RegExp(e.source,o+"g");if(!t){u=new RegExp("^"+h.source+"$(?!\\s)",o)}var p=typeof n==="undefined"?r:z.ToUint32(n);l=h.exec(i);while(l){s=l.index+l[0].length;if(s>f){_(a,K(i,f,l.index));if(!t&&l.length>1){l[0].replace(u,function(){for(var t=1;t<arguments.length-2;t++){if(typeof arguments[t]==="undefined"){l[t]=void 0}}})}if(l.length>1&&l.index<i.length){v.apply(a,W(l,1))}c=l[0].length;f=s;if(a.length>=p){break}}if(h.lastIndex===l.index){h.lastIndex++}l=h.exec(i)}if(f===i.length){if(c||!h.test("")){_(a,"")}}else{_(a,K(i,f))}return a.length>p?W(a,0,p):a}})()}else if("0".split(void 0,0).length){f.split=function split(t,r){if(typeof t==="undefined"&&r===0){return[]}return Q(this,t,r)}}var Dr=f.replace;var Sr=function(){var t=[];"x".replace(/x(.)?/g,function(r,e){_(t,e)});return t.length===1&&typeof t[0]==="undefined"}();if(!Sr){f.replace=function replace(t,r){var e=D(r);var n=M(t)&&/\)[*?]/.test(t.source);if(!e||!n){return Dr.call(this,t,r)}else{var i=function(e){var n=arguments.length;var i=t.lastIndex;t.lastIndex=0;var a=t.exec(e)||[];t.lastIndex=i;_(a,arguments[n-2],arguments[n-1]);return r.apply(this,a)};return Dr.call(this,t,i)}}}var xr=f.substr;var Or="".substr&&"0b".substr(-1)!=="b";P(f,{substr:function substr(t,r){var e=t;if(t<0){e=w(this.length+t,0)}return xr.call(this,e,r)}},Or);var Er="\t\n\x0B\f\r \xa0\u1680\u180e\u2000\u2001\u2002\u2003"+"\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u202f\u205f\u3000\u2028"+"\u2029\ufeff";var jr="\u200b";var Ir="["+Er+"]";var Mr=new RegExp("^"+Ir+Ir+"*");var Ur=new RegExp(Ir+Ir+"*$");var $r=f.trim&&(Er.trim()||!jr.trim());P(f,{trim:function trim(){if(typeof this==="undefined"||this===null){throw new TypeError("can't convert "+this+" to object")}return o(this).replace(Mr,"").replace(Ur,"")}},$r);var Fr=d.bind(String.prototype.trim);var Nr=f.lastIndexOf&&"abc\u3042\u3044".lastIndexOf("\u3042\u3044",2)!==-1;P(f,{lastIndexOf:function lastIndexOf(t){if(typeof this==="undefined"||this===null){throw new TypeError("can't convert "+this+" to object")}var r=o(this);var e=o(t);var n=arguments.length>1?u(arguments[1]):NaN;var i=Y(n)?Infinity:z.ToInteger(n);var a=b(w(i,0),r.length);var f=e.length;var l=a+f;while(l>0){l=w(0,l-f);var s=V(K(r,l,a+f),e);if(s!==-1){return l+s}}return-1}},Nr);var Cr=f.lastIndexOf;P(f,{lastIndexOf:function lastIndexOf(t){return Cr.apply(this,arguments)}},f.lastIndexOf.length!==1);if(parseInt(Er+"08")!==8||parseInt(Er+"0x16")!==22){parseInt=function(t){var r=/^[-+]?0[xX]/;return function parseInt(e,n){if(typeof e==="symbol"){""+e}var i=Fr(String(e));var a=u(n)||(r.test(i)?16:10);return t(i,a)}}(parseInt)}if(1/parseFloat("-0")!==-Infinity){parseFloat=function(t){return function parseFloat(r){var e=Fr(String(r));var n=t(e);return n===0&&K(e,0,1)==="-"?-0:n}}(parseFloat)}if(String(new RangeError("test"))!=="RangeError: test"){var kr=function toString(){if(typeof this==="undefined"||this===null){throw new TypeError("can't convert "+this+" to object")}var t=this.name;if(typeof t==="undefined"){t="Error"}else if(typeof t!=="string"){t=o(t)}var r=this.message;if(typeof r==="undefined"){r=""}else if(typeof r!=="string"){r=o(r)}if(!t){return r}if(!r){return t}return t+": "+r};Error.prototype.toString=kr}if(R){var Ar=function(t,r){if(tt(t,r)){var e=Object.getOwnPropertyDescriptor(t,r);if(e.configurable){e.enumerable=false;Object.defineProperty(t,r,e)}}};Ar(Error.prototype,"message");if(Error.prototype.message!==""){Error.prototype.message=""}Ar(Error.prototype,"name")}if(String(/a/gim)!=="/a/gim"){var Rr=function toString(){var t="/"+this.source+"/";if(this.global){t+="g"}if(this.ignoreCase){t+="i"}if(this.multiline){t+="m"}return t};RegExp.prototype.toString=Rr}});

/*! (c) Tom Wu | http://www-cs-students.stanford.edu/~tjw/jsbn/
 */
var b64map="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";var b64pad="=";function hex2b64(d){var b;var e;var a="";for(b=0;b+3<=d.length;b+=3){e=parseInt(d.substring(b,b+3),16);a+=b64map.charAt(e>>6)+b64map.charAt(e&63)}if(b+1==d.length){e=parseInt(d.substring(b,b+1),16);a+=b64map.charAt(e<<2)}else{if(b+2==d.length){e=parseInt(d.substring(b,b+2),16);a+=b64map.charAt(e>>2)+b64map.charAt((e&3)<<4)}}if(b64pad){while((a.length&3)>0){a+=b64pad}}return a}function b64tohex(f){var d="";var e;var b=0;var c;var a;for(e=0;e<f.length;++e){if(f.charAt(e)==b64pad){break}a=b64map.indexOf(f.charAt(e));if(a<0){continue}if(b==0){d+=int2char(a>>2);c=a&3;b=1}else{if(b==1){d+=int2char((c<<2)|(a>>4));c=a&15;b=2}else{if(b==2){d+=int2char(c);d+=int2char(a>>2);c=a&3;b=3}else{d+=int2char((c<<2)|(a>>4));d+=int2char(a&15);b=0}}}}if(b==1){d+=int2char(c<<2)}return d}function b64toBA(e){var d=b64tohex(e);var c;var b=new Array();for(c=0;2*c<d.length;++c){b[c]=parseInt(d.substring(2*c,2*c+2),16)}return b};
/*! (c) Tom Wu | http://www-cs-students.stanford.edu/~tjw/jsbn/
 */
var dbits;var canary=244837814094590;var j_lm=((canary&16777215)==15715070);function BigInteger(e,d,f){if(e!=null){if("number"==typeof e){this.fromNumber(e,d,f)}else{if(d==null&&"string"!=typeof e){this.fromString(e,256)}else{this.fromString(e,d)}}}}function nbi(){return new BigInteger(null)}function am1(f,a,b,e,h,g){while(--g>=0){var d=a*this[f++]+b[e]+h;h=Math.floor(d/67108864);b[e++]=d&67108863}return h}function am2(f,q,r,e,o,a){var k=q&32767,p=q>>15;while(--a>=0){var d=this[f]&32767;var g=this[f++]>>15;var b=p*d+g*k;d=k*d+((b&32767)<<15)+r[e]+(o&1073741823);o=(d>>>30)+(b>>>15)+p*g+(o>>>30);r[e++]=d&1073741823}return o}function am3(f,q,r,e,o,a){var k=q&16383,p=q>>14;while(--a>=0){var d=this[f]&16383;var g=this[f++]>>14;var b=p*d+g*k;d=k*d+((b&16383)<<14)+r[e]+o;o=(d>>28)+(b>>14)+p*g;r[e++]=d&268435455}return o}if(j_lm&&(navigator.appName=="Microsoft Internet Explorer")){BigInteger.prototype.am=am2;dbits=30}else{if(j_lm&&(navigator.appName!="Netscape")){BigInteger.prototype.am=am1;dbits=26}else{BigInteger.prototype.am=am3;dbits=28}}BigInteger.prototype.DB=dbits;BigInteger.prototype.DM=((1<<dbits)-1);BigInteger.prototype.DV=(1<<dbits);var BI_FP=52;BigInteger.prototype.FV=Math.pow(2,BI_FP);BigInteger.prototype.F1=BI_FP-dbits;BigInteger.prototype.F2=2*dbits-BI_FP;var BI_RM="0123456789abcdefghijklmnopqrstuvwxyz";var BI_RC=new Array();var rr,vv;rr="0".charCodeAt(0);for(vv=0;vv<=9;++vv){BI_RC[rr++]=vv}rr="a".charCodeAt(0);for(vv=10;vv<36;++vv){BI_RC[rr++]=vv}rr="A".charCodeAt(0);for(vv=10;vv<36;++vv){BI_RC[rr++]=vv}function int2char(a){return BI_RM.charAt(a)}function intAt(b,a){var d=BI_RC[b.charCodeAt(a)];return(d==null)?-1:d}function bnpCopyTo(b){for(var a=this.t-1;a>=0;--a){b[a]=this[a]}b.t=this.t;b.s=this.s}function bnpFromInt(a){this.t=1;this.s=(a<0)?-1:0;if(a>0){this[0]=a}else{if(a<-1){this[0]=a+this.DV}else{this.t=0}}}function nbv(a){var b=nbi();b.fromInt(a);return b}function bnpFromString(h,c){var e;if(c==16){e=4}else{if(c==8){e=3}else{if(c==256){e=8}else{if(c==2){e=1}else{if(c==32){e=5}else{if(c==4){e=2}else{this.fromRadix(h,c);return}}}}}}this.t=0;this.s=0;var g=h.length,d=false,f=0;while(--g>=0){var a=(e==8)?h[g]&255:intAt(h,g);if(a<0){if(h.charAt(g)=="-"){d=true}continue}d=false;if(f==0){this[this.t++]=a}else{if(f+e>this.DB){this[this.t-1]|=(a&((1<<(this.DB-f))-1))<<f;this[this.t++]=(a>>(this.DB-f))}else{this[this.t-1]|=a<<f}}f+=e;if(f>=this.DB){f-=this.DB}}if(e==8&&(h[0]&128)!=0){this.s=-1;if(f>0){this[this.t-1]|=((1<<(this.DB-f))-1)<<f}}this.clamp();if(d){BigInteger.ZERO.subTo(this,this)}}function bnpClamp(){var a=this.s&this.DM;while(this.t>0&&this[this.t-1]==a){--this.t}}function bnToString(c){if(this.s<0){return"-"+this.negate().toString(c)}var e;if(c==16){e=4}else{if(c==8){e=3}else{if(c==2){e=1}else{if(c==32){e=5}else{if(c==4){e=2}else{return this.toRadix(c)}}}}}var g=(1<<e)-1,l,a=false,h="",f=this.t;var j=this.DB-(f*this.DB)%e;if(f-->0){if(j<this.DB&&(l=this[f]>>j)>0){a=true;h=int2char(l)}while(f>=0){if(j<e){l=(this[f]&((1<<j)-1))<<(e-j);l|=this[--f]>>(j+=this.DB-e)}else{l=(this[f]>>(j-=e))&g;if(j<=0){j+=this.DB;--f}}if(l>0){a=true}if(a){h+=int2char(l)}}}return a?h:"0"}function bnNegate(){var a=nbi();BigInteger.ZERO.subTo(this,a);return a}function bnAbs(){return(this.s<0)?this.negate():this}function bnCompareTo(b){var d=this.s-b.s;if(d!=0){return d}var c=this.t;d=c-b.t;if(d!=0){return(this.s<0)?-d:d}while(--c>=0){if((d=this[c]-b[c])!=0){return d}}return 0}function nbits(a){var c=1,b;if((b=a>>>16)!=0){a=b;c+=16}if((b=a>>8)!=0){a=b;c+=8}if((b=a>>4)!=0){a=b;c+=4}if((b=a>>2)!=0){a=b;c+=2}if((b=a>>1)!=0){a=b;c+=1}return c}function bnBitLength(){if(this.t<=0){return 0}return this.DB*(this.t-1)+nbits(this[this.t-1]^(this.s&this.DM))}function bnpDLShiftTo(c,b){var a;for(a=this.t-1;a>=0;--a){b[a+c]=this[a]}for(a=c-1;a>=0;--a){b[a]=0}b.t=this.t+c;b.s=this.s}function bnpDRShiftTo(c,b){for(var a=c;a<this.t;++a){b[a-c]=this[a]}b.t=Math.max(this.t-c,0);b.s=this.s}function bnpLShiftTo(j,e){var b=j%this.DB;var a=this.DB-b;var g=(1<<a)-1;var f=Math.floor(j/this.DB),h=(this.s<<b)&this.DM,d;for(d=this.t-1;d>=0;--d){e[d+f+1]=(this[d]>>a)|h;h=(this[d]&g)<<b}for(d=f-1;d>=0;--d){e[d]=0}e[f]=h;e.t=this.t+f+1;e.s=this.s;e.clamp()}function bnpRShiftTo(g,d){d.s=this.s;var e=Math.floor(g/this.DB);if(e>=this.t){d.t=0;return}var b=g%this.DB;var a=this.DB-b;var f=(1<<b)-1;d[0]=this[e]>>b;for(var c=e+1;c<this.t;++c){d[c-e-1]|=(this[c]&f)<<a;d[c-e]=this[c]>>b}if(b>0){d[this.t-e-1]|=(this.s&f)<<a}d.t=this.t-e;d.clamp()}function bnpSubTo(d,f){var e=0,g=0,b=Math.min(d.t,this.t);while(e<b){g+=this[e]-d[e];f[e++]=g&this.DM;g>>=this.DB}if(d.t<this.t){g-=d.s;while(e<this.t){g+=this[e];f[e++]=g&this.DM;g>>=this.DB}g+=this.s}else{g+=this.s;while(e<d.t){g-=d[e];f[e++]=g&this.DM;g>>=this.DB}g-=d.s}f.s=(g<0)?-1:0;if(g<-1){f[e++]=this.DV+g}else{if(g>0){f[e++]=g}}f.t=e;f.clamp()}function bnpMultiplyTo(c,e){var b=this.abs(),f=c.abs();var d=b.t;e.t=d+f.t;while(--d>=0){e[d]=0}for(d=0;d<f.t;++d){e[d+b.t]=b.am(0,f[d],e,d,0,b.t)}e.s=0;e.clamp();if(this.s!=c.s){BigInteger.ZERO.subTo(e,e)}}function bnpSquareTo(d){var a=this.abs();var b=d.t=2*a.t;while(--b>=0){d[b]=0}for(b=0;b<a.t-1;++b){var e=a.am(b,a[b],d,2*b,0,1);if((d[b+a.t]+=a.am(b+1,2*a[b],d,2*b+1,e,a.t-b-1))>=a.DV){d[b+a.t]-=a.DV;d[b+a.t+1]=1}}if(d.t>0){d[d.t-1]+=a.am(b,a[b],d,2*b,0,1)}d.s=0;d.clamp()}function bnpDivRemTo(n,h,g){var w=n.abs();if(w.t<=0){return}var k=this.abs();if(k.t<w.t){if(h!=null){h.fromInt(0)}if(g!=null){this.copyTo(g)}return}if(g==null){g=nbi()}var d=nbi(),a=this.s,l=n.s;var v=this.DB-nbits(w[w.t-1]);if(v>0){w.lShiftTo(v,d);k.lShiftTo(v,g)}else{w.copyTo(d);k.copyTo(g)}var p=d.t;var b=d[p-1];if(b==0){return}var o=b*(1<<this.F1)+((p>1)?d[p-2]>>this.F2:0);var A=this.FV/o,z=(1<<this.F1)/o,x=1<<this.F2;var u=g.t,s=u-p,f=(h==null)?nbi():h;d.dlShiftTo(s,f);if(g.compareTo(f)>=0){g[g.t++]=1;g.subTo(f,g)}BigInteger.ONE.dlShiftTo(p,f);f.subTo(d,d);while(d.t<p){d[d.t++]=0}while(--s>=0){var c=(g[--u]==b)?this.DM:Math.floor(g[u]*A+(g[u-1]+x)*z);if((g[u]+=d.am(0,c,g,s,0,p))<c){d.dlShiftTo(s,f);g.subTo(f,g);while(g[u]<--c){g.subTo(f,g)}}}if(h!=null){g.drShiftTo(p,h);if(a!=l){BigInteger.ZERO.subTo(h,h)}}g.t=p;g.clamp();if(v>0){g.rShiftTo(v,g)}if(a<0){BigInteger.ZERO.subTo(g,g)}}function bnMod(b){var c=nbi();this.abs().divRemTo(b,null,c);if(this.s<0&&c.compareTo(BigInteger.ZERO)>0){b.subTo(c,c)}return c}function Classic(a){this.m=a}function cConvert(a){if(a.s<0||a.compareTo(this.m)>=0){return a.mod(this.m)}else{return a}}function cRevert(a){return a}function cReduce(a){a.divRemTo(this.m,null,a)}function cMulTo(a,c,b){a.multiplyTo(c,b);this.reduce(b)}function cSqrTo(a,b){a.squareTo(b);this.reduce(b)}Classic.prototype.convert=cConvert;Classic.prototype.revert=cRevert;Classic.prototype.reduce=cReduce;Classic.prototype.mulTo=cMulTo;Classic.prototype.sqrTo=cSqrTo;function bnpInvDigit(){if(this.t<1){return 0}var a=this[0];if((a&1)==0){return 0}var b=a&3;b=(b*(2-(a&15)*b))&15;b=(b*(2-(a&255)*b))&255;b=(b*(2-(((a&65535)*b)&65535)))&65535;b=(b*(2-a*b%this.DV))%this.DV;return(b>0)?this.DV-b:-b}function Montgomery(a){this.m=a;this.mp=a.invDigit();this.mpl=this.mp&32767;this.mph=this.mp>>15;this.um=(1<<(a.DB-15))-1;this.mt2=2*a.t}function montConvert(a){var b=nbi();a.abs().dlShiftTo(this.m.t,b);b.divRemTo(this.m,null,b);if(a.s<0&&b.compareTo(BigInteger.ZERO)>0){this.m.subTo(b,b)}return b}function montRevert(a){var b=nbi();a.copyTo(b);this.reduce(b);return b}function montReduce(a){while(a.t<=this.mt2){a[a.t++]=0}for(var c=0;c<this.m.t;++c){var b=a[c]&32767;var d=(b*this.mpl+(((b*this.mph+(a[c]>>15)*this.mpl)&this.um)<<15))&a.DM;b=c+this.m.t;a[b]+=this.m.am(0,d,a,c,0,this.m.t);while(a[b]>=a.DV){a[b]-=a.DV;a[++b]++}}a.clamp();a.drShiftTo(this.m.t,a);if(a.compareTo(this.m)>=0){a.subTo(this.m,a)}}function montSqrTo(a,b){a.squareTo(b);this.reduce(b)}function montMulTo(a,c,b){a.multiplyTo(c,b);this.reduce(b)}Montgomery.prototype.convert=montConvert;Montgomery.prototype.revert=montRevert;Montgomery.prototype.reduce=montReduce;Montgomery.prototype.mulTo=montMulTo;Montgomery.prototype.sqrTo=montSqrTo;function bnpIsEven(){return((this.t>0)?(this[0]&1):this.s)==0}function bnpExp(h,j){if(h>4294967295||h<1){return BigInteger.ONE}var f=nbi(),a=nbi(),d=j.convert(this),c=nbits(h)-1;d.copyTo(f);while(--c>=0){j.sqrTo(f,a);if((h&(1<<c))>0){j.mulTo(a,d,f)}else{var b=f;f=a;a=b}}return j.revert(f)}function bnModPowInt(b,a){var c;if(b<256||a.isEven()){c=new Classic(a)}else{c=new Montgomery(a)}return this.exp(b,c)}BigInteger.prototype.copyTo=bnpCopyTo;BigInteger.prototype.fromInt=bnpFromInt;BigInteger.prototype.fromString=bnpFromString;BigInteger.prototype.clamp=bnpClamp;BigInteger.prototype.dlShiftTo=bnpDLShiftTo;BigInteger.prototype.drShiftTo=bnpDRShiftTo;BigInteger.prototype.lShiftTo=bnpLShiftTo;BigInteger.prototype.rShiftTo=bnpRShiftTo;BigInteger.prototype.subTo=bnpSubTo;BigInteger.prototype.multiplyTo=bnpMultiplyTo;BigInteger.prototype.squareTo=bnpSquareTo;BigInteger.prototype.divRemTo=bnpDivRemTo;BigInteger.prototype.invDigit=bnpInvDigit;BigInteger.prototype.isEven=bnpIsEven;BigInteger.prototype.exp=bnpExp;BigInteger.prototype.toString=bnToString;BigInteger.prototype.negate=bnNegate;BigInteger.prototype.abs=bnAbs;BigInteger.prototype.compareTo=bnCompareTo;BigInteger.prototype.bitLength=bnBitLength;BigInteger.prototype.mod=bnMod;BigInteger.prototype.modPowInt=bnModPowInt;BigInteger.ZERO=nbv(0);BigInteger.ONE=nbv(1);
/*! Mike Samuel (c) 2009 | code.google.com/p/json-sans-eval
 */
var jsonParse=(function(){var e="(?:-?\\b(?:0|[1-9][0-9]*)(?:\\.[0-9]+)?(?:[eE][+-]?[0-9]+)?\\b)";var j='(?:[^\\0-\\x08\\x0a-\\x1f"\\\\]|\\\\(?:["/\\\\bfnrt]|u[0-9A-Fa-f]{4}))';var i='(?:"'+j+'*")';var d=new RegExp("(?:false|true|null|[\\{\\}\\[\\]]|"+e+"|"+i+")","g");var k=new RegExp("\\\\(?:([^u])|u(.{4}))","g");var g={'"':'"',"/":"/","\\":"\\",b:"\b",f:"\f",n:"\n",r:"\r",t:"\t"};function h(l,m,n){return m?g[m]:String.fromCharCode(parseInt(n,16))}var c=new String("");var a="\\";var f={"{":Object,"[":Array};var b=Object.hasOwnProperty;return function(u,q){var p=u.match(d);var x;var v=p[0];var l=false;if("{"===v){x={}}else{if("["===v){x=[]}else{x=[];l=true}}var t;var r=[x];for(var o=1-l,m=p.length;o<m;++o){v=p[o];var w;switch(v.charCodeAt(0)){default:w=r[0];w[t||w.length]=+(v);t=void 0;break;case 34:v=v.substring(1,v.length-1);if(v.indexOf(a)!==-1){v=v.replace(k,h)}w=r[0];if(!t){if(w instanceof Array){t=w.length}else{t=v||c;break}}w[t]=v;t=void 0;break;case 91:w=r[0];r.unshift(w[t||w.length]=[]);t=void 0;break;case 93:r.shift();break;case 102:w=r[0];w[t||w.length]=false;t=void 0;break;case 110:w=r[0];w[t||w.length]=null;t=void 0;break;case 116:w=r[0];w[t||w.length]=true;t=void 0;break;case 123:w=r[0];r.unshift(w[t||w.length]={});t=void 0;break;case 125:r.shift();break}}if(l){if(r.length!==1){throw new Error()}x=x[0]}else{if(r.length){throw new Error()}}if(q){var s=function(C,B){var D=C[B];if(D&&typeof D==="object"){var n=null;for(var z in D){if(b.call(D,z)&&D!==C){var y=s(D,z);if(y!==void 0){D[z]=y}else{if(!n){n=[]}n.push(z)}}}if(n){for(var A=n.length;--A>=0;){delete D[n[A]]}}}return q.call(C,B,D)};x=s({"":x},"")}return x}})();
/*! CryptoJS v3.1.2 core-fix.js
 * code.google.com/p/crypto-js
 * (c) 2009-2013 by Jeff Mott. All rights reserved.
 * code.google.com/p/crypto-js/wiki/License
 * THIS IS FIX of 'core.js' to fix Hmac issue.
 * https://code.google.com/p/crypto-js/issues/detail?id=84
 * https://crypto-js.googlecode.com/svn-history/r667/branches/3.x/src/core.js
 */
var CryptoJS=CryptoJS||(function(e,g){var a={};var b=a.lib={};var j=b.Base=(function(){function n(){}return{extend:function(p){n.prototype=this;var o=new n();if(p){o.mixIn(p)}if(!o.hasOwnProperty("init")){o.init=function(){o.$super.init.apply(this,arguments)}}o.init.prototype=o;o.$super=this;return o},create:function(){var o=this.extend();o.init.apply(o,arguments);return o},init:function(){},mixIn:function(p){for(var o in p){if(p.hasOwnProperty(o)){this[o]=p[o]}}if(p.hasOwnProperty("toString")){this.toString=p.toString}},clone:function(){return this.init.prototype.extend(this)}}}());var l=b.WordArray=j.extend({init:function(o,n){o=this.words=o||[];if(n!=g){this.sigBytes=n}else{this.sigBytes=o.length*4}},toString:function(n){return(n||h).stringify(this)},concat:function(t){var q=this.words;var p=t.words;var n=this.sigBytes;var s=t.sigBytes;this.clamp();if(n%4){for(var r=0;r<s;r++){var o=(p[r>>>2]>>>(24-(r%4)*8))&255;q[(n+r)>>>2]|=o<<(24-((n+r)%4)*8)}}else{for(var r=0;r<s;r+=4){q[(n+r)>>>2]=p[r>>>2]}}this.sigBytes+=s;return this},clamp:function(){var o=this.words;var n=this.sigBytes;o[n>>>2]&=4294967295<<(32-(n%4)*8);o.length=e.ceil(n/4)},clone:function(){var n=j.clone.call(this);n.words=this.words.slice(0);return n},random:function(p){var o=[];for(var n=0;n<p;n+=4){o.push((e.random()*4294967296)|0)}return new l.init(o,p)}});var m=a.enc={};var h=m.Hex={stringify:function(p){var r=p.words;var o=p.sigBytes;var q=[];for(var n=0;n<o;n++){var s=(r[n>>>2]>>>(24-(n%4)*8))&255;q.push((s>>>4).toString(16));q.push((s&15).toString(16))}return q.join("")},parse:function(p){var n=p.length;var q=[];for(var o=0;o<n;o+=2){q[o>>>3]|=parseInt(p.substr(o,2),16)<<(24-(o%8)*4)}return new l.init(q,n/2)}};var d=m.Latin1={stringify:function(q){var r=q.words;var p=q.sigBytes;var n=[];for(var o=0;o<p;o++){var s=(r[o>>>2]>>>(24-(o%4)*8))&255;n.push(String.fromCharCode(s))}return n.join("")},parse:function(p){var n=p.length;var q=[];for(var o=0;o<n;o++){q[o>>>2]|=(p.charCodeAt(o)&255)<<(24-(o%4)*8)}return new l.init(q,n)}};var c=m.Utf8={stringify:function(n){try{return decodeURIComponent(escape(d.stringify(n)))}catch(o){throw new Error("Malformed UTF-8 data")}},parse:function(n){return d.parse(unescape(encodeURIComponent(n)))}};var i=b.BufferedBlockAlgorithm=j.extend({reset:function(){this._data=new l.init();this._nDataBytes=0},_append:function(n){if(typeof n=="string"){n=c.parse(n)}this._data.concat(n);this._nDataBytes+=n.sigBytes},_process:function(w){var q=this._data;var x=q.words;var n=q.sigBytes;var t=this.blockSize;var v=t*4;var u=n/v;if(w){u=e.ceil(u)}else{u=e.max((u|0)-this._minBufferSize,0)}var s=u*t;var r=e.min(s*4,n);if(s){for(var p=0;p<s;p+=t){this._doProcessBlock(x,p)}var o=x.splice(0,s);q.sigBytes-=r}return new l.init(o,r)},clone:function(){var n=j.clone.call(this);n._data=this._data.clone();return n},_minBufferSize:0});var f=b.Hasher=i.extend({cfg:j.extend(),init:function(n){this.cfg=this.cfg.extend(n);this.reset()},reset:function(){i.reset.call(this);this._doReset()},update:function(n){this._append(n);this._process();return this},finalize:function(n){if(n){this._append(n)}var o=this._doFinalize();return o},blockSize:512/32,_createHelper:function(n){return function(p,o){return new n.init(o).finalize(p)}},_createHmacHelper:function(n){return function(p,o){return new k.HMAC.init(n,o).finalize(p)}}});var k=a.algo={};return a}(Math));
/*
CryptoJS v3.1.2
code.google.com/p/crypto-js
(c) 2009-2013 by Jeff Mott. All rights reserved.
code.google.com/p/crypto-js/wiki/License
*/
var CryptoJS=CryptoJS||function(h,s){var f={},g=f.lib={},q=function(){},m=g.Base={extend:function(a){q.prototype=this;var c=new q;a&&c.mixIn(a);c.hasOwnProperty("init")||(c.init=function(){c.$super.init.apply(this,arguments)});c.init.prototype=c;c.$super=this;return c},create:function(){var a=this.extend();a.init.apply(a,arguments);return a},init:function(){},mixIn:function(a){for(var c in a)a.hasOwnProperty(c)&&(this[c]=a[c]);a.hasOwnProperty("toString")&&(this.toString=a.toString)},clone:function(){return this.init.prototype.extend(this)}},
r=g.WordArray=m.extend({init:function(a,c){a=this.words=a||[];this.sigBytes=c!=s?c:4*a.length},toString:function(a){return(a||k).stringify(this)},concat:function(a){var c=this.words,d=a.words,b=this.sigBytes;a=a.sigBytes;this.clamp();if(b%4)for(var e=0;e<a;e++)c[b+e>>>2]|=(d[e>>>2]>>>24-8*(e%4)&255)<<24-8*((b+e)%4);else if(65535<d.length)for(e=0;e<a;e+=4)c[b+e>>>2]=d[e>>>2];else c.push.apply(c,d);this.sigBytes+=a;return this},clamp:function(){var a=this.words,c=this.sigBytes;a[c>>>2]&=4294967295<<
32-8*(c%4);a.length=h.ceil(c/4)},clone:function(){var a=m.clone.call(this);a.words=this.words.slice(0);return a},random:function(a){for(var c=[],d=0;d<a;d+=4)c.push(4294967296*h.random()|0);return new r.init(c,a)}}),l=f.enc={},k=l.Hex={stringify:function(a){var c=a.words;a=a.sigBytes;for(var d=[],b=0;b<a;b++){var e=c[b>>>2]>>>24-8*(b%4)&255;d.push((e>>>4).toString(16));d.push((e&15).toString(16))}return d.join("")},parse:function(a){for(var c=a.length,d=[],b=0;b<c;b+=2)d[b>>>3]|=parseInt(a.substr(b,
2),16)<<24-4*(b%8);return new r.init(d,c/2)}},n=l.Latin1={stringify:function(a){var c=a.words;a=a.sigBytes;for(var d=[],b=0;b<a;b++)d.push(String.fromCharCode(c[b>>>2]>>>24-8*(b%4)&255));return d.join("")},parse:function(a){for(var c=a.length,d=[],b=0;b<c;b++)d[b>>>2]|=(a.charCodeAt(b)&255)<<24-8*(b%4);return new r.init(d,c)}},j=l.Utf8={stringify:function(a){try{return decodeURIComponent(escape(n.stringify(a)))}catch(c){throw Error("Malformed UTF-8 data");}},parse:function(a){return n.parse(unescape(encodeURIComponent(a)))}},
u=g.BufferedBlockAlgorithm=m.extend({reset:function(){this._data=new r.init;this._nDataBytes=0},_append:function(a){"string"==typeof a&&(a=j.parse(a));this._data.concat(a);this._nDataBytes+=a.sigBytes},_process:function(a){var c=this._data,d=c.words,b=c.sigBytes,e=this.blockSize,f=b/(4*e),f=a?h.ceil(f):h.max((f|0)-this._minBufferSize,0);a=f*e;b=h.min(4*a,b);if(a){for(var g=0;g<a;g+=e)this._doProcessBlock(d,g);g=d.splice(0,a);c.sigBytes-=b}return new r.init(g,b)},clone:function(){var a=m.clone.call(this);
a._data=this._data.clone();return a},_minBufferSize:0});g.Hasher=u.extend({cfg:m.extend(),init:function(a){this.cfg=this.cfg.extend(a);this.reset()},reset:function(){u.reset.call(this);this._doReset()},update:function(a){this._append(a);this._process();return this},finalize:function(a){a&&this._append(a);return this._doFinalize()},blockSize:16,_createHelper:function(a){return function(c,d){return(new a.init(d)).finalize(c)}},_createHmacHelper:function(a){return function(c,d){return(new t.HMAC.init(a,
d)).finalize(c)}}});var t=f.algo={};return f}(Math);
(function(h){for(var s=CryptoJS,f=s.lib,g=f.WordArray,q=f.Hasher,f=s.algo,m=[],r=[],l=function(a){return 4294967296*(a-(a|0))|0},k=2,n=0;64>n;){var j;a:{j=k;for(var u=h.sqrt(j),t=2;t<=u;t++)if(!(j%t)){j=!1;break a}j=!0}j&&(8>n&&(m[n]=l(h.pow(k,0.5))),r[n]=l(h.pow(k,1/3)),n++);k++}var a=[],f=f.SHA256=q.extend({_doReset:function(){this._hash=new g.init(m.slice(0))},_doProcessBlock:function(c,d){for(var b=this._hash.words,e=b[0],f=b[1],g=b[2],j=b[3],h=b[4],m=b[5],n=b[6],q=b[7],p=0;64>p;p++){if(16>p)a[p]=
c[d+p]|0;else{var k=a[p-15],l=a[p-2];a[p]=((k<<25|k>>>7)^(k<<14|k>>>18)^k>>>3)+a[p-7]+((l<<15|l>>>17)^(l<<13|l>>>19)^l>>>10)+a[p-16]}k=q+((h<<26|h>>>6)^(h<<21|h>>>11)^(h<<7|h>>>25))+(h&m^~h&n)+r[p]+a[p];l=((e<<30|e>>>2)^(e<<19|e>>>13)^(e<<10|e>>>22))+(e&f^e&g^f&g);q=n;n=m;m=h;h=j+k|0;j=g;g=f;f=e;e=k+l|0}b[0]=b[0]+e|0;b[1]=b[1]+f|0;b[2]=b[2]+g|0;b[3]=b[3]+j|0;b[4]=b[4]+h|0;b[5]=b[5]+m|0;b[6]=b[6]+n|0;b[7]=b[7]+q|0},_doFinalize:function(){var a=this._data,d=a.words,b=8*this._nDataBytes,e=8*a.sigBytes;
d[e>>>5]|=128<<24-e%32;d[(e+64>>>9<<4)+14]=h.floor(b/4294967296);d[(e+64>>>9<<4)+15]=b;a.sigBytes=4*d.length;this._process();return this._hash},clone:function(){var a=q.clone.call(this);a._hash=this._hash.clone();return a}});s.SHA256=q._createHelper(f);s.HmacSHA256=q._createHmacHelper(f)})(Math);
(function(){var h=CryptoJS,s=h.enc.Utf8;h.algo.HMAC=h.lib.Base.extend({init:function(f,g){f=this._hasher=new f.init;"string"==typeof g&&(g=s.parse(g));var h=f.blockSize,m=4*h;g.sigBytes>m&&(g=f.finalize(g));g.clamp();for(var r=this._oKey=g.clone(),l=this._iKey=g.clone(),k=r.words,n=l.words,j=0;j<h;j++)k[j]^=1549556828,n[j]^=909522486;r.sigBytes=l.sigBytes=m;this.reset()},reset:function(){var f=this._hasher;f.reset();f.update(this._iKey)},update:function(f){this._hasher.update(f);return this},finalize:function(f){var g=
this._hasher;f=g.finalize(f);g.reset();return g.finalize(this._oKey.clone().concat(f))}})})();

/* store.js - Copyright (c) 2010-2017 Marcus Westin */
!function(e){if("object"==typeof exports&&"undefined"!=typeof module)module.exports=e();else if("function"==typeof define&&define.amd)define([],e);else{var t;t="undefined"!=typeof window?window:"undefined"!=typeof global?global:"undefined"!=typeof self?self:this,t.store=e()}}(function(){var define,module,exports;return function e(t,n,r){function o(u,a){if(!n[u]){if(!t[u]){var c="function"==typeof require&&require;if(!a&&c)return c(u,!0);if(i)return i(u,!0);var f=new Error("Cannot find module '"+u+"'");throw f.code="MODULE_NOT_FOUND",f}var s=n[u]={exports:{}};t[u][0].call(s.exports,function(e){var n=t[u][1][e];return o(n?n:e)},s,s.exports,e,t,n,r)}return n[u].exports}for(var i="function"==typeof require&&require,u=0;u<r.length;u++)o(r[u]);return o}({1:[function(e,t,n){"use strict";var r=e("../src/store-engine"),o=e("../storages/all"),i=[e("../plugins/json2")];t.exports=r.createStore(o,i)},{"../plugins/json2":2,"../src/store-engine":4,"../storages/all":6}],2:[function(e,t,n){"use strict";function r(){return e("./lib/json2"),{}}t.exports=r},{"./lib/json2":3}],3:[function(require,module,exports){"use strict";var _typeof="function"==typeof Symbol&&"symbol"==typeof Symbol.iterator?function(e){return typeof e}:function(e){return e&&"function"==typeof Symbol&&e.constructor===Symbol&&e!==Symbol.prototype?"symbol":typeof e};"object"!==("undefined"==typeof JSON?"undefined":_typeof(JSON))&&(JSON={}),function(){function f(e){return e<10?"0"+e:e}function this_value(){return this.valueOf()}function quote(e){return rx_escapable.lastIndex=0,rx_escapable.test(e)?'"'+e.replace(rx_escapable,function(e){var t=meta[e];return"string"==typeof t?t:"\\u"+("0000"+e.charCodeAt(0).toString(16)).slice(-4)})+'"':'"'+e+'"'}function str(e,t){var n,r,o,i,u,a=gap,c=t[e];switch(c&&"object"===("undefined"==typeof c?"undefined":_typeof(c))&&"function"==typeof c.toJSON&&(c=c.toJSON(e)),"function"==typeof rep&&(c=rep.call(t,e,c)),"undefined"==typeof c?"undefined":_typeof(c)){case"string":return quote(c);case"number":return isFinite(c)?String(c):"null";case"boolean":case"null":return String(c);case"object":if(!c)return"null";if(gap+=indent,u=[],"[object Array]"===Object.prototype.toString.apply(c)){for(i=c.length,n=0;n<i;n+=1)u[n]=str(n,c)||"null";return o=0===u.length?"[]":gap?"[\n"+gap+u.join(",\n"+gap)+"\n"+a+"]":"["+u.join(",")+"]",gap=a,o}if(rep&&"object"===("undefined"==typeof rep?"undefined":_typeof(rep)))for(i=rep.length,n=0;n<i;n+=1)"string"==typeof rep[n]&&(r=rep[n],o=str(r,c),o&&u.push(quote(r)+(gap?": ":":")+o));else for(r in c)Object.prototype.hasOwnProperty.call(c,r)&&(o=str(r,c),o&&u.push(quote(r)+(gap?": ":":")+o));return o=0===u.length?"{}":gap?"{\n"+gap+u.join(",\n"+gap)+"\n"+a+"}":"{"+u.join(",")+"}",gap=a,o}}var rx_one=/^[\],:{}\s]*$/,rx_two=/\\(?:["\\\/bfnrt]|u[0-9a-fA-F]{4})/g,rx_three=/"[^"\\\n\r]*"|true|false|null|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?/g,rx_four=/(?:^|:|,)(?:\s*\[)+/g,rx_escapable=/[\\"\u0000-\u001f\u007f-\u009f\u00ad\u0600-\u0604\u070f\u17b4\u17b5\u200c-\u200f\u2028-\u202f\u2060-\u206f\ufeff\ufff0-\uffff]/g,rx_dangerous=/[\u0000\u00ad\u0600-\u0604\u070f\u17b4\u17b5\u200c-\u200f\u2028-\u202f\u2060-\u206f\ufeff\ufff0-\uffff]/g;"function"!=typeof Date.prototype.toJSON&&(Date.prototype.toJSON=function(){return isFinite(this.valueOf())?this.getUTCFullYear()+"-"+f(this.getUTCMonth()+1)+"-"+f(this.getUTCDate())+"T"+f(this.getUTCHours())+":"+f(this.getUTCMinutes())+":"+f(this.getUTCSeconds())+"Z":null},Boolean.prototype.toJSON=this_value,Number.prototype.toJSON=this_value,String.prototype.toJSON=this_value);var gap,indent,meta,rep;"function"!=typeof JSON.stringify&&(meta={"\b":"\\b","\t":"\\t","\n":"\\n","\f":"\\f","\r":"\\r",'"':'\\"',"\\":"\\\\"},JSON.stringify=function(e,t,n){var r;if(gap="",indent="","number"==typeof n)for(r=0;r<n;r+=1)indent+=" ";else"string"==typeof n&&(indent=n);if(rep=t,t&&"function"!=typeof t&&("object"!==("undefined"==typeof t?"undefined":_typeof(t))||"number"!=typeof t.length))throw new Error("JSON.stringify");return str("",{"":e})}),"function"!=typeof JSON.parse&&(JSON.parse=function(text,reviver){function walk(e,t){var n,r,o=e[t];if(o&&"object"===("undefined"==typeof o?"undefined":_typeof(o)))for(n in o)Object.prototype.hasOwnProperty.call(o,n)&&(r=walk(o,n),void 0!==r?o[n]=r:delete o[n]);return reviver.call(e,t,o)}var j;if(text=String(text),rx_dangerous.lastIndex=0,rx_dangerous.test(text)&&(text=text.replace(rx_dangerous,function(e){return"\\u"+("0000"+e.charCodeAt(0).toString(16)).slice(-4)})),rx_one.test(text.replace(rx_two,"@").replace(rx_three,"]").replace(rx_four,"")))return j=eval("("+text+")"),"function"==typeof reviver?walk({"":j},""):j;throw new SyntaxError("JSON.parse")})}()},{}],4:[function(e,t,n){"use strict";function r(){var e="undefined"==typeof console?null:console;if(e){var t=e.warn?e.warn:e.log;t.apply(e,arguments)}}function o(e,t,n){n||(n=""),e&&!l(e)&&(e=[e]),t&&!l(t)&&(t=[t]);var o=n?"__storejs_"+n+"_":"",i=n?new RegExp("^"+o):null,v=/^[a-zA-Z0-9_\-]*$/;if(!v.test(n))throw new Error("store.js namespaces can only have alphanumerics + underscores and dashes");var h={_namespacePrefix:o,_namespaceRegexp:i,_testStorage:function(e){try{var t="__storejs__test__";e.write(t,t);var n=e.read(t)===t;return e.remove(t),n}catch(r){return!1}},_assignPluginFnProp:function(e,t){var n=this[t];this[t]=function(){function t(){if(n)return c(arguments,function(e,t){r[t]=e}),n.apply(o,r)}var r=u(arguments,0),o=this,i=[t].concat(r);return e.apply(o,i)}},_serialize:function(e){return JSON.stringify(e)},_deserialize:function(e,t){if(!e)return t;var n="";try{n=JSON.parse(e)}catch(r){n=e}return void 0!==n?n:t},_addStorage:function(e){this.enabled||this._testStorage(e)&&(this.storage=e,this.enabled=!0)},_addPlugin:function(e){var t=this;if(l(e))return void c(e,function(e){t._addPlugin(e)});var n=a(this.plugins,function(t){return e===t});if(!n){if(this.plugins.push(e),!p(e))throw new Error("Plugins must be function values that return objects");var r=e.call(this);if(!d(r))throw new Error("Plugins must return an object of function properties");c(r,function(n,r){if(!p(n))throw new Error("Bad plugin property: "+r+" from plugin "+e.name+". Plugins should only return functions.");t._assignPluginFnProp(n,r)})}},addStorage:function(e){r("store.addStorage(storage) is deprecated. Use createStore([storages])"),this._addStorage(e)}},m=s(h,g,{plugins:[]});return m.raw={},c(m,function(e,t){p(e)&&(m.raw[t]=f(m,e))}),c(e,function(e){m._addStorage(e)}),c(t,function(e){m._addPlugin(e)}),m}var i=e("./util"),u=i.slice,a=i.pluck,c=i.each,f=i.bind,s=i.create,l=i.isList,p=i.isFunction,d=i.isObject;t.exports={createStore:o};var g={version:"2.0.12",enabled:!1,get:function(e,t){var n=this.storage.read(this._namespacePrefix+e);return this._deserialize(n,t)},set:function(e,t){return void 0===t?this.remove(e):(this.storage.write(this._namespacePrefix+e,this._serialize(t)),t)},remove:function(e){this.storage.remove(this._namespacePrefix+e)},each:function(e){var t=this;this.storage.each(function(n,r){e.call(t,t._deserialize(n),(r||"").replace(t._namespaceRegexp,""))})},clearAll:function(){this.storage.clearAll()},hasNamespace:function(e){return this._namespacePrefix=="__storejs_"+e+"_"},createStore:function(){return o.apply(this,arguments)},addPlugin:function(e){this._addPlugin(e)},namespace:function(e){return o(this.storage,this.plugins,e)}}},{"./util":5}],5:[function(e,t,n){(function(e){"use strict";function n(){return Object.assign?Object.assign:function(e,t,n,r){for(var o=1;o<arguments.length;o++)a(Object(arguments[o]),function(t,n){e[n]=t});return e}}function r(){if(Object.create)return function(e,t,n,r){var o=u(arguments,1);return d.apply(this,[Object.create(e)].concat(o))};var e=function(){};return function(t,n,r,o){var i=u(arguments,1);return e.prototype=t,d.apply(this,[new e].concat(i))}}function o(){return String.prototype.trim?function(e){return String.prototype.trim.call(e)}:function(e){return e.replace(/^[\s\uFEFF\xA0]+|[\s\uFEFF\xA0]+$/g,"")}}function i(e,t){return function(){return t.apply(e,Array.prototype.slice.call(arguments,0))}}function u(e,t){return Array.prototype.slice.call(e,t||0)}function a(e,t){f(e,function(e,n){return t(e,n),!1})}function c(e,t){var n=s(e)?[]:{};return f(e,function(e,r){return n[r]=t(e,r),!1}),n}function f(e,t){if(s(e)){for(var n=0;n<e.length;n++)if(t(e[n],n))return e[n]}else for(var r in e)if(e.hasOwnProperty(r)&&t(e[r],r))return e[r]}function s(e){return null!=e&&"function"!=typeof e&&"number"==typeof e.length}function l(e){return e&&"[object Function]"==={}.toString.call(e)}function p(e){return e&&"[object Object]"==={}.toString.call(e)}var d=n(),g=r(),v=o(),h="undefined"!=typeof window?window:e;t.exports={assign:d,create:g,trim:v,bind:i,slice:u,each:a,map:c,pluck:f,isList:s,isFunction:l,isObject:p,Global:h}}).call(this,"undefined"!=typeof global?global:"undefined"!=typeof self?self:"undefined"!=typeof window?window:{})},{}],6:[function(e,t,n){"use strict";t.exports=[e("./localStorage"),e("./oldFF-globalStorage"),e("./oldIE-userDataStorage"),e("./cookieStorage"),e("./sessionStorage"),e("./memoryStorage")]},{"./cookieStorage":7,"./localStorage":8,"./memoryStorage":9,"./oldFF-globalStorage":10,"./oldIE-userDataStorage":11,"./sessionStorage":12}],7:[function(e,t,n){"use strict";function r(e){if(!e||!c(e))return null;var t="(?:^|.*;\\s*)"+escape(e).replace(/[\-\.\+\*]/g,"\\$&")+"\\s*\\=\\s*((?:[^;](?!;))*[^;]?).*";return unescape(p.cookie.replace(new RegExp(t),"$1"))}function o(e){for(var t=p.cookie.split(/; ?/g),n=t.length-1;n>=0;n--)if(l(t[n])){var r=t[n].split("="),o=unescape(r[0]),i=unescape(r[1]);e(i,o)}}function i(e,t){e&&(p.cookie=escape(e)+"="+escape(t)+"; expires=Tue, 19 Jan 2038 03:14:07 GMT; path=/")}function u(e){e&&c(e)&&(p.cookie=escape(e)+"=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/")}function a(){o(function(e,t){u(t)})}function c(e){return new RegExp("(?:^|;\\s*)"+escape(e).replace(/[\-\.\+\*]/g,"\\$&")+"\\s*\\=").test(p.cookie)}var f=e("../src/util"),s=f.Global,l=f.trim;t.exports={name:"cookieStorage",read:r,write:i,each:o,remove:u,clearAll:a};var p=s.document},{"../src/util":5}],8:[function(e,t,n){"use strict";function r(){return s.localStorage}function o(e){return r().getItem(e)}function i(e,t){return r().setItem(e,t)}function u(e){for(var t=r().length-1;t>=0;t--){var n=r().key(t);e(o(n),n)}}function a(e){return r().removeItem(e)}function c(){return r().clear()}var f=e("../src/util"),s=f.Global;t.exports={name:"localStorage",read:o,write:i,each:u,remove:a,clearAll:c}},{"../src/util":5}],9:[function(e,t,n){"use strict";function r(e){return c[e]}function o(e,t){c[e]=t}function i(e){for(var t in c)c.hasOwnProperty(t)&&e(c[t],t)}function u(e){delete c[e]}function a(e){c={}}t.exports={name:"memoryStorage",read:r,write:o,each:i,remove:u,clearAll:a};var c={}},{}],10:[function(e,t,n){"use strict";function r(e){return s[e]}function o(e,t){s[e]=t}function i(e){for(var t=s.length-1;t>=0;t--){var n=s.key(t);e(s[n],n)}}function u(e){return s.removeItem(e)}function a(){i(function(e,t){delete s[e]})}var c=e("../src/util"),f=c.Global;t.exports={name:"oldFF-globalStorage",read:r,write:o,each:i,remove:u,clearAll:a};var s=f.globalStorage},{"../src/util":5}],11:[function(e,t,n){"use strict";function r(e,t){if(!v){var n=c(e);g(function(e){e.setAttribute(n,t),e.save(p)})}}function o(e){if(!v){var t=c(e),n=null;return g(function(e){n=e.getAttribute(t)}),n}}function i(e){g(function(t){for(var n=t.XMLDocument.documentElement.attributes,r=n.length-1;r>=0;r--){var o=n[r];e(t.getAttribute(o.name),o.name)}})}function u(e){var t=c(e);g(function(e){e.removeAttribute(t),e.save(p)})}function a(){g(function(e){var t=e.XMLDocument.documentElement.attributes;e.load(p);for(var n=t.length-1;n>=0;n--)e.removeAttribute(t[n].name);e.save(p)})}function c(e){return e.replace(/^\d/,"___$&").replace(h,"___")}function f(){if(!d||!d.documentElement||!d.documentElement.addBehavior)return null;var e,t,n,r="script";try{t=new ActiveXObject("htmlfile"),t.open(),t.write("<"+r+">document.w=window</"+r+'><iframe src="/favicon.ico"></iframe>'),t.close(),e=t.w.frames[0].document,n=e.createElement("div")}catch(o){n=d.createElement("div"),e=d.body}return function(t){var r=[].slice.call(arguments,0);r.unshift(n),e.appendChild(n),n.addBehavior("#default#userData"),n.load(p),t.apply(this,r),e.removeChild(n)}}var s=e("../src/util"),l=s.Global;t.exports={name:"oldIE-userDataStorage",write:r,read:o,each:i,remove:u,clearAll:a};var p="storejs",d=l.document,g=f(),v=(l.navigator?l.navigator.userAgent:"").match(/ (MSIE 8|MSIE 9|MSIE 10)\./),h=new RegExp("[!\"#$%&'()*+,/\\\\:;<=>?@[\\]^`{|}~]","g")},{"../src/util":5}],12:[function(e,t,n){"use strict";function r(){return s.sessionStorage}function o(e){return r().getItem(e)}function i(e,t){return r().setItem(e,t)}function u(e){for(var t=r().length-1;t>=0;t--){var n=r().key(t);e(o(n),n)}}function a(e){return r().removeItem(e)}function c(){return r().clear()}var f=e("../src/util"),s=f.Global;t.exports={name:"sessionStorage",read:o,write:i,each:u,remove:a,clearAll:c}},{"../src/util":5}]},{},[1])(1)});
var KJUR,utf8tob64u,b64utoutf8;function Base64x(){}function stoBA(t){for(var e=new Array,r=0;r<t.length;r++)e[r]=t.charCodeAt(r);return e}function BAtos(t){for(var e="",r=0;r<t.length;r++)e+=String.fromCharCode(t[r]);return e}function BAtohex(t){for(var e="",r=0;r<t.length;r++){var n=t[r].toString(16);1==n.length&&(n="0"+n),e+=n}return e}function stohex(t){return BAtohex(stoBA(t))}function stob64(t){return hex2b64(stohex(t))}function stob64u(t){return b64tob64u(hex2b64(stohex(t)))}function b64utos(t){return BAtos(b64toBA(b64utob64(t)))}function b64tob64u(t){return t=(t=(t=t.replace(/\=/g,"")).replace(/\+/g,"-")).replace(/\//g,"_")}function b64utob64(t){return t.length%4==2?t+="==":t.length%4==3&&(t+="="),t=(t=t.replace(/-/g,"+")).replace(/_/g,"/")}function hextob64u(t){return t.length%2==1&&(t="0"+t),b64tob64u(hex2b64(t))}function b64utohex(t){return b64tohex(b64utob64(t))}function utf8tob64(t){return hex2b64(uricmptohex(encodeURIComponentAll(t)))}function b64toutf8(t){return decodeURIComponent(hextouricmp(b64tohex(t)))}function utf8tohex(t){return uricmptohex(encodeURIComponentAll(t))}function hextoutf8(t){return decodeURIComponent(hextouricmp(t))}function hextorstr(t){for(var e="",r=0;r<t.length-1;r+=2)e+=String.fromCharCode(parseInt(t.substr(r,2),16));return e}function rstrtohex(t){for(var e="",r=0;r<t.length;r++)e+=("0"+t.charCodeAt(r).toString(16)).slice(-2);return e}function hextob64(t){return hex2b64(t)}function hextob64nl(t){var e=hextob64(t).replace(/(.{64})/g,"$1\r\n");return e=e.replace(/\r\n$/,"")}function b64nltohex(t){var e=t.replace(/[^0-9A-Za-z\/+=]*/g,"");return b64tohex(e)}function uricmptohex(t){return t.replace(/%/g,"")}function hextouricmp(t){return t.replace(/(..)/g,"%$1")}function encodeURIComponentAll(t){for(var e=encodeURIComponent(t),r="",n=0;n<e.length;n++)"%"==e[n]?(r+=e.substr(n,3),n+=2):r=r+"%"+stohex(e[n]);return r}function newline_toUnix(t){return t=t.replace(/\r\n/gm,"\n")}function newline_toDos(t){return t=(t=t.replace(/\r\n/gm,"\n")).replace(/\n/gm,"\r\n")}function intarystrtohex(t){t=(t=(t=t.replace(/^\s*\[\s*/,"")).replace(/\s*\]\s*$/,"")).replace(/\s*/g,"");try{return t.split(/,/).map(function(t,e,r){var n=parseInt(t);if(n<0||255<n)throw"integer not in range 0-255";return("00"+n.toString(16)).slice(-2)}).join("")}catch(t){throw"malformed integer array string: "+t}}!function(t,e){"use strict";"object"==typeof module&&module.exports?module.exports=e(require("./punycode"),require("./IPv6"),require("./SecondLevelDomains")):"function"==typeof define&&define.amd?define(["./punycode","./IPv6","./SecondLevelDomains"],e):t.URI=e(t.punycode,t.IPv6,t.SecondLevelDomains,t)}(this,function(a,e,u,r){"use strict";var n=r&&r.URI;function S(t,e){var r=1<=arguments.length,n=2<=arguments.length;if(!(this instanceof S))return r?n?new S(t,e):new S(t):new S;if(void 0===t){if(r)throw new TypeError("undefined is not a valid argument for URI");t="undefined"!=typeof location?location.href+"":""}if(null===t&&r)throw new TypeError("null is not a valid argument for URI");return this.href(t),void 0!==e?this.absoluteTo(e):this}S.version="1.19.11";var t=S.prototype,p=Object.prototype.hasOwnProperty;function h(t){return t.replace(/([.*+?^=!:${}()|[\]\/\\])/g,"\\$1")}function o(t){return void 0===t?"Undefined":String(Object.prototype.toString.call(t)).slice(8,-1)}function c(t){return"Array"===o(t)}function l(t,e){var r,n,i={};if("RegExp"===o(e))i=null;else if(c(e))for(r=0,n=e.length;r<n;r++)i[e[r]]=!0;else i[e]=!0;for(r=0,n=t.length;r<n;r++){(i&&void 0!==i[t[r]]||!i&&e.test(t[r]))&&(t.splice(r,1),n--,r--)}return t}function f(t,e){var r,n;if(c(e)){for(r=0,n=e.length;r<n;r++)if(!f(t,e[r]))return!1;return!0}var i=o(e);for(r=0,n=t.length;r<n;r++)if("RegExp"===i){if("string"==typeof t[r]&&t[r].match(e))return!0}else if(t[r]===e)return!0;return!1}function g(t,e){if(!c(t)||!c(e))return!1;if(t.length!==e.length)return!1;t.sort(),e.sort();for(var r=0,n=t.length;r<n;r++)if(t[r]!==e[r])return!1;return!0}function d(t){return t.replace(/^\/+|\/+$/g,"")}function i(t){return escape(t)}function s(t){return encodeURIComponent(t).replace(/[!'()*]/g,i).replace(/\*/g,"%2A")}S._parts=function(){return{protocol:null,username:null,password:null,hostname:null,urn:null,port:null,path:null,query:null,fragment:null,preventInvalidHostname:S.preventInvalidHostname,duplicateQueryParameters:S.duplicateQueryParameters,escapeQuerySpace:S.escapeQuerySpace}},S.preventInvalidHostname=!1,S.duplicateQueryParameters=!1,S.escapeQuerySpace=!0,S.protocol_expression=/^[a-z][a-z0-9.+-]*$/i,S.idn_expression=/[^a-z0-9\._-]/i,S.punycode_expression=/(xn--)/i,S.ip4_expression=/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/,S.ip6_expression=/^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$/,S.find_uri_expression=/\b((?:[a-z][\w-]+:(?:\/{1,3}|[a-z0-9%])|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}\/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'".,<>?«»“”‘’]))/gi,S.findUri={start:/\b(?:([a-z][a-z0-9.+-]*:\/\/)|www\.)/gi,end:/[\s\r\n]|$/,trim:/[`!()\[\]{};:'".,<>?«»“”„‘’]+$/,parens:/(\([^\)]*\)|\[[^\]]*\]|\{[^}]*\}|<[^>]*>)/g},S.leading_whitespace_expression=/^[\x00-\x20\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]+/,S.ascii_tab_whitespace=/[\u0009\u000A\u000D]+/g,S.defaultPorts={http:"80",https:"443",ftp:"21",gopher:"70",ws:"80",wss:"443"},S.hostProtocols=["http","https"],S.invalid_hostname_characters=/[^a-zA-Z0-9\.\-:_]/,S.domAttributes={a:"href",blockquote:"cite",link:"href",base:"href",script:"src",form:"action",img:"src",area:"href",iframe:"src",embed:"src",source:"src",track:"src",input:"src",audio:"src",video:"src"},S.getDomAttribute=function(t){if(t&&t.nodeName){var e=t.nodeName.toLowerCase();if("input"!==e||"image"===t.type)return S.domAttributes[e]}},S.encode=s,S.decode=decodeURIComponent,S.iso8859=function(){S.encode=escape,S.decode=unescape},S.unicode=function(){S.encode=s,S.decode=decodeURIComponent},S.characters={pathname:{encode:{expression:/%(24|26|2B|2C|3B|3D|3A|40)/gi,map:{"%24":"$","%26":"&","%2B":"+","%2C":",","%3B":";","%3D":"=","%3A":":","%40":"@"}},decode:{expression:/[\/\?#]/g,map:{"/":"%2F","?":"%3F","#":"%23"}}},reserved:{encode:{expression:/%(21|23|24|26|27|28|29|2A|2B|2C|2F|3A|3B|3D|3F|40|5B|5D)/gi,map:{"%3A":":","%2F":"/","%3F":"?","%23":"#","%5B":"[","%5D":"]","%40":"@","%21":"!","%24":"$","%26":"&","%27":"'","%28":"(","%29":")","%2A":"*","%2B":"+","%2C":",","%3B":";","%3D":"="}}},urnpath:{encode:{expression:/%(21|24|27|28|29|2A|2B|2C|3B|3D|40)/gi,map:{"%21":"!","%24":"$","%27":"'","%28":"(","%29":")","%2A":"*","%2B":"+","%2C":",","%3B":";","%3D":"=","%40":"@"}},decode:{expression:/[\/\?#:]/g,map:{"/":"%2F","?":"%3F","#":"%23",":":"%3A"}}}},S.encodeQuery=function(t,e){var r=S.encode(t+"");return void 0===e&&(e=S.escapeQuerySpace),e?r.replace(/%20/g,"+"):r},S.decodeQuery=function(e,t){e+="",void 0===t&&(t=S.escapeQuerySpace);try{return S.decode(t?e.replace(/\+/g,"%20"):e)}catch(t){return e}};var y,v={encode:"encode",decode:"decode"},m=function(r,n){return function(e){try{return S[n](e+"").replace(S.characters[r][n].expression,function(t){return S.characters[r][n].map[t]})}catch(t){return e}}};for(y in v)S[y+"PathSegment"]=m("pathname",v[y]),S[y+"UrnPathSegment"]=m("urnpath",v[y]);var A=function(s,o,a){return function(t){var e;e=a?function(t){return S[o](S[a](t))}:S[o];for(var r=(t+"").split(s),n=0,i=r.length;n<i;n++)r[n]=e(r[n]);return r.join(s)}};function b(r){return function(t,e){return void 0===t?this._parts[r]||"":(this._parts[r]=t||null,this.build(!e),this)}}function E(r,n){return function(t,e){return void 0===t?this._parts[r]||"":(null!==t&&(t+="").charAt(0)===n&&(t=t.substring(1)),this._parts[r]=t,this.build(!e),this)}}S.decodePath=A("/","decodePathSegment"),S.decodeUrnPath=A(":","decodeUrnPathSegment"),S.recodePath=A("/","encodePathSegment","decode"),S.recodeUrnPath=A(":","encodeUrnPathSegment","decode"),S.encodeReserved=m("reserved","encode"),S.parse=function(t,e){var r;return e||(e={preventInvalidHostname:S.preventInvalidHostname}),-1<(r=(t=(t=t.replace(S.leading_whitespace_expression,"")).replace(S.ascii_tab_whitespace,"")).indexOf("#"))&&(e.fragment=t.substring(r+1)||null,t=t.substring(0,r)),-1<(r=t.indexOf("?"))&&(e.query=t.substring(r+1)||null,t=t.substring(0,r)),"//"===(t=(t=t.replace(/^(https?|ftp|wss?)?:+[/\\]*/i,"$1://")).replace(/^[/\\]{2,}/i,"//")).substring(0,2)?(e.protocol=null,t=t.substring(2),t=S.parseAuthority(t,e)):-1<(r=t.indexOf(":"))&&(e.protocol=t.substring(0,r)||null,e.protocol&&!e.protocol.match(S.protocol_expression)?e.protocol=void 0:"//"===t.substring(r+1,r+3).replace(/\\/g,"/")?(t=t.substring(r+3),t=S.parseAuthority(t,e)):(t=t.substring(r+1),e.urn=!0)),e.path=t,e},S.parseHost=function(t,e){t||(t="");var r,n,i=(t=t.replace(/\\/g,"/")).indexOf("/");if(-1===i&&(i=t.length),"["===t.charAt(0))r=t.indexOf("]"),e.hostname=t.substring(1,r)||null,e.port=t.substring(r+2,i)||null,"/"===e.port&&(e.port=null);else{var s=t.indexOf(":"),o=t.indexOf("/"),a=t.indexOf(":",s+1);-1!==a&&(-1===o||a<o)?(e.hostname=t.substring(0,i)||null,e.port=null):(n=t.substring(0,i).split(":"),e.hostname=n[0]||null,e.port=n[1]||null)}return e.hostname&&"/"!==t.substring(i).charAt(0)&&(i++,t="/"+t),e.preventInvalidHostname&&S.ensureValidHostname(e.hostname,e.protocol),e.port&&S.ensureValidPort(e.port),t.substring(i)||"/"},S.parseAuthority=function(t,e){return t=S.parseUserinfo(t,e),S.parseHost(t,e)},S.parseUserinfo=function(t,e){var r=t;-1!==t.indexOf("\\")&&(t=t.replace(/\\/g,"/"));var n,i=t.indexOf("/"),s=t.lastIndexOf("@",-1<i?i:t.length-1);return-1<s&&(-1===i||s<i)?(n=t.substring(0,s).split(":"),e.username=n[0]?S.decode(n[0]):null,n.shift(),e.password=n[0]?S.decode(n.join(":")):null,t=r.substring(s+1)):(e.username=null,e.password=null),t},S.parseQuery=function(t,e){if(!t)return{};if(!(t=t.replace(/&+/g,"&").replace(/^\?*&*|&+$/g,"")))return{};for(var r,n,i,s={},o=t.split("&"),a=o.length,h=0;h<a;h++)r=o[h].split("="),n=S.decodeQuery(r.shift(),e),i=r.length?S.decodeQuery(r.join("="),e):null,"__proto__"!==n&&(p.call(s,n)?("string"!=typeof s[n]&&null!==s[n]||(s[n]=[s[n]]),s[n].push(i)):s[n]=i);return s},S.build=function(t){var e="",r=!1;return t.protocol&&(e+=t.protocol+":"),t.urn||!e&&!t.hostname||(e+="//",r=!0),e+=S.buildAuthority(t)||"","string"==typeof t.path&&("/"!==t.path.charAt(0)&&r&&(e+="/"),e+=t.path),"string"==typeof t.query&&t.query&&(e+="?"+t.query),"string"==typeof t.fragment&&t.fragment&&(e+="#"+t.fragment),e},S.buildHost=function(t){var e="";return t.hostname?(S.ip6_expression.test(t.hostname)?e+="["+t.hostname+"]":e+=t.hostname,t.port&&(e+=":"+t.port),e):""},S.buildAuthority=function(t){return S.buildUserinfo(t)+S.buildHost(t)},S.buildUserinfo=function(t){var e="";return t.username&&(e+=S.encode(t.username)),t.password&&(e+=":"+S.encode(t.password)),e&&(e+="@"),e},S.buildQuery=function(t,e,r){var n,i,s,o,a="";for(i in t)if("__proto__"!==i&&p.call(t,i))if(c(t[i]))for(n={},s=0,o=t[i].length;s<o;s++)void 0!==t[i][s]&&void 0===n[t[i][s]+""]&&(a+="&"+S.buildQueryParameter(i,t[i][s],r),!0!==e&&(n[t[i][s]+""]=!0));else void 0!==t[i]&&(a+="&"+S.buildQueryParameter(i,t[i],r));return a.substring(1)},S.buildQueryParameter=function(t,e,r){return S.encodeQuery(t,r)+(null!==e?"="+S.encodeQuery(e,r):"")},S.addQuery=function(t,e,r){if("object"==typeof e)for(var n in e)p.call(e,n)&&S.addQuery(t,n,e[n]);else{if("string"!=typeof e)throw new TypeError("URI.addQuery() accepts an object, string as the name parameter");if(void 0===t[e])return void(t[e]=r);"string"==typeof t[e]&&(t[e]=[t[e]]),c(r)||(r=[r]),t[e]=(t[e]||[]).concat(r)}},S.setQuery=function(t,e,r){if("object"==typeof e)for(var n in e)p.call(e,n)&&S.setQuery(t,n,e[n]);else{if("string"!=typeof e)throw new TypeError("URI.setQuery() accepts an object, string as the name parameter");t[e]=void 0===r?null:r}},S.removeQuery=function(t,e,r){var n,i,s;if(c(e))for(n=0,i=e.length;n<i;n++)t[e[n]]=void 0;else if("RegExp"===o(e))for(s in t)e.test(s)&&(t[s]=void 0);else if("object"==typeof e)for(s in e)p.call(e,s)&&S.removeQuery(t,s,e[s]);else{if("string"!=typeof e)throw new TypeError("URI.removeQuery() accepts an object, string, RegExp as the first parameter");void 0!==r?"RegExp"===o(r)?!c(t[e])&&r.test(t[e])?t[e]=void 0:t[e]=l(t[e],r):t[e]!==String(r)||c(r)&&1!==r.length?c(t[e])&&(t[e]=l(t[e],r)):t[e]=void 0:t[e]=void 0}},S.hasQuery=function(t,e,r,n){switch(o(e)){case"String":break;case"RegExp":for(var i in t)if(p.call(t,i)&&e.test(i)&&(void 0===r||S.hasQuery(t,i,r)))return!0;return!1;case"Object":for(var s in e)if(p.call(e,s)&&!S.hasQuery(t,s,e[s]))return!1;return!0;default:throw new TypeError("URI.hasQuery() accepts a string, regular expression or object as the name parameter")}switch(o(r)){case"Undefined":return e in t;case"Boolean":return r===Boolean(c(t[e])?t[e].length:t[e]);case"Function":return!!r(t[e],e,t);case"Array":return!!c(t[e])&&(n?f:g)(t[e],r);case"RegExp":return c(t[e])?!!n&&f(t[e],r):Boolean(t[e]&&t[e].match(r));case"Number":r=String(r);case"String":return c(t[e])?!!n&&f(t[e],r):t[e]===r;default:throw new TypeError("URI.hasQuery() accepts undefined, boolean, string, number, RegExp, Function as the value parameter")}},S.joinPaths=function(){for(var t=[],e=[],r=0,n=0;n<arguments.length;n++){var i=new S(arguments[n]);t.push(i);for(var s=i.segment(),o=0;o<s.length;o++)"string"==typeof s[o]&&e.push(s[o]),s[o]&&r++}if(!e.length||!r)return new S("");var a=new S("").segment(e);return""!==t[0].path()&&"/"!==t[0].path().slice(0,1)||a.path("/"+a.path()),a.normalize()},S.commonPath=function(t,e){var r,n=Math.min(t.length,e.length);for(r=0;r<n;r++)if(t.charAt(r)!==e.charAt(r)){r--;break}return r<1?t.charAt(0)===e.charAt(0)&&"/"===t.charAt(0)?"/":"":("/"===t.charAt(r)&&"/"===e.charAt(r)||(r=t.substring(0,r).lastIndexOf("/")),t.substring(0,r+1))},S.withinString=function(t,e,r){r||(r={});var n=r.start||S.findUri.start,i=r.end||S.findUri.end,s=r.trim||S.findUri.trim,o=r.parens||S.findUri.parens,a=/[a-z0-9-]=["']?$/i;for(n.lastIndex=0;;){var h=n.exec(t);if(!h)break;var u=h.index;if(r.ignoreHtml){var p=t.slice(Math.max(u-3,0),u);if(p&&a.test(p))continue}for(var c=u+t.slice(u).search(i),l=t.slice(u,c),f=-1;;){var g=o.exec(l);if(!g)break;var d=g.index+g[0].length;f=Math.max(f,d)}if(!((l=-1<f?l.slice(0,f)+l.slice(f).replace(s,""):l.replace(s,"")).length<=h[0].length||r.ignore&&r.ignore.test(l))){var y=e(l,u,c=u+l.length,t);void 0!==y?(y=String(y),t=t.slice(0,u)+y+t.slice(c),n.lastIndex=u+y.length):n.lastIndex=c}}return n.lastIndex=0,t},S.ensureValidHostname=function(t,e){var r=!!t,n=!1;if(!!e&&(n=f(S.hostProtocols,e)),n&&!r)throw new TypeError("Hostname cannot be empty, if protocol is "+e);if(t&&t.match(S.invalid_hostname_characters)){if(!a)throw new TypeError('Hostname "'+t+'" contains characters other than [A-Z0-9.-:_] and Punycode.js is not available');if(a.toASCII(t).match(S.invalid_hostname_characters))throw new TypeError('Hostname "'+t+'" contains characters other than [A-Z0-9.-:_]')}},S.ensureValidPort=function(t){if(t){var e=Number(t);if(!(/^[0-9]+$/.test(e)&&0<e&&e<65536))throw new TypeError('Port "'+t+'" is not a valid port')}},S.noConflict=function(t){if(t){var e={URI:this.noConflict()};return r.URITemplate&&"function"==typeof r.URITemplate.noConflict&&(e.URITemplate=r.URITemplate.noConflict()),r.IPv6&&"function"==typeof r.IPv6.noConflict&&(e.IPv6=r.IPv6.noConflict()),r.SecondLevelDomains&&"function"==typeof r.SecondLevelDomains.noConflict&&(e.SecondLevelDomains=r.SecondLevelDomains.noConflict()),e}return r.URI===this&&(r.URI=n),this},t.build=function(t){return!0===t?this._deferred_build=!0:(void 0===t||this._deferred_build)&&(this._string=S.build(this._parts),this._deferred_build=!1),this},t.clone=function(){return new S(this)},t.valueOf=t.toString=function(){return this.build(!1)._string},t.protocol=b("protocol"),t.username=b("username"),t.password=b("password"),t.hostname=b("hostname"),t.port=b("port"),t.query=E("query","?"),t.fragment=E("fragment","#"),t.search=function(t,e){var r=this.query(t,e);return"string"==typeof r&&r.length?"?"+r:r},t.hash=function(t,e){var r=this.fragment(t,e);return"string"==typeof r&&r.length?"#"+r:r},t.pathname=function(t,e){if(void 0!==t&&!0!==t)return this._parts.urn?this._parts.path=t?S.recodeUrnPath(t):"":this._parts.path=t?S.recodePath(t):"/",this.build(!e),this;var r=this._parts.path||(this._parts.hostname?"/":"");return t?(this._parts.urn?S.decodeUrnPath:S.decodePath)(r):r},t.path=t.pathname,t.href=function(t,e){var r;if(void 0===t)return this.toString();this._string="",this._parts=S._parts();var n=t instanceof S,i="object"==typeof t&&(t.hostname||t.path||t.pathname);t.nodeName&&(t=t[S.getDomAttribute(t)]||"",i=!1);if(!n&&i&&void 0!==t.pathname&&(t=t.toString()),"string"==typeof t||t instanceof String)this._parts=S.parse(String(t),this._parts);else{if(!n&&!i)throw new TypeError("invalid input");var s=n?t._parts:t;for(r in s)"query"!==r&&p.call(this._parts,r)&&(this._parts[r]=s[r]);s.query&&this.query(s.query,!1)}return this.build(!e),this},t.is=function(t){var e=!1,r=!1,n=!1,i=!1,s=!1,o=!1,a=!1,h=!this._parts.urn;switch(this._parts.hostname&&(h=!1,r=S.ip4_expression.test(this._parts.hostname),n=S.ip6_expression.test(this._parts.hostname),s=(i=!(e=r||n))&&u&&u.has(this._parts.hostname),o=i&&S.idn_expression.test(this._parts.hostname),a=i&&S.punycode_expression.test(this._parts.hostname)),t.toLowerCase()){case"relative":return h;case"absolute":return!h;case"domain":case"name":return i;case"sld":return s;case"ip":return e;case"ip4":case"ipv4":case"inet4":return r;case"ip6":case"ipv6":case"inet6":return n;case"idn":return o;case"url":return!this._parts.urn;case"urn":return!!this._parts.urn;case"punycode":return a}return null};var x=t.protocol,P=t.port,R=t.hostname;t.protocol=function(t,e){if(t&&!(t=t.replace(/:(\/\/)?$/,"")).match(S.protocol_expression))throw new TypeError('Protocol "'+t+"\" contains characters other than [A-Z0-9.+-] or doesn't start with [A-Z]");return x.call(this,t,e)},t.scheme=t.protocol,t.port=function(t,e){return this._parts.urn?void 0===t?"":this:(void 0!==t&&(0===t&&(t=null),t&&(":"===(t+="").charAt(0)&&(t=t.substring(1)),S.ensureValidPort(t))),P.call(this,t,e))},t.hostname=function(t,e){if(this._parts.urn)return void 0===t?"":this;if(void 0!==t){var r={preventInvalidHostname:this._parts.preventInvalidHostname};if("/"!==S.parseHost(t,r))throw new TypeError('Hostname "'+t+'" contains characters other than [A-Z0-9.-]');t=r.hostname,this._parts.preventInvalidHostname&&S.ensureValidHostname(t,this._parts.protocol)}return R.call(this,t,e)},t.origin=function(t,e){if(this._parts.urn)return void 0===t?"":this;if(void 0===t){var r=this.protocol();return this.authority()?(r?r+"://":"")+this.authority():""}var n=S(t);return this.protocol(n.protocol()).authority(n.authority()).build(!e),this},t.host=function(t,e){if(this._parts.urn)return void 0===t?"":this;if(void 0===t)return this._parts.hostname?S.buildHost(this._parts):"";if("/"!==S.parseHost(t,this._parts))throw new TypeError('Hostname "'+t+'" contains characters other than [A-Z0-9.-]');return this.build(!e),this},t.authority=function(t,e){if(this._parts.urn)return void 0===t?"":this;if(void 0===t)return this._parts.hostname?S.buildAuthority(this._parts):"";if("/"!==S.parseAuthority(t,this._parts))throw new TypeError('Hostname "'+t+'" contains characters other than [A-Z0-9.-]');return this.build(!e),this},t.userinfo=function(t,e){if(this._parts.urn)return void 0===t?"":this;if(void 0!==t)return"@"!==t[t.length-1]&&(t+="@"),S.parseUserinfo(t,this._parts),this.build(!e),this;var r=S.buildUserinfo(this._parts);return r?r.substring(0,r.length-1):r},t.resource=function(t,e){var r;return void 0===t?this.path()+this.search()+this.hash():(r=S.parse(t),this._parts.path=r.path,this._parts.query=r.query,this._parts.fragment=r.fragment,this.build(!e),this)},t.subdomain=function(t,e){if(this._parts.urn)return void 0===t?"":this;if(void 0===t){if(!this._parts.hostname||this.is("IP"))return"";var r=this._parts.hostname.length-this.domain().length-1;return this._parts.hostname.substring(0,r)||""}var n=this._parts.hostname.length-this.domain().length,i=this._parts.hostname.substring(0,n),s=new RegExp("^"+h(i));if(t&&"."!==t.charAt(t.length-1)&&(t+="."),-1!==t.indexOf(":"))throw new TypeError("Domains cannot contain colons");return t&&S.ensureValidHostname(t,this._parts.protocol),this._parts.hostname=this._parts.hostname.replace(s,t),this.build(!e),this},t.domain=function(t,e){if(this._parts.urn)return void 0===t?"":this;if("boolean"==typeof t&&(e=t,t=void 0),void 0===t){if(!this._parts.hostname||this.is("IP"))return"";var r=this._parts.hostname.match(/\./g);if(r&&r.length<2)return this._parts.hostname;var n=this._parts.hostname.length-this.tld(e).length-1;return n=this._parts.hostname.lastIndexOf(".",n-1)+1,this._parts.hostname.substring(n)||""}if(!t)throw new TypeError("cannot set domain empty");if(-1!==t.indexOf(":"))throw new TypeError("Domains cannot contain colons");if(S.ensureValidHostname(t,this._parts.protocol),!this._parts.hostname||this.is("IP"))this._parts.hostname=t;else{var i=new RegExp(h(this.domain())+"$");this._parts.hostname=this._parts.hostname.replace(i,t)}return this.build(!e),this},t.tld=function(t,e){if(this._parts.urn)return void 0===t?"":this;if("boolean"==typeof t&&(e=t,t=void 0),void 0===t){if(!this._parts.hostname||this.is("IP"))return"";var r=this._parts.hostname.lastIndexOf("."),n=this._parts.hostname.substring(r+1);return!0!==e&&u&&u.list[n.toLowerCase()]&&u.get(this._parts.hostname)||n}var i;if(!t)throw new TypeError("cannot set TLD empty");if(t.match(/[^a-zA-Z0-9-]/)){if(!u||!u.is(t))throw new TypeError('TLD "'+t+'" contains characters other than [A-Z0-9]');i=new RegExp(h(this.tld())+"$"),this._parts.hostname=this._parts.hostname.replace(i,t)}else{if(!this._parts.hostname||this.is("IP"))throw new ReferenceError("cannot set TLD on non-domain host");i=new RegExp(h(this.tld())+"$"),this._parts.hostname=this._parts.hostname.replace(i,t)}return this.build(!e),this},t.directory=function(t,e){if(this._parts.urn)return void 0===t?"":this;if(void 0===t||!0===t){if(!this._parts.path&&!this._parts.hostname)return"";if("/"===this._parts.path)return"/";var r=this._parts.path.length-this.filename().length-1,n=this._parts.path.substring(0,r)||(this._parts.hostname?"/":"");return t?S.decodePath(n):n}var i=this._parts.path.length-this.filename().length,s=this._parts.path.substring(0,i),o=new RegExp("^"+h(s));return this.is("relative")||(t||(t="/"),"/"!==t.charAt(0)&&(t="/"+t)),t&&"/"!==t.charAt(t.length-1)&&(t+="/"),t=S.recodePath(t),this._parts.path=this._parts.path.replace(o,t),this.build(!e),this},t.filename=function(t,e){if(this._parts.urn)return void 0===t?"":this;if("string"!=typeof t){if(!this._parts.path||"/"===this._parts.path)return"";var r=this._parts.path.lastIndexOf("/"),n=this._parts.path.substring(r+1);return t?S.decodePathSegment(n):n}var i=!1;"/"===t.charAt(0)&&(t=t.substring(1)),t.match(/\.?\//)&&(i=!0);var s=new RegExp(h(this.filename())+"$");return t=S.recodePath(t),this._parts.path=this._parts.path.replace(s,t),i?this.normalizePath(e):this.build(!e),this},t.suffix=function(t,e){if(this._parts.urn)return void 0===t?"":this;if(void 0===t||!0===t){if(!this._parts.path||"/"===this._parts.path)return"";var r,n,i=this.filename(),s=i.lastIndexOf(".");return-1===s?"":(r=i.substring(s+1),n=/^[a-z0-9%]+$/i.test(r)?r:"",t?S.decodePathSegment(n):n)}"."===t.charAt(0)&&(t=t.substring(1));var o,a=this.suffix();if(a)o=t?new RegExp(h(a)+"$"):new RegExp(h("."+a)+"$");else{if(!t)return this;this._parts.path+="."+S.recodePath(t)}return o&&(t=S.recodePath(t),this._parts.path=this._parts.path.replace(o,t)),this.build(!e),this},t.segment=function(t,e,r){var n=this._parts.urn?":":"/",i=this.path(),s="/"===i.substring(0,1),o=i.split(n);if(void 0!==t&&"number"!=typeof t&&(r=e,e=t,t=void 0),void 0!==t&&"number"!=typeof t)throw new Error('Bad segment "'+t+'", must be 0-based integer');if(s&&o.shift(),t<0&&(t=Math.max(o.length+t,0)),void 0===e)return void 0===t?o:o[t];if(null===t||void 0===o[t])if(c(e)){o=[];for(var a=0,h=e.length;a<h;a++)(e[a].length||o.length&&o[o.length-1].length)&&(o.length&&!o[o.length-1].length&&o.pop(),o.push(d(e[a])))}else(e||"string"==typeof e)&&(e=d(e),""===o[o.length-1]?o[o.length-1]=e:o.push(e));else e?o[t]=d(e):o.splice(t,1);return s&&o.unshift(""),this.path(o.join(n),r)},t.segmentCoded=function(t,e,r){var n,i,s;if("number"!=typeof t&&(r=e,e=t,t=void 0),void 0===e){if(c(n=this.segment(t,e,r)))for(i=0,s=n.length;i<s;i++)n[i]=S.decode(n[i]);else n=void 0!==n?S.decode(n):void 0;return n}if(c(e))for(i=0,s=e.length;i<s;i++)e[i]=S.encode(e[i]);else e="string"==typeof e||e instanceof String?S.encode(e):e;return this.segment(t,e,r)};var K=t.query;return t.query=function(t,e){if(!0===t)return S.parseQuery(this._parts.query,this._parts.escapeQuerySpace);if("function"!=typeof t)return void 0!==t&&"string"!=typeof t?(this._parts.query=S.buildQuery(t,this._parts.duplicateQueryParameters,this._parts.escapeQuerySpace),this.build(!e),this):K.call(this,t,e);var r=S.parseQuery(this._parts.query,this._parts.escapeQuerySpace),n=t.call(this,r);return this._parts.query=S.buildQuery(n||r,this._parts.duplicateQueryParameters,this._parts.escapeQuerySpace),this.build(!e),this},t.setQuery=function(t,e,r){var n=S.parseQuery(this._parts.query,this._parts.escapeQuerySpace);if("string"==typeof t||t instanceof String)n[t]=void 0!==e?e:null;else{if("object"!=typeof t)throw new TypeError("URI.addQuery() accepts an object, string as the name parameter");for(var i in t)p.call(t,i)&&(n[i]=t[i])}return this._parts.query=S.buildQuery(n,this._parts.duplicateQueryParameters,this._parts.escapeQuerySpace),"string"!=typeof t&&(r=e),this.build(!r),this},t.addQuery=function(t,e,r){var n=S.parseQuery(this._parts.query,this._parts.escapeQuerySpace);return S.addQuery(n,t,void 0===e?null:e),this._parts.query=S.buildQuery(n,this._parts.duplicateQueryParameters,this._parts.escapeQuerySpace),"string"!=typeof t&&(r=e),this.build(!r),this},t.removeQuery=function(t,e,r){var n=S.parseQuery(this._parts.query,this._parts.escapeQuerySpace);return S.removeQuery(n,t,e),this._parts.query=S.buildQuery(n,this._parts.duplicateQueryParameters,this._parts.escapeQuerySpace),"string"!=typeof t&&(r=e),this.build(!r),this},t.hasQuery=function(t,e,r){var n=S.parseQuery(this._parts.query,this._parts.escapeQuerySpace);return S.hasQuery(n,t,e,r)},t.setSearch=t.setQuery,t.addSearch=t.addQuery,t.removeSearch=t.removeQuery,t.hasSearch=t.hasQuery,t.normalize=function(){return this._parts.urn?this.normalizeProtocol(!1).normalizePath(!1).normalizeQuery(!1).normalizeFragment(!1).build():this.normalizeProtocol(!1).normalizeHostname(!1).normalizePort(!1).normalizePath(!1).normalizeQuery(!1).normalizeFragment(!1).build()},t.normalizeProtocol=function(t){return"string"==typeof this._parts.protocol&&(this._parts.protocol=this._parts.protocol.toLowerCase(),this.build(!t)),this},t.normalizeHostname=function(t){return this._parts.hostname&&(this.is("IDN")&&a?this._parts.hostname=a.toASCII(this._parts.hostname):this.is("IPv6")&&e&&(this._parts.hostname=e.best(this._parts.hostname)),this._parts.hostname=this._parts.hostname.toLowerCase(),this.build(!t)),this},t.normalizePort=function(t){return"string"==typeof this._parts.protocol&&this._parts.port===S.defaultPorts[this._parts.protocol]&&(this._parts.port=null,this.build(!t)),this},t.normalizePath=function(t){var e,r=this._parts.path;if(!r)return this;if(this._parts.urn)return this._parts.path=S.recodeUrnPath(this._parts.path),this.build(!t),this;if("/"===this._parts.path)return this;var n,i,s="";for("/"!==(r=S.recodePath(r)).charAt(0)&&(e=!0,r="/"+r),"/.."!==r.slice(-3)&&"/."!==r.slice(-2)||(r+="/"),r=r.replace(/(\/(\.\/)+)|(\/\.$)/g,"/").replace(/\/{2,}/g,"/"),e&&(s=r.substring(1).match(/^(\.\.\/)+/)||"")&&(s=s[0]);-1!==(n=r.search(/\/\.\.(\/|$)/));)r=0!==n?(-1===(i=r.substring(0,n).lastIndexOf("/"))&&(i=n),r.substring(0,i)+r.substring(n+3)):r.substring(3);return e&&this.is("relative")&&(r=s+r.substring(1)),this._parts.path=r,this.build(!t),this},t.normalizePathname=t.normalizePath,t.normalizeQuery=function(t){return"string"==typeof this._parts.query&&(this._parts.query.length?this.query(S.parseQuery(this._parts.query,this._parts.escapeQuerySpace)):this._parts.query=null,this.build(!t)),this},t.normalizeFragment=function(t){return this._parts.fragment||(this._parts.fragment=null,this.build(!t)),this},t.normalizeSearch=t.normalizeQuery,t.normalizeHash=t.normalizeFragment,t.iso8859=function(){var t=S.encode,e=S.decode;S.encode=escape,S.decode=decodeURIComponent;try{this.normalize()}finally{S.encode=t,S.decode=e}return this},t.unicode=function(){var t=S.encode,e=S.decode;S.encode=s,S.decode=unescape;try{this.normalize()}finally{S.encode=t,S.decode=e}return this},t.readable=function(){var t=this.clone();t.username("").password("").normalize();var e="";if(t._parts.protocol&&(e+=t._parts.protocol+"://"),t._parts.hostname&&(t.is("punycode")&&a?(e+=a.toUnicode(t._parts.hostname),t._parts.port&&(e+=":"+t._parts.port)):e+=t.host()),t._parts.hostname&&t._parts.path&&"/"!==t._parts.path.charAt(0)&&(e+="/"),e+=t.path(!0),t._parts.query){for(var r="",n=0,i=t._parts.query.split("&"),s=i.length;n<s;n++){var o=(i[n]||"").split("=");r+="&"+S.decodeQuery(o[0],this._parts.escapeQuerySpace).replace(/&/g,"%26"),void 0!==o[1]&&(r+="="+S.decodeQuery(o[1],this._parts.escapeQuerySpace).replace(/&/g,"%26"))}e+="?"+r.substring(1)}return e+=S.decodeQuery(t.hash(),!0)},t.absoluteTo=function(t){var e,r,n,i=this.clone(),s=["protocol","username","password","hostname","port"];if(this._parts.urn)throw new Error("URNs do not have any generally defined hierarchical components");if(t instanceof S||(t=new S(t)),i._parts.protocol)return i;if(i._parts.protocol=t._parts.protocol,this._parts.hostname)return i;for(r=0;n=s[r];r++)i._parts[n]=t._parts[n];return i._parts.path?(".."===i._parts.path.substring(-2)&&(i._parts.path+="/"),"/"!==i.path().charAt(0)&&(e=(e=t.directory())||(0===t.path().indexOf("/")?"/":""),i._parts.path=(e?e+"/":"")+i._parts.path,i.normalizePath())):(i._parts.path=t._parts.path,i._parts.query||(i._parts.query=t._parts.query)),i.build(),i},t.relativeTo=function(t){var e,r,n,i,s,o=this.clone().normalize();if(o._parts.urn)throw new Error("URNs do not have any generally defined hierarchical components");if(t=new S(t).normalize(),e=o._parts,r=t._parts,i=o.path(),s=t.path(),"/"!==i.charAt(0))throw new Error("URI is already relative");if("/"!==s.charAt(0))throw new Error("Cannot calculate a URI relative to another relative URI");if(e.protocol===r.protocol&&(e.protocol=null),e.username!==r.username||e.password!==r.password)return o.build();if(null!==e.protocol||null!==e.username||null!==e.password)return o.build();if(e.hostname!==r.hostname||e.port!==r.port)return o.build();if(e.hostname=null,e.port=null,i===s)return e.path="",o.build();if(!(n=S.commonPath(i,s)))return o.build();var a=r.path.substring(n.length).replace(/[^\/]*$/,"").replace(/.*?\//g,"../");return e.path=a+e.path.substring(n.length)||"./",o.build()},t.equals=function(t){var e,r,n,i,s,o=this.clone(),a=new S(t),h={};if(o.normalize(),a.normalize(),o.toString()===a.toString())return!0;if(n=o.query(),i=a.query(),o.query(""),a.query(""),o.toString()!==a.toString())return!1;if(n.length!==i.length)return!1;for(s in e=S.parseQuery(n,this._parts.escapeQuerySpace),r=S.parseQuery(i,this._parts.escapeQuerySpace),e)if(p.call(e,s)){if(c(e[s])){if(!g(e[s],r[s]))return!1}else if(e[s]!==r[s])return!1;h[s]=!0}for(s in r)if(p.call(r,s)&&!h[s])return!1;return!0},t.preventInvalidHostname=function(t){return this._parts.preventInvalidHostname=!!t,this},t.duplicateQueryParameters=function(t){return this._parts.duplicateQueryParameters=!!t,this},t.escapeQuerySpace=function(t){return this._parts.escapeQuerySpace=!!t,this},S}),function(t,e){"use strict";"object"==typeof module&&module.exports?module.exports=e():"function"==typeof define&&define.amd?define(e):t.IPv6=e(t)}(this,function(t){"use strict";var e=t&&t.IPv6;return{best:function(t){var e,r,n=t.toLowerCase().split(":"),i=n.length,s=8;for(""===n[0]&&""===n[1]&&""===n[2]?(n.shift(),n.shift()):""===n[0]&&""===n[1]?n.shift():""===n[i-1]&&""===n[i-2]&&n.pop(),-1!==n[(i=n.length)-1].indexOf(".")&&(s=7),e=0;e<i&&""!==n[e];e++);if(e<s)for(n.splice(e,1,"0000");n.length<s;)n.splice(e,0,"0000");for(var o=0;o<s;o++){r=n[o].split("");for(var a=0;a<3&&"0"===r[0]&&1<r.length;a++)r.splice(0,1);n[o]=r.join("")}var h=-1,u=0,p=0,c=-1,l=!1;for(o=0;o<s;o++)l?"0"===n[o]?p+=1:(l=!1,u<p&&(h=c,u=p)):"0"===n[o]&&(l=!0,c=o,p=1);u<p&&(h=c,u=p),1<u&&n.splice(h,u,""),i=n.length;var f="";for(""===n[0]&&(f=":"),o=0;o<i&&(f+=n[o],o!==i-1);o++)f+=":";return""===n[i-1]&&(f+=":"),f},noConflict:function(){return t.IPv6===this&&(t.IPv6=e),this}}}),function(t){var e="object"==typeof exports&&exports&&!exports.nodeType&&exports,r="object"==typeof module&&module&&!module.nodeType&&module,n="object"==typeof global&&global;n.global!==n&&n.window!==n&&n.self!==n||(t=n);var i,s,S=2147483647,v=36,m=1,A=26,o=38,a=700,b=72,E=128,x="-",h=/^xn--/,u=/[^\x20-\x7E]/,p=/[\x2E\u3002\uFF0E\uFF61]/g,c={overflow:"Overflow: input needs wider integers to process","not-basic":"Illegal input >= 0x80 (not a basic code point)","invalid-input":"Invalid input"},l=v-m,P=Math.floor,R=String.fromCharCode;function K(t){throw new RangeError(c[t])}function f(t,e){for(var r=t.length,n=[];r--;)n[r]=e(t[r]);return n}function g(t,e){var r=t.split("@"),n="";return 1<r.length&&(n=r[0]+"@",t=r[1]),n+f((t=t.replace(p,".")).split("."),e).join(".")}function w(t){for(var e,r,n=[],i=0,s=t.length;i<s;)55296<=(e=t.charCodeAt(i++))&&e<=56319&&i<s?56320==(64512&(r=t.charCodeAt(i++)))?n.push(((1023&e)<<10)+(1023&r)+65536):(n.push(e),i--):n.push(e);return n}function H(t){return f(t,function(t){var e="";return 65535<t&&(e+=R((t-=65536)>>>10&1023|55296),t=56320|1023&t),e+=R(t)}).join("")}function _(t,e){return t+22+75*(t<26)-((0!=e)<<5)}function C(t,e,r){var n=0;for(t=r?P(t/a):t>>1,t+=P(t/e);l*A>>1<t;n+=v)t=P(t/l);return P(n+(l+1)*t/(t+o))}function d(t){var e,r,n,i,s,o,a,h,u,p,c,l=[],f=t.length,g=0,d=E,y=b;for((r=t.lastIndexOf(x))<0&&(r=0),n=0;n<r;++n)128<=t.charCodeAt(n)&&K("not-basic"),l.push(t.charCodeAt(n));for(i=0<r?r+1:0;i<f;){for(s=g,o=1,a=v;f<=i&&K("invalid-input"),c=t.charCodeAt(i++),(v<=(h=c-48<10?c-22:c-65<26?c-65:c-97<26?c-97:v)||h>P((S-g)/o))&&K("overflow"),g+=h*o,!(h<(u=a<=y?m:y+A<=a?A:a-y));a+=v)o>P(S/(p=v-u))&&K("overflow"),o*=p;y=C(g-s,e=l.length+1,0==s),P(g/e)>S-d&&K("overflow"),d+=P(g/e),g%=e,l.splice(g++,0,d)}return H(l)}function y(t){var e,r,n,i,s,o,a,h,u,p,c,l,f,g,d,y=[];for(l=(t=w(t)).length,e=E,s=b,o=r=0;o<l;++o)(c=t[o])<128&&y.push(R(c));for(n=i=y.length,i&&y.push(x);n<l;){for(a=S,o=0;o<l;++o)e<=(c=t[o])&&c<a&&(a=c);for(a-e>P((S-r)/(f=n+1))&&K("overflow"),r+=(a-e)*f,e=a,o=0;o<l;++o)if((c=t[o])<e&&++r>S&&K("overflow"),c==e){for(h=r,u=v;!(h<(p=u<=s?m:s+A<=u?A:u-s));u+=v)d=h-p,g=v-p,y.push(R(_(p+d%g,0))),h=P(d/g);y.push(R(_(h,0))),s=C(r,f,n==i),r=0,++n}++r,++e}return y.join("")}if(i={version:"1.3.2",ucs2:{decode:w,encode:H},decode:d,encode:y,toASCII:function(t){return g(t,function(t){return u.test(t)?"xn--"+y(t):t})},toUnicode:function(t){return g(t,function(t){return h.test(t)?d(t.slice(4).toLowerCase()):t})}},"function"==typeof define&&"object"==typeof define.amd&&define.amd)define("punycode",function(){return i});else if(e&&r)if(module.exports==e)r.exports=i;else for(s in i)i.hasOwnProperty(s)&&(e[s]=i[s]);else t.punycode=i}(this),function(n,r){function t(t){var e=r[t];r[t]=function(t){return s(e(t))}}function i(t,e,r){return(r=this).attachEvent("on"+t,function(t){(t=t||n.event).preventDefault=t.preventDefault||function(){t.returnValue=!1},t.stopPropagation=t.stopPropagation||function(){t.cancelBubble=!0},e.call(r,t)})}function s(t,e){if(e=t.length)for(;e--;)t[e].addEventListener=i;else t.addEventListener=i;return t}n.addEventListener||(s([r,n]),"Element"in n?n.Element.prototype.addEventListener=i:(r.attachEvent("onreadystatechange",function(){s(r.all)}),t("getElementsByTagName"),t("getElementById"),t("createElement"),s(r.all)))}(window,document),void 0!==KJUR&&KJUR||(KJUR={}),void 0!==KJUR.jws&&KJUR.jws||(KJUR.jws={}),KJUR.jws.JWS=function(){var p=KJUR.jws.JWS;this.parseJWS=function(t,e){if(void 0===this.parsedJWS||!e&&void 0===this.parsedJWS.sigvalH){if(null==t.match(/^([^.]+)\.([^.]+)\.([^.]+)$/))throw"JWS signature is not a form of 'Head.Payload.SigValue'.";var r=RegExp.$1,n=RegExp.$2,i=RegExp.$3,s=r+"."+n;if(this.parsedJWS={},this.parsedJWS.headB64U=r,this.parsedJWS.payloadB64U=n,this.parsedJWS.sigvalB64U=i,this.parsedJWS.si=s,!e){var o=b64utohex(i),a=parseBigInt(o,16);this.parsedJWS.sigvalH=o,this.parsedJWS.sigvalBI=a}var h=b64utoutf8(r),u=b64utoutf8(n);if(this.parsedJWS.headS=h,this.parsedJWS.payloadS=u,!p.isSafeJSONString(h,this.parsedJWS,"headP"))throw"malformed JSON string for JWS Head: "+h}}},KJUR.jws.JWS.sign=function(t,e,r,n,i){var s,o,a,h=KJUR.jws.JWS;if("string"!=typeof e&&"object"!=typeof e)throw"spHeader must be JSON string or object: "+e;if("object"==typeof e&&(o=e,s=JSON.stringify(o)),"string"==typeof e){if(s=e,!h.isSafeJSONString(s))throw"JWS Head is not safe JSON string: "+s;o=h.readSafeJSONString(s)}if("object"==typeof(a=r)&&(a=JSON.stringify(r)),""!=t&&null!=t||void 0===o.alg||(t=o.alg),""!=t&&null!=t&&void 0===o.alg&&(o.alg=t,s=JSON.stringify(o)),t!==o.alg)throw"alg and sHeader.alg doesn't match: "+t+"!="+o.alg;var u=null;if(void 0===h.jwsalg2sigalg[t])throw"unsupported alg name: "+t;u=h.jwsalg2sigalg[t];var p=utf8tob64u(s)+"."+utf8tob64u(a),c="";if("Hmac"==u.substr(0,4)){if(void 0===n)throw"mac key shall be specified for HS* alg";var l=new KJUR.crypto.Mac({alg:u,prov:"cryptojs",pass:n});l.updateString(p),c=l.doFinal()}else if(-1!=u.indexOf("withECDSA")){(f=new KJUR.crypto.Signature({alg:u})).init(n,i),f.updateString(p),hASN1Sig=f.sign(),c=KJUR.crypto.ECDSA.asn1SigToConcatSig(hASN1Sig)}else if("none"!=u){var f;(f=new KJUR.crypto.Signature({alg:u})).init(n,i),f.updateString(p),c=f.sign()}return p+"."+hextob64u(c)},KJUR.jws.JWS.verify=function(t,e,r){var n=KJUR.jws.JWS,i=t.split("."),s=i[0]+"."+i[1],o=b64utohex(i[2]),a=n.readSafeJSONString(b64utoutf8(i[0])),h=null,u=null;if(void 0===a.alg)throw"algorithm not specified in header";if((u=(h=a.alg).substr(0,2),null!=r&&"[object Array]"===Object.prototype.toString.call(r)&&0<r.length)&&-1==(":"+r.join(":")+":").indexOf(":"+h+":"))throw"algorithm '"+h+"' not accepted in the list";if("none"!=h&&null===e)throw"key shall be specified to verify.";if("string"==typeof e&&-1!=e.indexOf("-----BEGIN ")&&(e=KEYUTIL.getKey(e)),!("RS"!=u&&"PS"!=u||e instanceof RSAKey))throw"key shall be a RSAKey obj for RS* and PS* algs";if("ES"==u&&!(e instanceof KJUR.crypto.ECDSA))throw"key shall be a ECDSA obj for ES* algs";var p=null;if(void 0===n.jwsalg2sigalg[a.alg])throw"unsupported alg name: "+h;if("none"==(p=n.jwsalg2sigalg[h]))throw"not supported";if("Hmac"==p.substr(0,4)){if(void 0===e)throw"hexadecimal key shall be specified for HMAC";var c=new KJUR.crypto.Mac({alg:p,pass:e});return c.updateString(s),o==c.doFinal()}if(-1==p.indexOf("withECDSA"))return(l=new KJUR.crypto.Signature({alg:p})).init(e),l.updateString(s),l.verify(o);var l,f=null;try{f=KJUR.crypto.ECDSA.concatSigToASN1Sig(o)}catch(t){return!1}return(l=new KJUR.crypto.Signature({alg:p})).init(e),l.updateString(s),l.verify(f)},KJUR.jws.JWS.parse=function(t){var e,r,n,i=t.split("."),s={};if(2!=i.length&&3!=i.length)throw"malformed sJWS: wrong number of '.' splitted elements";return e=i[0],r=i[1],3==i.length&&(n=i[2]),s.headerObj=KJUR.jws.JWS.readSafeJSONString(b64utoutf8(e)),s.payloadObj=KJUR.jws.JWS.readSafeJSONString(b64utoutf8(r)),s.headerPP=JSON.stringify(s.headerObj,null,"  "),null==s.payloadObj?s.payloadPP=b64utoutf8(r):s.payloadPP=JSON.stringify(s.payloadObj,null,"  "),void 0!==n&&(s.sigHex=b64utohex(n)),s},KJUR.jws.JWS.verifyJWT=function(t,e,r){var n=KJUR.jws.JWS,i=t.split("."),s=i[0],o=i[1],a=(b64utohex(i[2]),n.readSafeJSONString(b64utoutf8(s))),h=n.readSafeJSONString(b64utoutf8(o));if(void 0===a.alg)return!1;if(void 0===r.alg)throw"acceptField.alg shall be specified";if(!n.inArray(a.alg,r.alg))return!1;if(void 0!==h.iss&&"object"==typeof r.iss&&!n.inArray(h.iss,r.iss))return!1;if(void 0!==h.sub&&"object"==typeof r.sub&&!n.inArray(h.sub,r.sub))return!1;if(void 0!==h.aud&&"object"==typeof r.aud)if("string"==typeof h.aud){if(!n.inArray(h.aud,r.aud))return!1}else if("object"==typeof h.aud&&!n.includedArray(h.aud,r.aud))return!1;var u=KJUR.jws.IntDate.getNow();return void 0!==r.verifyAt&&"number"==typeof r.verifyAt&&(u=r.verifyAt),void 0!==r.gracePeriod&&"number"==typeof r.gracePeriod||(r.gracePeriod=0),!(void 0!==h.exp&&"number"==typeof h.exp&&h.exp+r.gracePeriod<u)&&(!(void 0!==h.nbf&&"number"==typeof h.nbf&&u<h.nbf-r.gracePeriod)&&(!(void 0!==h.iat&&"number"==typeof h.iat&&u<h.iat-r.gracePeriod)&&((void 0===h.jti||void 0===r.jti||h.jti===r.jti)&&!!KJUR.jws.JWS.verify(t,e,r.alg))))},KJUR.jws.JWS.includedArray=function(t,e){var r=KJUR.jws.JWS.inArray;if(null===t)return!1;if("object"!=typeof t)return!1;if("number"!=typeof t.length)return!1;for(var n=0;n<t.length;n++)if(!r(t[n],e))return!1;return!0},KJUR.jws.JWS.inArray=function(t,e){if(null===e)return!1;if("object"!=typeof e)return!1;if("number"!=typeof e.length)return!1;for(var r=0;r<e.length;r++)if(e[r]==t)return!0;return!1},KJUR.jws.JWS.jwsalg2sigalg={HS256:"HmacSHA256",HS384:"HmacSHA384",HS512:"HmacSHA512",RS256:"SHA256withRSA",RS384:"SHA384withRSA",RS512:"SHA512withRSA",ES256:"SHA256withECDSA",ES384:"SHA384withECDSA",PS256:"SHA256withRSAandMGF1",PS384:"SHA384withRSAandMGF1",PS512:"SHA512withRSAandMGF1",none:"none"},KJUR.jws.JWS.isSafeJSONString=function(t,e,r){var n=null;try{return"object"!=typeof(n=jsonParse(t))?0:n.constructor===Array?0:(e&&(e[r]=n),1)}catch(t){return 0}},KJUR.jws.JWS.readSafeJSONString=function(t){var e=null;try{return"object"!=typeof(e=jsonParse(t))?null:e.constructor===Array?null:e}catch(t){return null}},KJUR.jws.JWS.getEncodedSignatureValueFromJWS=function(t){if(null==t.match(/^[^.]+\.[^.]+\.([^.]+)$/))throw"JWS signature is not a form of 'Head.Payload.SigValue'.";return RegExp.$1},KJUR.jws.JWS.getJWKthumbprint=function(t){if("RSA"!==t.kty&&"EC"!==t.kty&&"oct"!==t.kty)throw"unsupported algorithm for JWK Thumprint";var e="{";if("RSA"===t.kty){if("string"!=typeof t.n||"string"!=typeof t.e)throw"wrong n and e value for RSA key";e+='"e":"'+t.e+'",',e+='"kty":"'+t.kty+'",',e+='"n":"'+t.n+'"}'}else if("EC"===t.kty){if("string"!=typeof t.crv||"string"!=typeof t.x||"string"!=typeof t.y)throw"wrong crv, x and y value for EC key";e+='"crv":"'+t.crv+'",',e+='"kty":"'+t.kty+'",',e+='"x":"'+t.x+'",',e+='"y":"'+t.y+'"}'}else if("oct"===t.kty){if("string"!=typeof t.k)throw"wrong k value for oct(symmetric) key";e+='"kty":"'+t.kty+'",',e+='"k":"'+t.k+'"}'}var r=rstrtohex(e);return hextob64u(KJUR.crypto.Util.hashHex(r,"sha256"))},KJUR.jws.IntDate={},KJUR.jws.IntDate.get=function(t){if("now"==t)return KJUR.jws.IntDate.getNow();if("now + 1hour"==t)return KJUR.jws.IntDate.getNow()+3600;if("now + 1day"==t)return KJUR.jws.IntDate.getNow()+86400;if("now + 1month"==t)return KJUR.jws.IntDate.getNow()+2592e3;if("now + 1year"==t)return KJUR.jws.IntDate.getNow()+31536e3;if(t.match(/Z$/))return KJUR.jws.IntDate.getZulu(t);if(t.match(/^[0-9]+$/))return parseInt(t);throw"unsupported format: "+t},KJUR.jws.IntDate.getZulu=function(t){if(t.match(/(\d+)(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)Z/)){var e=RegExp.$1,r=parseInt(e);if(4==e.length);else{if(2!=e.length)throw"malformed year string";if(50<=r&&r<100)r=1900+r;else{if(!(0<=r&&r<50))throw"malformed year string for UTCTime";r=2e3+r}}var n=parseInt(RegExp.$2)-1,i=parseInt(RegExp.$3),s=parseInt(RegExp.$4),o=parseInt(RegExp.$5),a=parseInt(RegExp.$6);return~~(new Date(Date.UTC(r,n,i,s,o,a))/1e3)}throw"unsupported format: "+t},KJUR.jws.IntDate.getNow=function(){return~~(new Date/1e3)},KJUR.jws.IntDate.intDate2UTCString=function(t){return new Date(1e3*t).toUTCString()},KJUR.jws.IntDate.intDate2Zulu=function(t){var e=new Date(1e3*t);return("0000"+e.getUTCFullYear()).slice(-4)+("00"+(e.getUTCMonth()+1)).slice(-2)+("00"+e.getUTCDate()).slice(-2)+("00"+e.getUTCHours()).slice(-2)+("00"+e.getUTCMinutes()).slice(-2)+("00"+e.getUTCSeconds()).slice(-2)+"Z"},void 0!==KJUR&&KJUR||(KJUR={}),void 0!==KJUR.crypto&&KJUR.crypto||(KJUR.crypto={}),KJUR.crypto.Util=new function(){this.DIGESTINFOHEAD={sha1:"3021300906052b0e03021a05000414",sha224:"302d300d06096086480165030402040500041c",sha256:"3031300d060960864801650304020105000420",sha384:"3041300d060960864801650304020205000430",sha512:"3051300d060960864801650304020305000440",md2:"3020300c06082a864886f70d020205000410",md5:"3020300c06082a864886f70d020505000410",ripemd160:"3021300906052b2403020105000414"},this.DEFAULTPROVIDER={md5:"cryptojs",sha1:"cryptojs",sha224:"cryptojs",sha256:"cryptojs",sha384:"cryptojs",sha512:"cryptojs",ripemd160:"cryptojs",hmacmd5:"cryptojs",hmacsha1:"cryptojs",hmacsha224:"cryptojs",hmacsha256:"cryptojs",hmacsha384:"cryptojs",hmacsha512:"cryptojs",hmacripemd160:"cryptojs",MD5withRSA:"cryptojs/jsrsa",SHA1withRSA:"cryptojs/jsrsa",SHA224withRSA:"cryptojs/jsrsa",SHA256withRSA:"cryptojs/jsrsa",SHA384withRSA:"cryptojs/jsrsa",SHA512withRSA:"cryptojs/jsrsa",RIPEMD160withRSA:"cryptojs/jsrsa",MD5withECDSA:"cryptojs/jsrsa",SHA1withECDSA:"cryptojs/jsrsa",SHA224withECDSA:"cryptojs/jsrsa",SHA256withECDSA:"cryptojs/jsrsa",SHA384withECDSA:"cryptojs/jsrsa",SHA512withECDSA:"cryptojs/jsrsa",RIPEMD160withECDSA:"cryptojs/jsrsa",SHA1withDSA:"cryptojs/jsrsa",SHA224withDSA:"cryptojs/jsrsa",SHA256withDSA:"cryptojs/jsrsa",MD5withRSAandMGF1:"cryptojs/jsrsa",SHA1withRSAandMGF1:"cryptojs/jsrsa",SHA224withRSAandMGF1:"cryptojs/jsrsa",SHA256withRSAandMGF1:"cryptojs/jsrsa",SHA384withRSAandMGF1:"cryptojs/jsrsa",SHA512withRSAandMGF1:"cryptojs/jsrsa",RIPEMD160withRSAandMGF1:"cryptojs/jsrsa"},this.CRYPTOJSMESSAGEDIGESTNAME={md5:CryptoJS.algo.MD5,sha1:CryptoJS.algo.SHA1,sha224:CryptoJS.algo.SHA224,sha256:CryptoJS.algo.SHA256,sha384:CryptoJS.algo.SHA384,sha512:CryptoJS.algo.SHA512,ripemd160:CryptoJS.algo.RIPEMD160},this.getDigestInfoHex=function(t,e){if(void 0===this.DIGESTINFOHEAD[e])throw"alg not supported in Util.DIGESTINFOHEAD: "+e;return this.DIGESTINFOHEAD[e]+t},this.getPaddedDigestInfoHex=function(t,e,r){var n=this.getDigestInfoHex(t,e),i=r/4;if(n.length+22>i)throw"key is too short for SigAlg: keylen="+r+","+e;for(var s="00"+n,o="",a=i-"0001".length-s.length,h=0;h<a;h+=2)o+="ff";return"0001"+o+s},this.hashString=function(t,e){return new KJUR.crypto.MessageDigest({alg:e}).digestString(t)},this.hashHex=function(t,e){return new KJUR.crypto.MessageDigest({alg:e}).digestHex(t)},this.sha1=function(t){return new KJUR.crypto.MessageDigest({alg:"sha1",prov:"cryptojs"}).digestString(t)},this.sha256=function(t){return new KJUR.crypto.MessageDigest({alg:"sha256",prov:"cryptojs"}).digestString(t)},this.sha256Hex=function(t){return new KJUR.crypto.MessageDigest({alg:"sha256",prov:"cryptojs"}).digestHex(t)},this.sha512=function(t){return new KJUR.crypto.MessageDigest({alg:"sha512",prov:"cryptojs"}).digestString(t)},this.sha512Hex=function(t){return new KJUR.crypto.MessageDigest({alg:"sha512",prov:"cryptojs"}).digestHex(t)},this.md5=function(t){return new KJUR.crypto.MessageDigest({alg:"md5",prov:"cryptojs"}).digestString(t)},this.ripemd160=function(t){return new KJUR.crypto.MessageDigest({alg:"ripemd160",prov:"cryptojs"}).digestString(t)},this.getCryptoJSMDByName=function(t){}},KJUR.crypto.MessageDigest=function(t){this.setAlgAndProvider=function(e,t){if(null!=e&&void 0===t&&(t=KJUR.crypto.Util.DEFAULTPROVIDER[e]),-1!=":md5:sha1:sha224:sha256:sha384:sha512:ripemd160:".indexOf(e)&&"cryptojs"==t){try{this.md=KJUR.crypto.Util.CRYPTOJSMESSAGEDIGESTNAME[e].create()}catch(t){throw"setAlgAndProvider hash alg set fail alg="+e+"/"+t}this.updateString=function(t){this.md.update(t)},this.updateHex=function(t){var e=CryptoJS.enc.Hex.parse(t);this.md.update(e)},this.digest=function(){return this.md.finalize().toString(CryptoJS.enc.Hex)},this.digestString=function(t){return this.updateString(t),this.digest()},this.digestHex=function(t){return this.updateHex(t),this.digest()}}if(-1!=":sha256:".indexOf(e)&&"sjcl"==t){try{this.md=new sjcl.hash.sha256}catch(t){throw"setAlgAndProvider hash alg set fail alg="+e+"/"+t}this.updateString=function(t){this.md.update(t)},this.updateHex=function(t){var e=sjcl.codec.hex.toBits(t);this.md.update(e)},this.digest=function(){var t=this.md.finalize();return sjcl.codec.hex.fromBits(t)},this.digestString=function(t){return this.updateString(t),this.digest()},this.digestHex=function(t){return this.updateHex(t),this.digest()}}},this.updateString=function(t){throw"updateString(str) not supported for this alg/prov: "+this.algName+"/"+this.provName},this.updateHex=function(t){throw"updateHex(hex) not supported for this alg/prov: "+this.algName+"/"+this.provName},this.digest=function(){throw"digest() not supported for this alg/prov: "+this.algName+"/"+this.provName},this.digestString=function(t){throw"digestString(str) not supported for this alg/prov: "+this.algName+"/"+this.provName},this.digestHex=function(t){throw"digestHex(hex) not supported for this alg/prov: "+this.algName+"/"+this.provName},void 0!==t&&void 0!==t.alg&&(this.algName=t.alg,void 0===t.prov&&(this.provName=KJUR.crypto.Util.DEFAULTPROVIDER[this.algName]),this.setAlgAndProvider(this.algName,this.provName))},KJUR.crypto.Mac=function(t){this.setAlgAndProvider=function(t,e){if(null==(t=t.toLowerCase())&&(t="hmacsha1"),"hmac"!=(t=t.toLowerCase()).substr(0,4))throw"setAlgAndProvider unsupported HMAC alg: "+t;void 0===e&&(e=KJUR.crypto.Util.DEFAULTPROVIDER[t]),this.algProv=t+"/"+e;var r=t.substr(4);if(-1!=":md5:sha1:sha224:sha256:sha384:sha512:ripemd160:".indexOf(r)&&"cryptojs"==e){try{var n=KJUR.crypto.Util.CRYPTOJSMESSAGEDIGESTNAME[r];this.mac=CryptoJS.algo.HMAC.create(n,this.pass)}catch(t){throw"setAlgAndProvider hash alg set fail hashAlg="+r+"/"+t}this.updateString=function(t){this.mac.update(t)},this.updateHex=function(t){var e=CryptoJS.enc.Hex.parse(t);this.mac.update(e)},this.doFinal=function(){return this.mac.finalize().toString(CryptoJS.enc.Hex)},this.doFinalString=function(t){return this.updateString(t),this.doFinal()},this.doFinalHex=function(t){return this.updateHex(t),this.doFinal()}}},this.updateString=function(t){throw"updateString(str) not supported for this alg/prov: "+this.algProv},this.updateHex=function(t){throw"updateHex(hex) not supported for this alg/prov: "+this.algProv},this.doFinal=function(){throw"digest() not supported for this alg/prov: "+this.algProv},this.doFinalString=function(t){throw"digestString(str) not supported for this alg/prov: "+this.algProv},this.doFinalHex=function(t){throw"digestHex(hex) not supported for this alg/prov: "+this.algProv},this.setPassword=function(t){if("string"==typeof t){var e=t;return t.length%2!=1&&t.match(/^[0-9A-Fa-f]+$/)||(e=rstrtohex(t)),void(this.pass=CryptoJS.enc.Hex.parse(e))}if("object"!=typeof t)throw"KJUR.crypto.Mac unsupported password type: "+t;e=null;if(void 0!==t.hex){if(t.hex.length%2!=0||!t.hex.match(/^[0-9A-Fa-f]+$/))throw"Mac: wrong hex password: "+t.hex;e=t.hex}if(void 0!==t.utf8&&(e=utf8tohex(t.utf8)),void 0!==t.rstr&&(e=rstrtohex(t.rstr)),void 0!==t.b64&&(e=b64tohex(t.b64)),void 0!==t.b64u&&(e=b64utohex(t.b64u)),null==e)throw"KJUR.crypto.Mac unsupported password type: "+t;this.pass=CryptoJS.enc.Hex.parse(e)},void 0!==t&&(void 0!==t.pass&&this.setPassword(t.pass),void 0!==t.alg&&(this.algName=t.alg,void 0===t.prov&&(this.provName=KJUR.crypto.Util.DEFAULTPROVIDER[this.algName]),this.setAlgAndProvider(this.algName,this.provName)))},KJUR.crypto.Signature=function(t){var e=null;if(this._setAlgNames=function(){this.algName.match(/^(.+)with(.+)$/)&&(this.mdAlgName=RegExp.$1.toLowerCase(),this.pubkeyAlgName=RegExp.$2.toLowerCase())},this._zeroPaddingOfSignature=function(t,e){for(var r="",n=e/4-t.length,i=0;i<n;i++)r+="0";return r+t},this.setAlgAndProvider=function(t,e){if(this._setAlgNames(),"cryptojs/jsrsa"!=e)throw"provider not supported: "+e;if(-1!=":md5:sha1:sha224:sha256:sha384:sha512:ripemd160:".indexOf(this.mdAlgName)){try{this.md=new KJUR.crypto.MessageDigest({alg:this.mdAlgName})}catch(t){throw"setAlgAndProvider hash alg set fail alg="+this.mdAlgName+"/"+t}this.init=function(t,e){var r=null;try{r=void 0===e?KEYUTIL.getKey(t):KEYUTIL.getKey(t,e)}catch(t){throw"init failed:"+t}if(!0===r.isPrivate)this.prvKey=r,this.state="SIGN";else{if(!0!==r.isPublic)throw"init failed.:"+r;this.pubKey=r,this.state="VERIFY"}},this.initSign=function(t){"string"==typeof t.ecprvhex&&"string"==typeof t.eccurvename?(this.ecprvhex=t.ecprvhex,this.eccurvename=t.eccurvename):this.prvKey=t,this.state="SIGN"},this.initVerifyByPublicKey=function(t){"string"==typeof t.ecpubhex&&"string"==typeof t.eccurvename?(this.ecpubhex=t.ecpubhex,this.eccurvename=t.eccurvename):t instanceof KJUR.crypto.ECDSA?this.pubKey=t:t instanceof RSAKey&&(this.pubKey=t),this.state="VERIFY"},this.initVerifyByCertificatePEM=function(t){var e=new X509;e.readCertPEM(t),this.pubKey=e.subjectPublicKeyRSA,this.state="VERIFY"},this.updateString=function(t){this.md.updateString(t)},this.updateHex=function(t){this.md.updateHex(t)},this.sign=function(){if(this.sHashHex=this.md.digest(),void 0!==this.ecprvhex&&void 0!==this.eccurvename){var t=new KJUR.crypto.ECDSA({curve:this.eccurvename});this.hSign=t.signHex(this.sHashHex,this.ecprvhex)}else if(this.prvKey instanceof RSAKey&&"rsaandmgf1"==this.pubkeyAlgName)this.hSign=this.prvKey.signWithMessageHashPSS(this.sHashHex,this.mdAlgName,this.pssSaltLen);else if(this.prvKey instanceof RSAKey&&"rsa"==this.pubkeyAlgName)this.hSign=this.prvKey.signWithMessageHash(this.sHashHex,this.mdAlgName);else if(this.prvKey instanceof KJUR.crypto.ECDSA)this.hSign=this.prvKey.signWithMessageHash(this.sHashHex);else{if(!(this.prvKey instanceof KJUR.crypto.DSA))throw"Signature: unsupported public key alg: "+this.pubkeyAlgName;this.hSign=this.prvKey.signWithMessageHash(this.sHashHex)}return this.hSign},this.signString=function(t){return this.updateString(t),this.sign()},this.signHex=function(t){return this.updateHex(t),this.sign()},this.verify=function(t){if(this.sHashHex=this.md.digest(),void 0!==this.ecpubhex&&void 0!==this.eccurvename)return new KJUR.crypto.ECDSA({curve:this.eccurvename}).verifyHex(this.sHashHex,t,this.ecpubhex);if(this.pubKey instanceof RSAKey&&"rsaandmgf1"==this.pubkeyAlgName)return this.pubKey.verifyWithMessageHashPSS(this.sHashHex,t,this.mdAlgName,this.pssSaltLen);if(this.pubKey instanceof RSAKey&&"rsa"==this.pubkeyAlgName)return this.pubKey.verifyWithMessageHash(this.sHashHex,t);if(this.pubKey instanceof KJUR.crypto.ECDSA)return this.pubKey.verifyWithMessageHash(this.sHashHex,t);if(this.pubKey instanceof KJUR.crypto.DSA)return this.pubKey.verifyWithMessageHash(this.sHashHex,t);throw"Signature: unsupported public key alg: "+this.pubkeyAlgName}}},this.init=function(t,e){throw"init(key, pass) not supported for this alg:prov="+this.algProvName},this.initVerifyByPublicKey=function(t){throw"initVerifyByPublicKey(rsaPubKeyy) not supported for this alg:prov="+this.algProvName},this.initVerifyByCertificatePEM=function(t){throw"initVerifyByCertificatePEM(certPEM) not supported for this alg:prov="+this.algProvName},this.initSign=function(t){throw"initSign(prvKey) not supported for this alg:prov="+this.algProvName},this.updateString=function(t){throw"updateString(str) not supported for this alg:prov="+this.algProvName},this.updateHex=function(t){throw"updateHex(hex) not supported for this alg:prov="+this.algProvName},this.sign=function(){throw"sign() not supported for this alg:prov="+this.algProvName},this.signString=function(t){throw"digestString(str) not supported for this alg:prov="+this.algProvName},this.signHex=function(t){throw"digestHex(hex) not supported for this alg:prov="+this.algProvName},this.verify=function(t){throw"verify(hSigVal) not supported for this alg:prov="+this.algProvName},void 0!==(this.initParams=t)&&(void 0!==t.alg&&(this.algName=t.alg,void 0===t.prov?this.provName=KJUR.crypto.Util.DEFAULTPROVIDER[this.algName]:this.provName=t.prov,this.algProvName=this.algName+":"+this.provName,this.setAlgAndProvider(this.algName,this.provName),this._setAlgNames()),void 0!==t.psssaltlen&&(this.pssSaltLen=t.psssaltlen),void 0!==t.prvkeypem)){if(void 0!==t.prvkeypas)throw"both prvkeypem and prvkeypas parameters not supported";try{(e=new RSAKey).readPrivateKeyFromPEMString(t.prvkeypem),this.initSign(e)}catch(t){throw"fatal error to load pem private key: "+t}}},KJUR.crypto.OID=new function(){this.oidhex2name={"2a864886f70d010101":"rsaEncryption","2a8648ce3d0201":"ecPublicKey","2a8648ce380401":"dsa","2a8648ce3d030107":"secp256r1","2b8104001f":"secp192k1","2b81040021":"secp224r1","2b8104000a":"secp256k1","2b81040023":"secp521r1","2b81040022":"secp384r1","2a8648ce380403":"SHA1withDSA","608648016503040301":"SHA224withDSA","608648016503040302":"SHA256withDSA"}},void 0!==KJUR&&KJUR||(KJUR={}),void 0!==KJUR.lang&&KJUR.lang||(KJUR.lang={}),KJUR.lang.String=function(){},b64utoutf8="function"==typeof Buffer?(utf8tob64u=function(t){return b64tob64u(new Buffer(t,"utf8").toString("base64"))},function(t){return new Buffer(b64utob64(t),"base64").toString("utf8")}):(utf8tob64u=function(t){return hextob64u(uricmptohex(encodeURIComponentAll(t)))},function(t){return decodeURIComponent(hextouricmp(b64utohex(t)))}),KJUR.lang.String.isInteger=function(t){return!!t.match(/^[0-9]+$/)||!!t.match(/^-[0-9]+$/)},KJUR.lang.String.isHex=function(t){return!(t.length%2!=0||!t.match(/^[0-9a-f]+$/)&&!t.match(/^[0-9A-F]+$/))},KJUR.lang.String.isBase64=function(t){return!(!(t=t.replace(/\s+/g,"")).match(/^[0-9A-Za-z+\/]+={0,3}$/)||t.length%4!=0)},KJUR.lang.String.isBase64URL=function(t){return!t.match(/[+/=]/)&&(t=b64utob64(t),KJUR.lang.String.isBase64(t))},KJUR.lang.String.isIntegerArray=function(t){return!!(t=t.replace(/\s+/g,"")).match(/^\[[0-9,]+\]$/)};var strdiffidx=function(t,e){var r=t.length;t.length>e.length&&(r=e.length);for(var n=0;n<r;n++)if(t.charCodeAt(n)!=e.charCodeAt(n))return n;return t.length!=e.length?r:-1};function parseBigInt(t,e){return new BigInteger(t,e)}function linebrk(t,e){for(var r="",n=0;n+e<t.length;)r+=t.substring(n,n+e)+"\n",n+=e;return r+t.substring(n,t.length)}function byte2Hex(t){return t<16?"0"+t.toString(16):t.toString(16)}function pkcs1pad2(t,e){if(e<t.length+11)return alert("Message too long for RSA"),null;for(var r=new Array,n=t.length-1;0<=n&&0<e;){var i=t.charCodeAt(n--);i<128?r[--e]=i:127<i&&i<2048?(r[--e]=63&i|128,r[--e]=i>>6|192):(r[--e]=63&i|128,r[--e]=i>>6&63|128,r[--e]=i>>12|224)}r[--e]=0;for(var s=new SecureRandom,o=new Array;2<e;){for(o[0]=0;0==o[0];)s.nextBytes(o);r[--e]=o[0]}return r[--e]=2,r[--e]=0,new BigInteger(r)}function oaep_mgf1_arr(t,e,r){for(var n="",i=0;n.length<e;)n+=r(String.fromCharCode.apply(String,t.concat([(4278190080&i)>>24,(16711680&i)>>16,(65280&i)>>8,255&i]))),i+=1;return n}function oaep_pad(t,e,r,n){if(r||(r=rstr_sha1,n=20),t.length+2*n+2>e)throw"Message too long for RSA";var i,s="";for(i=0;i<e-t.length-2*n-2;i+=1)s+="\0";var o=r("")+s+""+t,a=new Array(n);(new SecureRandom).nextBytes(a);var h=oaep_mgf1_arr(a,o.length,r),u=[];for(i=0;i<o.length;i+=1)u[i]=o.charCodeAt(i)^h.charCodeAt(i);var p=oaep_mgf1_arr(u,a.length,r),c=[0];for(i=0;i<a.length;i+=1)c[i+1]=a[i]^p.charCodeAt(i);return new BigInteger(c.concat(u))}function RSAKey(){this.n=null,this.e=0,this.d=null,this.p=null,this.q=null,this.dmp1=null,this.dmq1=null,this.coeff=null}function RSASetPublic(t,e){this.isPublic=!0,"string"!=typeof t?(this.n=t,this.e=e):null!=t&&null!=e&&0<t.length&&0<e.length?(this.n=parseBigInt(t,16),this.e=parseInt(e,16)):alert("Invalid RSA public key")}function RSADoPublic(t){return t.modPowInt(this.e,this.n)}function RSAEncrypt(t){var e=pkcs1pad2(t,this.n.bitLength()+7>>3);if(null==e)return null;var r=this.doPublic(e);if(null==r)return null;var n=r.toString(16);return 0==(1&n.length)?n:"0"+n}function RSAEncryptOAEP(t,e,r){var n=oaep_pad(t,this.n.bitLength()+7>>3,e,r);if(null==n)return null;var i=this.doPublic(n);if(null==i)return null;var s=i.toString(16);return 0==(1&s.length)?s:"0"+s}RSAKey.prototype.doPublic=RSADoPublic,RSAKey.prototype.setPublic=RSASetPublic,RSAKey.prototype.encrypt=RSAEncrypt,RSAKey.prototype.encryptOAEP=RSAEncryptOAEP,RSAKey.prototype.type="RSA";var _RE_HEXDECONLY=new RegExp("");function _rsasign_getHexPaddedDigestInfoForString(t,e,r){var n,i=(n=t,KJUR.crypto.Util.hashString(n,r));return KJUR.crypto.Util.getPaddedDigestInfoHex(i,r,e)}function _zeroPaddingOfSignature(t,e){for(var r="",n=e/4-t.length,i=0;i<n;i++)r+="0";return r+t}function _rsasign_signString(t,e){var r,n=(r=t,KJUR.crypto.Util.hashString(r,e));return this.signWithMessageHash(n,e)}function _rsasign_signWithMessageHash(t,e){var r=parseBigInt(KJUR.crypto.Util.getPaddedDigestInfoHex(t,e,this.n.bitLength()),16);return _zeroPaddingOfSignature(this.doPrivate(r).toString(16),this.n.bitLength())}function _rsasign_signStringWithSHA1(t){return _rsasign_signString.call(this,t,"sha1")}function _rsasign_signStringWithSHA256(t){return _rsasign_signString.call(this,t,"sha256")}function pss_mgf1_str(t,e,r){for(var n="",i=0;n.length<e;)n+=hextorstr(r(rstrtohex(t+String.fromCharCode.apply(String,[(4278190080&i)>>24,(16711680&i)>>16,(65280&i)>>8,255&i])))),i+=1;return n}function _rsasign_signStringPSS(t,e,r){var n,i=(n=rstrtohex(t),KJUR.crypto.Util.hashHex(n,e));return void 0===r&&(r=-1),this.signWithMessageHashPSS(i,e,r)}function _rsasign_signWithMessageHashPSS(t,e,r){var n,i=hextorstr(t),s=i.length,o=this.n.bitLength()-1,a=Math.ceil(o/8),h=function(t){return KJUR.crypto.Util.hashHex(t,e)};if(-1===r||void 0===r)r=s;else if(-2===r)r=a-s-2;else if(r<-2)throw"invalid salt length";if(a<s+r+2)throw"data too long";var u="";0<r&&(u=new Array(r),(new SecureRandom).nextBytes(u),u=String.fromCharCode.apply(String,u));var p=hextorstr(h(rstrtohex("\0\0\0\0\0\0\0\0"+i+u))),c=[];for(n=0;n<a-r-s-2;n+=1)c[n]=0;var l=String.fromCharCode.apply(String,c)+""+u,f=pss_mgf1_str(p,l.length,h),g=[];for(n=0;n<l.length;n+=1)g[n]=l.charCodeAt(n)^f.charCodeAt(n);var d=65280>>8*a-o&255;for(g[0]&=~d,n=0;n<s;n++)g.push(p.charCodeAt(n));return g.push(188),_zeroPaddingOfSignature(this.doPrivate(new BigInteger(g)).toString(16),this.n.bitLength())}function _rsasign_getDecryptSignatureBI(t,e,r){var n=new RSAKey;return n.setPublic(e,r),n.doPublic(t)}function _rsasign_getHexDigestInfoFromSig(t,e,r){return _rsasign_getDecryptSignatureBI(t,e,r).toString(16).replace(/^1f+00/,"")}function _rsasign_getAlgNameAndHashFromHexDisgestInfo(t){for(var e in KJUR.crypto.Util.DIGESTINFOHEAD){var r=KJUR.crypto.Util.DIGESTINFOHEAD[e],n=r.length;if(t.substring(0,n)==r)return[e,t.substring(n)]}return[]}function _rsasign_verifySignatureWithArgs(t,e,r,n){var i=_rsasign_getAlgNameAndHashFromHexDisgestInfo(_rsasign_getHexDigestInfoFromSig(e,r,n));if(0==i.length)return!1;var s,o=i[0];return i[1]==(s=t,KJUR.crypto.Util.hashString(s,o))}function _rsasign_verifyHexSignatureForMessage(t,e){return _rsasign_verifySignatureWithArgs(e,parseBigInt(t,16),this.n.toString(16),this.e.toString(16))}function _rsasign_verifyString(t,e){var r=parseBigInt(e=(e=e.replace(_RE_HEXDECONLY,"")).replace(/[ \n]+/g,""),16);if(r.bitLength()>this.n.bitLength())return 0;var n=_rsasign_getAlgNameAndHashFromHexDisgestInfo(this.doPublic(r).toString(16).replace(/^1f+00/,""));if(0==n.length)return!1;var i,s=n[0];return n[1]==(i=t,KJUR.crypto.Util.hashString(i,s))}function _rsasign_verifyWithMessageHash(t,e){var r=parseBigInt(e=(e=e.replace(_RE_HEXDECONLY,"")).replace(/[ \n]+/g,""),16);if(r.bitLength()>this.n.bitLength())return 0;var n=_rsasign_getAlgNameAndHashFromHexDisgestInfo(this.doPublic(r).toString(16).replace(/^1f+00/,""));if(0==n.length)return!1;n[0];return n[1]==t}function _rsasign_verifyStringPSS(t,e,r,n){var i,s=(i=rstrtohex(t),KJUR.crypto.Util.hashHex(i,r));return void 0===n&&(n=-1),this.verifyWithMessageHashPSS(s,e,r,n)}function _rsasign_verifyWithMessageHashPSS(t,e,r,n){var i=new BigInteger(e,16);if(i.bitLength()>this.n.bitLength())return!1;var s,o=function(t){return KJUR.crypto.Util.hashHex(t,r)},a=hextorstr(t),h=a.length,u=this.n.bitLength()-1,p=Math.ceil(u/8);if(-1===n||void 0===n)n=h;else if(-2===n)n=p-h-2;else if(n<-2)throw"invalid salt length";if(p<h+n+2)throw"data too long";var c=this.doPublic(i).toByteArray();for(s=0;s<c.length;s+=1)c[s]&=255;for(;c.length<p;)c.unshift(0);if(188!==c[p-1])throw"encoded message does not end in 0xbc";var l=(c=String.fromCharCode.apply(String,c)).substr(0,p-h-1),f=c.substr(l.length,h),g=65280>>8*p-u&255;if(0!=(l.charCodeAt(0)&g))throw"bits beyond keysize not zero";var d=pss_mgf1_str(f,l.length,o),y=[];for(s=0;s<l.length;s+=1)y[s]=l.charCodeAt(s)^d.charCodeAt(s);y[0]&=~g;var S=p-h-n-2;for(s=0;s<S;s+=1)if(0!==y[s])throw"leftmost octets not zero";if(1!==y[S])throw"0x01 marker not found";return f===hextorstr(o(rstrtohex("\0\0\0\0\0\0\0\0"+a+String.fromCharCode.apply(String,y.slice(-n)))))}_RE_HEXDECONLY.compile("[^0-9a-f]","gi"),RSAKey.prototype.signWithMessageHash=_rsasign_signWithMessageHash,RSAKey.prototype.signString=_rsasign_signString,RSAKey.prototype.signStringWithSHA1=_rsasign_signStringWithSHA1,RSAKey.prototype.signStringWithSHA256=_rsasign_signStringWithSHA256,RSAKey.prototype.sign=_rsasign_signString,RSAKey.prototype.signWithSHA1=_rsasign_signStringWithSHA1,RSAKey.prototype.signWithSHA256=_rsasign_signStringWithSHA256,RSAKey.prototype.signWithMessageHashPSS=_rsasign_signWithMessageHashPSS,RSAKey.prototype.signStringPSS=_rsasign_signStringPSS,RSAKey.prototype.signPSS=_rsasign_signStringPSS,RSAKey.SALT_LEN_HLEN=-1,RSAKey.SALT_LEN_MAX=-2,RSAKey.prototype.verifyWithMessageHash=_rsasign_verifyWithMessageHash,RSAKey.prototype.verifyString=_rsasign_verifyString,RSAKey.prototype.verifyHexSignatureForMessage=_rsasign_verifyHexSignatureForMessage,RSAKey.prototype.verify=_rsasign_verifyString,RSAKey.prototype.verifyHexSignatureForByteArrayMessage=_rsasign_verifyHexSignatureForMessage,RSAKey.prototype.verifyWithMessageHashPSS=_rsasign_verifyWithMessageHashPSS,RSAKey.prototype.verifyStringPSS=_rsasign_verifyStringPSS,RSAKey.prototype.verifyPSS=_rsasign_verifyStringPSS,RSAKey.SALT_LEN_RECOVER=-2;var KEYUTIL=function(){var t=function(t,e,r){return n(CryptoJS.AES,t,e,r)},n=function(t,e,r,n){var i=CryptoJS.enc.Hex.parse(e),s=CryptoJS.enc.Hex.parse(r),o=CryptoJS.enc.Hex.parse(n),a={};a.key=s,a.iv=o,a.ciphertext=i;var h=t.decrypt(a,s,{iv:o});return CryptoJS.enc.Hex.stringify(h)},e=function(t,e,r){return i(CryptoJS.AES,t,e,r)},i=function(t,e,r,n){var i=CryptoJS.enc.Hex.parse(e),s=CryptoJS.enc.Hex.parse(r),o=CryptoJS.enc.Hex.parse(n),a=t.encrypt(i,s,{iv:o}),h=CryptoJS.enc.Hex.parse(a.toString());return CryptoJS.enc.Base64.stringify(h)},f={"AES-256-CBC":{proc:t,eproc:e,keylen:32,ivlen:16},"AES-192-CBC":{proc:t,eproc:e,keylen:24,ivlen:16},"AES-128-CBC":{proc:t,eproc:e,keylen:16,ivlen:16},"DES-EDE3-CBC":{proc:function(t,e,r){return n(CryptoJS.TripleDES,t,e,r)},eproc:function(t,e,r){return i(CryptoJS.TripleDES,t,e,r)},keylen:24,ivlen:8},"DES-CBC":{proc:function(t,e,r){return n(CryptoJS.DES,t,e,r)},eproc:function(t,e,r){return i(CryptoJS.DES,t,e,r)},keylen:8,ivlen:8}},a=function(t){var e={};t.match(new RegExp("DEK-Info: ([^,]+),([0-9A-Fa-f]+)","m"))&&(e.cipher=RegExp.$1,e.ivsalt=RegExp.$2),t.match(new RegExp("-----BEGIN ([A-Z]+) PRIVATE KEY-----"))&&(e.type=RegExp.$1);var r=-1,n=0;-1!=t.indexOf("\r\n\r\n")&&(r=t.indexOf("\r\n\r\n"),n=2),-1!=t.indexOf("\n\n")&&(r=t.indexOf("\n\n"),n=1);var i=t.indexOf("-----END");if(-1!=r&&-1!=i){var s=t.substring(r+2*n,i-n);s=s.replace(/\s+/g,""),e.data=s}return e},g=function(t,e,r){for(var n=r.substring(0,16),i=CryptoJS.enc.Hex.parse(n),s=CryptoJS.enc.Utf8.parse(e),o=f[t].keylen+f[t].ivlen,a="",h=null;;){var u=CryptoJS.algo.MD5.create();if(null!=h&&u.update(h),u.update(s),u.update(i),h=u.finalize(),(a+=CryptoJS.enc.Hex.stringify(h)).length>=2*o)break}var p={};return p.keyhex=a.substr(0,2*f[t].keylen),p.ivhex=a.substr(2*f[t].keylen,2*f[t].ivlen),p},h=function(t,e,r,n){var i=CryptoJS.enc.Base64.parse(t),s=CryptoJS.enc.Hex.stringify(i);return(0,f[e].proc)(s,r,n)};return{version:"1.0.0",getHexFromPEM:function(t,e){var r=t;if(-1==r.indexOf("-----BEGIN "))throw"can't find PEM header: "+e;var n=(r="string"==typeof e&&""!=e?(r=r.replace("-----BEGIN "+e+"-----","")).replace("-----END "+e+"-----",""):(r=r.replace(/-----BEGIN [^-]+-----/,"")).replace(/-----END [^-]+-----/,"")).replace(/\s+/g,"");return b64tohex(n)},getDecryptedKeyHexByKeyIV:function(t,e,r,n){return(0,f[e].proc)(t,r,n)},parsePKCS5PEM:function(t){return a(t)},getKeyAndUnusedIvByPasscodeAndIvsalt:function(t,e,r){return g(t,e,r)},decryptKeyB64:function(t,e,r,n){return h(t,e,r,n)},getDecryptedKeyHex:function(t,e){var r=a(t),n=(r.type,r.cipher),i=r.ivsalt,s=r.data,o=g(n,e,i).keyhex;return h(s,n,o,i)},getRSAKeyFromEncryptedPKCS5PEM:function(t,e){var r=this.getDecryptedKeyHex(t,e),n=new RSAKey;return n.readPrivateKeyFromASN1HexString(r),n},getEncryptedPKCS5PEMFromPrvKeyHex:function(t,e,r,n,i){var s,o,a="";if(void 0!==n&&null!=n||(n="AES-256-CBC"),void 0===f[n])throw"KEYUTIL unsupported algorithm: "+n;if(void 0===i||null==i){var h=f[n].ivlen;i=(s=h,o=CryptoJS.lib.WordArray.random(s),CryptoJS.enc.Hex.stringify(o)).toUpperCase()}var u,p,c,l=g(n,r,i).keyhex;a="-----BEGIN "+t+" PRIVATE KEY-----\r\n";return a+="Proc-Type: 4,ENCRYPTED\r\n",a+="DEK-Info: "+n+","+i+"\r\n",a+="\r\n",a+=(u=e,p=l,c=i,(0,f[n].eproc)(u,p,c)).replace(/(.{64})/g,"$1\r\n"),a+="\r\n-----END "+t+" PRIVATE KEY-----\r\n"},getEncryptedPKCS5PEMFromRSAKey:function(t,e,r,n){var i=new KJUR.asn1.DERInteger({int:0}),s=new KJUR.asn1.DERInteger({bigint:t.n}),o=new KJUR.asn1.DERInteger({int:t.e}),a=new KJUR.asn1.DERInteger({bigint:t.d}),h=new KJUR.asn1.DERInteger({bigint:t.p}),u=new KJUR.asn1.DERInteger({bigint:t.q}),p=new KJUR.asn1.DERInteger({bigint:t.dmp1}),c=new KJUR.asn1.DERInteger({bigint:t.dmq1}),l=new KJUR.asn1.DERInteger({bigint:t.coeff}),f=new KJUR.asn1.DERSequence({array:[i,s,o,a,h,u,p,c,l]}).getEncodedHex();return this.getEncryptedPKCS5PEMFromPrvKeyHex("RSA",f,e,r,n)},newEncryptedPKCS5PEM:function(t,e,r,n){void 0!==e&&null!=e||(e=1024),void 0!==r&&null!=r||(r="10001");var i=new RSAKey;i.generate(e,r);return void 0===n||null==n?this.getEncryptedPKCS5PEMFromRSAKey(i,t):this.getEncryptedPKCS5PEMFromRSAKey(i,t,n)},getRSAKeyFromPlainPKCS8PEM:function(t){if(t.match(/ENCRYPTED/))throw"pem shall be not ENCRYPTED";var e=this.getHexFromPEM(t,"PRIVATE KEY");return this.getRSAKeyFromPlainPKCS8Hex(e)},getRSAKeyFromPlainPKCS8Hex:function(t){var e=ASN1HEX.getPosArrayOfChildren_AtObj(t,0);if(3!=e.length)throw"outer DERSequence shall have 3 elements: "+e.length;if("300d06092a864886f70d0101010500"!=(r=ASN1HEX.getHexOfTLV_AtObj(t,e[1])))throw"PKCS8 AlgorithmIdentifier is not rsaEnc: "+r;var r=ASN1HEX.getHexOfTLV_AtObj(t,e[1]),n=ASN1HEX.getHexOfTLV_AtObj(t,e[2]),i=ASN1HEX.getHexOfV_AtObj(n,0),s=new RSAKey;return s.readPrivateKeyFromASN1HexString(i),s},parseHexOfEncryptedPKCS8:function(t){var e={},r=ASN1HEX.getPosArrayOfChildren_AtObj(t,0);if(2!=r.length)throw"malformed format: SEQUENCE(0).items != 2: "+r.length;e.ciphertext=ASN1HEX.getHexOfV_AtObj(t,r[1]);var n=ASN1HEX.getPosArrayOfChildren_AtObj(t,r[0]);if(2!=n.length)throw"malformed format: SEQUENCE(0.0).items != 2: "+n.length;if("2a864886f70d01050d"!=ASN1HEX.getHexOfV_AtObj(t,n[0]))throw"this only supports pkcs5PBES2";var i=ASN1HEX.getPosArrayOfChildren_AtObj(t,n[1]);if(2!=n.length)throw"malformed format: SEQUENCE(0.0.1).items != 2: "+i.length;var s=ASN1HEX.getPosArrayOfChildren_AtObj(t,i[1]);if(2!=s.length)throw"malformed format: SEQUENCE(0.0.1.1).items != 2: "+s.length;if("2a864886f70d0307"!=ASN1HEX.getHexOfV_AtObj(t,s[0]))throw"this only supports TripleDES";e.encryptionSchemeAlg="TripleDES",e.encryptionSchemeIV=ASN1HEX.getHexOfV_AtObj(t,s[1]);var o=ASN1HEX.getPosArrayOfChildren_AtObj(t,i[0]);if(2!=o.length)throw"malformed format: SEQUENCE(0.0.1.0).items != 2: "+o.length;if("2a864886f70d01050c"!=ASN1HEX.getHexOfV_AtObj(t,o[0]))throw"this only supports pkcs5PBKDF2";var a=ASN1HEX.getPosArrayOfChildren_AtObj(t,o[1]);if(a.length<2)throw"malformed format: SEQUENCE(0.0.1.0.1).items < 2: "+a.length;e.pbkdf2Salt=ASN1HEX.getHexOfV_AtObj(t,a[0]);var h=ASN1HEX.getHexOfV_AtObj(t,a[1]);try{e.pbkdf2Iter=parseInt(h,16)}catch(t){throw"malformed format pbkdf2Iter: "+h}return e},getPBKDF2KeyHexFromParam:function(t,e){var r=CryptoJS.enc.Hex.parse(t.pbkdf2Salt),n=t.pbkdf2Iter,i=CryptoJS.PBKDF2(e,r,{keySize:6,iterations:n});return CryptoJS.enc.Hex.stringify(i)},getPlainPKCS8HexFromEncryptedPKCS8PEM:function(t,e){var r=this.getHexFromPEM(t,"ENCRYPTED PRIVATE KEY"),n=this.parseHexOfEncryptedPKCS8(r),i=KEYUTIL.getPBKDF2KeyHexFromParam(n,e),s={};s.ciphertext=CryptoJS.enc.Hex.parse(n.ciphertext);var o=CryptoJS.enc.Hex.parse(i),a=CryptoJS.enc.Hex.parse(n.encryptionSchemeIV),h=CryptoJS.TripleDES.decrypt(s,o,{iv:a});return CryptoJS.enc.Hex.stringify(h)},getRSAKeyFromEncryptedPKCS8PEM:function(t,e){var r=this.getPlainPKCS8HexFromEncryptedPKCS8PEM(t,e);return this.getRSAKeyFromPlainPKCS8Hex(r)},getKeyFromEncryptedPKCS8PEM:function(t,e){var r=this.getPlainPKCS8HexFromEncryptedPKCS8PEM(t,e);return this.getKeyFromPlainPrivatePKCS8Hex(r)},parsePlainPrivatePKCS8Hex:function(t){var e={algparam:null};if("30"!=t.substr(0,2))throw"malformed plain PKCS8 private key(code:001)";var r=ASN1HEX.getPosArrayOfChildren_AtObj(t,0);if(3!=r.length)throw"malformed plain PKCS8 private key(code:002)";if("30"!=t.substr(r[1],2))throw"malformed PKCS8 private key(code:003)";var n=ASN1HEX.getPosArrayOfChildren_AtObj(t,r[1]);if(2!=n.length)throw"malformed PKCS8 private key(code:004)";if("06"!=t.substr(n[0],2))throw"malformed PKCS8 private key(code:005)";if(e.algoid=ASN1HEX.getHexOfV_AtObj(t,n[0]),"06"==t.substr(n[1],2)&&(e.algparam=ASN1HEX.getHexOfV_AtObj(t,n[1])),"04"!=t.substr(r[2],2))throw"malformed PKCS8 private key(code:006)";return e.keyidx=ASN1HEX.getStartPosOfV_AtObj(t,r[2]),e},getKeyFromPlainPrivatePKCS8PEM:function(t){var e=this.getHexFromPEM(t,"PRIVATE KEY");return this.getKeyFromPlainPrivatePKCS8Hex(e)},getKeyFromPlainPrivatePKCS8Hex:function(t){var e=this.parsePlainPrivatePKCS8Hex(t);if("2a864886f70d010101"==e.algoid){this.parsePrivateRawRSAKeyHexAtObj(t,e);var r=e.key;return(i=new RSAKey).setPrivateEx(r.n,r.e,r.d,r.p,r.q,r.dp,r.dq,r.co),i}if("2a8648ce3d0201"==e.algoid){if(this.parsePrivateRawECKeyHexAtObj(t,e),void 0===KJUR.crypto.OID.oidhex2name[e.algparam])throw"KJUR.crypto.OID.oidhex2name undefined: "+e.algparam;var n=KJUR.crypto.OID.oidhex2name[e.algparam];return(i=new KJUR.crypto.ECDSA({curve:n})).setPublicKeyHex(e.pubkey),i.setPrivateKeyHex(e.key),i.isPublic=!1,i}if("2a8648ce380401"!=e.algoid)throw"unsupported private key algorithm";var i,s=ASN1HEX.getVbyList(t,0,[1,1,0],"02"),o=ASN1HEX.getVbyList(t,0,[1,1,1],"02"),a=ASN1HEX.getVbyList(t,0,[1,1,2],"02"),h=ASN1HEX.getVbyList(t,0,[2,0],"02"),u=new BigInteger(s,16),p=new BigInteger(o,16),c=new BigInteger(a,16),l=new BigInteger(h,16);return(i=new KJUR.crypto.DSA).setPrivate(u,p,c,null,l),i},getRSAKeyFromPublicPKCS8PEM:function(t){var e=this.getHexFromPEM(t,"PUBLIC KEY");return this.getRSAKeyFromPublicPKCS8Hex(e)},getKeyFromPublicPKCS8PEM:function(t){var e=this.getHexFromPEM(t,"PUBLIC KEY");return this.getKeyFromPublicPKCS8Hex(e)},getKeyFromPublicPKCS8Hex:function(t){var e=this.parsePublicPKCS8Hex(t);if("2a864886f70d010101"==e.algoid){var r=this.parsePublicRawRSAKeyHex(e.key);return(i=new RSAKey).setPublic(r.n,r.e),i}if("2a8648ce3d0201"==e.algoid){if(void 0===KJUR.crypto.OID.oidhex2name[e.algparam])throw"KJUR.crypto.OID.oidhex2name undefined: "+e.algparam;var n=KJUR.crypto.OID.oidhex2name[e.algparam];return i=new KJUR.crypto.ECDSA({curve:n,pub:e.key})}if("2a8648ce380401"!=e.algoid)throw"unsupported public key algorithm";var i,s=e.algparam,o=ASN1HEX.getHexOfV_AtObj(e.key,0);return(i=new KJUR.crypto.DSA).setPublic(new BigInteger(s.p,16),new BigInteger(s.q,16),new BigInteger(s.g,16),new BigInteger(o,16)),i},parsePublicRawRSAKeyHex:function(t){var e={};if("30"!=t.substr(0,2))throw"malformed RSA key(code:001)";var r=ASN1HEX.getPosArrayOfChildren_AtObj(t,0);if(2!=r.length)throw"malformed RSA key(code:002)";if("02"!=t.substr(r[0],2))throw"malformed RSA key(code:003)";if(e.n=ASN1HEX.getHexOfV_AtObj(t,r[0]),"02"!=t.substr(r[1],2))throw"malformed RSA key(code:004)";return e.e=ASN1HEX.getHexOfV_AtObj(t,r[1]),e},parsePrivateRawRSAKeyHexAtObj:function(t,e){var r=e.keyidx;if("30"!=t.substr(r,2))throw"malformed RSA private key(code:001)";var n=ASN1HEX.getPosArrayOfChildren_AtObj(t,r);if(9!=n.length)throw"malformed RSA private key(code:002)";e.key={},e.key.n=ASN1HEX.getHexOfV_AtObj(t,n[1]),e.key.e=ASN1HEX.getHexOfV_AtObj(t,n[2]),e.key.d=ASN1HEX.getHexOfV_AtObj(t,n[3]),e.key.p=ASN1HEX.getHexOfV_AtObj(t,n[4]),e.key.q=ASN1HEX.getHexOfV_AtObj(t,n[5]),e.key.dp=ASN1HEX.getHexOfV_AtObj(t,n[6]),e.key.dq=ASN1HEX.getHexOfV_AtObj(t,n[7]),e.key.co=ASN1HEX.getHexOfV_AtObj(t,n[8])},parsePrivateRawECKeyHexAtObj:function(t,e){var r=e.keyidx,n=ASN1HEX.getVbyList(t,r,[1],"04"),i=ASN1HEX.getVbyList(t,r,[2,0],"03").substr(2);e.key=n,e.pubkey=i},parsePublicPKCS8Hex:function(t){var e={algparam:null},r=ASN1HEX.getPosArrayOfChildren_AtObj(t,0);if(2!=r.length)throw"outer DERSequence shall have 2 elements: "+r.length;var n=r[0];if("30"!=t.substr(n,2))throw"malformed PKCS8 public key(code:001)";var i=ASN1HEX.getPosArrayOfChildren_AtObj(t,n);if(2!=i.length)throw"malformed PKCS8 public key(code:002)";if("06"!=t.substr(i[0],2))throw"malformed PKCS8 public key(code:003)";if(e.algoid=ASN1HEX.getHexOfV_AtObj(t,i[0]),"06"==t.substr(i[1],2)?e.algparam=ASN1HEX.getHexOfV_AtObj(t,i[1]):"30"==t.substr(i[1],2)&&(e.algparam={},e.algparam.p=ASN1HEX.getVbyList(t,i[1],[0],"02"),e.algparam.q=ASN1HEX.getVbyList(t,i[1],[1],"02"),e.algparam.g=ASN1HEX.getVbyList(t,i[1],[2],"02")),"03"!=t.substr(r[1],2))throw"malformed PKCS8 public key(code:004)";return e.key=ASN1HEX.getHexOfV_AtObj(t,r[1]).substr(2),e},getRSAKeyFromPublicPKCS8Hex:function(t){var e=ASN1HEX.getPosArrayOfChildren_AtObj(t,0);if(2!=e.length)throw"outer DERSequence shall have 2 elements: "+e.length;if("300d06092a864886f70d0101010500"!=ASN1HEX.getHexOfTLV_AtObj(t,e[0]))throw"PKCS8 AlgorithmId is not rsaEncryption";if("03"!=t.substr(e[1],2))throw"PKCS8 Public Key is not BITSTRING encapslated.";var r=ASN1HEX.getStartPosOfV_AtObj(t,e[1])+2;if("30"!=t.substr(r,2))throw"PKCS8 Public Key is not SEQUENCE.";var n=ASN1HEX.getPosArrayOfChildren_AtObj(t,r);if(2!=n.length)throw"inner DERSequence shall have 2 elements: "+n.length;if("02"!=t.substr(n[0],2))throw"N is not ASN.1 INTEGER";if("02"!=t.substr(n[1],2))throw"E is not ASN.1 INTEGER";var i=ASN1HEX.getHexOfV_AtObj(t,n[0]),s=ASN1HEX.getHexOfV_AtObj(t,n[1]),o=new RSAKey;return o.setPublic(i,s),o}}}();KEYUTIL.getKey=function(t,e,r){if(void 0!==RSAKey&&t instanceof RSAKey)return t;if(void 0!==KJUR.crypto.ECDSA&&t instanceof KJUR.crypto.ECDSA)return t;if(void 0!==KJUR.crypto.DSA&&t instanceof KJUR.crypto.DSA)return t;if(void 0!==t.curve&&void 0!==t.xy&&void 0===t.d)return new KJUR.crypto.ECDSA({pub:t.xy,curve:t.curve});if(void 0!==t.curve&&void 0!==t.d)return new KJUR.crypto.ECDSA({prv:t.d,curve:t.curve});if(void 0===t.kty&&void 0!==t.n&&void 0!==t.e&&void 0===t.d)return(g=new RSAKey).setPublic(t.n,t.e),g;if(void 0===t.kty&&void 0!==t.n&&void 0!==t.e&&void 0!==t.d&&void 0!==t.p&&void 0!==t.q&&void 0!==t.dp&&void 0!==t.dq&&void 0!==t.co&&void 0===t.qi)return(g=new RSAKey).setPrivateEx(t.n,t.e,t.d,t.p,t.q,t.dp,t.dq,t.co),g;if(void 0===t.kty&&void 0!==t.n&&void 0!==t.e&&void 0!==t.d&&void 0===t.p)return(g=new RSAKey).setPrivate(t.n,t.e,t.d),g;if(void 0!==t.p&&void 0!==t.q&&void 0!==t.g&&void 0!==t.y&&void 0===t.x)return(g=new KJUR.crypto.DSA).setPublic(t.p,t.q,t.g,t.y),g;if(void 0!==t.p&&void 0!==t.q&&void 0!==t.g&&void 0!==t.y&&void 0!==t.x)return(g=new KJUR.crypto.DSA).setPrivate(t.p,t.q,t.g,t.y,t.x),g;if("RSA"===t.kty&&void 0!==t.n&&void 0!==t.e&&void 0===t.d)return(g=new RSAKey).setPublic(b64utohex(t.n),b64utohex(t.e)),g;if("RSA"===t.kty&&void 0!==t.n&&void 0!==t.e&&void 0!==t.d&&void 0!==t.p&&void 0!==t.q&&void 0!==t.dp&&void 0!==t.dq&&void 0!==t.qi)return(g=new RSAKey).setPrivateEx(b64utohex(t.n),b64utohex(t.e),b64utohex(t.d),b64utohex(t.p),b64utohex(t.q),b64utohex(t.dp),b64utohex(t.dq),b64utohex(t.qi)),g;if("RSA"===t.kty&&void 0!==t.n&&void 0!==t.e&&void 0!==t.d)return(g=new RSAKey).setPrivate(b64utohex(t.n),b64utohex(t.e),b64utohex(t.d)),g;if("EC"===t.kty&&void 0!==t.crv&&void 0!==t.x&&void 0!==t.y&&void 0===t.d){var n=(f=new KJUR.crypto.ECDSA({curve:t.crv})).ecparams.keylen/4,i="04"+("0000000000"+b64utohex(t.x)).slice(-n)+("0000000000"+b64utohex(t.y)).slice(-n);return f.setPublicKeyHex(i),f}if("EC"===t.kty&&void 0!==t.crv&&void 0!==t.x&&void 0!==t.y&&void 0!==t.d){n=(f=new KJUR.crypto.ECDSA({curve:t.crv})).ecparams.keylen/4,i="04"+("0000000000"+b64utohex(t.x)).slice(-n)+("0000000000"+b64utohex(t.y)).slice(-n);var s=("0000000000"+b64utohex(t.d)).slice(-n);return f.setPublicKeyHex(i),f.setPrivateKeyHex(s),f}if(-1!=t.indexOf("-END CERTIFICATE-",0)||-1!=t.indexOf("-END X509 CERTIFICATE-",0)||-1!=t.indexOf("-END TRUSTED CERTIFICATE-",0))return X509.getPublicKeyFromCertPEM(t);if("pkcs8pub"===r)return KEYUTIL.getKeyFromPublicPKCS8Hex(t);if(-1!=t.indexOf("-END PUBLIC KEY-"))return KEYUTIL.getKeyFromPublicPKCS8PEM(t);if("pkcs5prv"===r)return(g=new RSAKey).readPrivateKeyFromASN1HexString(t),g;if("pkcs5prv"===r)return(g=new RSAKey).readPrivateKeyFromASN1HexString(t),g;if(-1!=t.indexOf("-END RSA PRIVATE KEY-")&&-1==t.indexOf("4,ENCRYPTED")){var o=KEYUTIL.getHexFromPEM(t,"RSA PRIVATE KEY");return KEYUTIL.getKey(o,null,"pkcs5prv")}if(-1!=t.indexOf("-END DSA PRIVATE KEY-")&&-1==t.indexOf("4,ENCRYPTED")){var a=this.getHexFromPEM(t,"DSA PRIVATE KEY"),h=ASN1HEX.getVbyList(a,0,[1],"02"),u=ASN1HEX.getVbyList(a,0,[2],"02"),p=ASN1HEX.getVbyList(a,0,[3],"02"),c=ASN1HEX.getVbyList(a,0,[4],"02"),l=ASN1HEX.getVbyList(a,0,[5],"02");return(g=new KJUR.crypto.DSA).setPrivate(new BigInteger(h,16),new BigInteger(u,16),new BigInteger(p,16),new BigInteger(c,16),new BigInteger(l,16)),g}if(-1!=t.indexOf("-END PRIVATE KEY-"))return KEYUTIL.getKeyFromPlainPrivatePKCS8PEM(t);if(-1!=t.indexOf("-END RSA PRIVATE KEY-")&&-1!=t.indexOf("4,ENCRYPTED"))return KEYUTIL.getRSAKeyFromEncryptedPKCS5PEM(t,e);if(-1!=t.indexOf("-END EC PRIVATE KEY-")&&-1!=t.indexOf("4,ENCRYPTED")){a=KEYUTIL.getDecryptedKeyHex(t,e);var f,g=ASN1HEX.getVbyList(a,0,[1],"04"),d=ASN1HEX.getVbyList(a,0,[2,0],"06"),y=ASN1HEX.getVbyList(a,0,[3,0],"03").substr(2),S="";if(void 0===KJUR.crypto.OID.oidhex2name[d])throw"undefined OID(hex) in KJUR.crypto.OID: "+d;return S=KJUR.crypto.OID.oidhex2name[d],(f=new KJUR.crypto.ECDSA({name:S})).setPublicKeyHex(y),f.setPrivateKeyHex(g),f.isPublic=!1,f}if(-1!=t.indexOf("-END DSA PRIVATE KEY-")&&-1!=t.indexOf("4,ENCRYPTED")){a=KEYUTIL.getDecryptedKeyHex(t,e),h=ASN1HEX.getVbyList(a,0,[1],"02"),u=ASN1HEX.getVbyList(a,0,[2],"02"),p=ASN1HEX.getVbyList(a,0,[3],"02"),c=ASN1HEX.getVbyList(a,0,[4],"02"),l=ASN1HEX.getVbyList(a,0,[5],"02");return(g=new KJUR.crypto.DSA).setPrivate(new BigInteger(h,16),new BigInteger(u,16),new BigInteger(p,16),new BigInteger(c,16),new BigInteger(l,16)),g}if(-1!=t.indexOf("-END ENCRYPTED PRIVATE KEY-"))return KEYUTIL.getKeyFromEncryptedPKCS8PEM(t,e);throw"not supported argument"},KEYUTIL.generateKeypair=function(t,e){if("RSA"==t){var r=e;(o=new RSAKey).generate(r,"10001"),o.isPrivate=!0,o.isPublic=!0;var n=new RSAKey,i=o.n.toString(16),s=o.e.toString(16);return n.setPublic(i,s),n.isPrivate=!1,n.isPublic=!0,(a={}).prvKeyObj=o,a.pubKeyObj=n,a}if("EC"!=t)throw"unknown algorithm: "+t;var o,a,h=e,u=new KJUR.crypto.ECDSA({curve:h}).generateKeyPairHex();return(o=new KJUR.crypto.ECDSA({curve:h})).setPublicKeyHex(u.ecpubhex),o.setPrivateKeyHex(u.ecprvhex),o.isPrivate=!0,o.isPublic=!1,(n=new KJUR.crypto.ECDSA({curve:h})).setPublicKeyHex(u.ecpubhex),n.isPrivate=!1,n.isPublic=!0,(a={}).prvKeyObj=o,a.pubKeyObj=n,a},KEYUTIL.getPEM=function(t,e,r,n,i){var s=KJUR.asn1,o=KJUR.crypto;function a(t){return KJUR.asn1.ASN1Util.newObject({seq:[{int:0},{int:{bigint:t.n}},{int:t.e},{int:{bigint:t.d}},{int:{bigint:t.p}},{int:{bigint:t.q}},{int:{bigint:t.dmp1}},{int:{bigint:t.dmq1}},{int:{bigint:t.coeff}}]})}function h(t){return KJUR.asn1.ASN1Util.newObject({seq:[{int:1},{octstr:{hex:t.prvKeyHex}},{tag:["a0",!0,{oid:{name:t.curveName}}]},{tag:["a1",!0,{bitstr:{hex:"00"+t.pubKeyHex}}]}]})}function u(t){return KJUR.asn1.ASN1Util.newObject({seq:[{int:0},{int:{bigint:t.p}},{int:{bigint:t.q}},{int:{bigint:t.g}},{int:{bigint:t.y}},{int:{bigint:t.x}}]})}if((void 0!==RSAKey&&t instanceof RSAKey||void 0!==o.DSA&&t instanceof o.DSA||void 0!==o.ECDSA&&t instanceof o.ECDSA)&&1==t.isPublic&&(void 0===e||"PKCS8PUB"==e)){var p=new KJUR.asn1.x509.SubjectPublicKeyInfo(t).getEncodedHex();return s.ASN1Util.getPEMStringFromHex(p,"PUBLIC KEY")}if("PKCS1PRV"==e&&void 0!==RSAKey&&t instanceof RSAKey&&(void 0===r||null==r)&&1==t.isPrivate){p=a(t).getEncodedHex();return s.ASN1Util.getPEMStringFromHex(p,"RSA PRIVATE KEY")}if("PKCS1PRV"==e&&void 0!==RSAKey&&t instanceof KJUR.crypto.ECDSA&&(void 0===r||null==r)&&1==t.isPrivate){var c=new KJUR.asn1.DERObjectIdentifier({name:t.curveName}).getEncodedHex(),l=h(t).getEncodedHex(),f="";return f+=s.ASN1Util.getPEMStringFromHex(c,"EC PARAMETERS"),f+=s.ASN1Util.getPEMStringFromHex(l,"EC PRIVATE KEY")}if("PKCS1PRV"==e&&void 0!==KJUR.crypto.DSA&&t instanceof KJUR.crypto.DSA&&(void 0===r||null==r)&&1==t.isPrivate){p=u(t).getEncodedHex();return s.ASN1Util.getPEMStringFromHex(p,"DSA PRIVATE KEY")}if("PKCS5PRV"==e&&void 0!==RSAKey&&t instanceof RSAKey&&void 0!==r&&null!=r&&1==t.isPrivate){p=a(t).getEncodedHex();return void 0===n&&(n="DES-EDE3-CBC"),this.getEncryptedPKCS5PEMFromPrvKeyHex("RSA",p,r,n)}if("PKCS5PRV"==e&&void 0!==KJUR.crypto.ECDSA&&t instanceof KJUR.crypto.ECDSA&&void 0!==r&&null!=r&&1==t.isPrivate){p=h(t).getEncodedHex();return void 0===n&&(n="DES-EDE3-CBC"),this.getEncryptedPKCS5PEMFromPrvKeyHex("EC",p,r,n)}if("PKCS5PRV"==e&&void 0!==KJUR.crypto.DSA&&t instanceof KJUR.crypto.DSA&&void 0!==r&&null!=r&&1==t.isPrivate){p=u(t).getEncodedHex();return void 0===n&&(n="DES-EDE3-CBC"),this.getEncryptedPKCS5PEMFromPrvKeyHex("DSA",p,r,n)}var g=function(t,e){var r=d(t,e);return new KJUR.asn1.ASN1Util.newObject({seq:[{seq:[{oid:{name:"pkcs5PBES2"}},{seq:[{seq:[{oid:{name:"pkcs5PBKDF2"}},{seq:[{octstr:{hex:r.pbkdf2Salt}},{int:r.pbkdf2Iter}]}]},{seq:[{oid:{name:"des-EDE3-CBC"}},{octstr:{hex:r.encryptionSchemeIV}}]}]}]},{octstr:{hex:r.ciphertext}}]}).getEncodedHex()},d=function(t,e){var r=CryptoJS.lib.WordArray.random(8),n=CryptoJS.lib.WordArray.random(8),i=CryptoJS.PBKDF2(e,r,{keySize:6,iterations:100}),s=CryptoJS.enc.Hex.parse(t),o=CryptoJS.TripleDES.encrypt(s,i,{iv:n})+"",a={};return a.ciphertext=o,a.pbkdf2Salt=CryptoJS.enc.Hex.stringify(r),a.pbkdf2Iter=100,a.encryptionSchemeAlg="DES-EDE3-CBC",a.encryptionSchemeIV=CryptoJS.enc.Hex.stringify(n),a};if("PKCS8PRV"==e&&void 0!==RSAKey&&t instanceof RSAKey&&1==t.isPrivate){var y=a(t).getEncodedHex();p=KJUR.asn1.ASN1Util.newObject({seq:[{int:0},{seq:[{oid:{name:"rsaEncryption"}},{null:!0}]},{octstr:{hex:y}}]}).getEncodedHex();if(void 0===r||null==r)return s.ASN1Util.getPEMStringFromHex(p,"PRIVATE KEY");l=g(p,r);return s.ASN1Util.getPEMStringFromHex(l,"ENCRYPTED PRIVATE KEY")}if("PKCS8PRV"==e&&void 0!==KJUR.crypto.ECDSA&&t instanceof KJUR.crypto.ECDSA&&1==t.isPrivate){y=new KJUR.asn1.ASN1Util.newObject({seq:[{int:1},{octstr:{hex:t.prvKeyHex}},{tag:["a1",!0,{bitstr:{hex:"00"+t.pubKeyHex}}]}]}).getEncodedHex(),p=KJUR.asn1.ASN1Util.newObject({seq:[{int:0},{seq:[{oid:{name:"ecPublicKey"}},{oid:{name:t.curveName}}]},{octstr:{hex:y}}]}).getEncodedHex();if(void 0===r||null==r)return s.ASN1Util.getPEMStringFromHex(p,"PRIVATE KEY");l=g(p,r);return s.ASN1Util.getPEMStringFromHex(l,"ENCRYPTED PRIVATE KEY")}if("PKCS8PRV"==e&&void 0!==KJUR.crypto.DSA&&t instanceof KJUR.crypto.DSA&&1==t.isPrivate){y=new KJUR.asn1.DERInteger({bigint:t.x}).getEncodedHex(),p=KJUR.asn1.ASN1Util.newObject({seq:[{int:0},{seq:[{oid:{name:"dsa"}},{seq:[{int:{bigint:t.p}},{int:{bigint:t.q}},{int:{bigint:t.g}}]}]},{octstr:{hex:y}}]}).getEncodedHex();if(void 0===r||null==r)return s.ASN1Util.getPEMStringFromHex(p,"PRIVATE KEY");l=g(p,r);return s.ASN1Util.getPEMStringFromHex(l,"ENCRYPTED PRIVATE KEY")}throw"unsupported object nor format"},KEYUTIL.getKeyFromCSRPEM=function(t){var e=KEYUTIL.getHexFromPEM(t,"CERTIFICATE REQUEST");return KEYUTIL.getKeyFromCSRHex(e)},KEYUTIL.getKeyFromCSRHex=function(t){var e=KEYUTIL.parseCSRHex(t);return KEYUTIL.getKey(e.p8pubkeyhex,null,"pkcs8pub")},KEYUTIL.parseCSRHex=function(t){var e={},r=t;if("30"!=r.substr(0,2))throw"malformed CSR(code:001)";var n=ASN1HEX.getPosArrayOfChildren_AtObj(r,0);if(n.length<1)throw"malformed CSR(code:002)";if("30"!=r.substr(n[0],2))throw"malformed CSR(code:003)";var i=ASN1HEX.getPosArrayOfChildren_AtObj(r,n[0]);if(i.length<3)throw"malformed CSR(code:004)";return e.p8pubkeyhex=ASN1HEX.getHexOfTLV_AtObj(r,i[2]),e},KEYUTIL.getJWKFromKey=function(t){var e={};if(t instanceof RSAKey&&t.isPrivate)return e.kty="RSA",e.n=hextob64u(t.n.toString(16)),e.e=hextob64u(t.e.toString(16)),e.d=hextob64u(t.d.toString(16)),e.p=hextob64u(t.p.toString(16)),e.q=hextob64u(t.q.toString(16)),e.dp=hextob64u(t.dmp1.toString(16)),e.dq=hextob64u(t.dmq1.toString(16)),e.qi=hextob64u(t.coeff.toString(16)),e;if(t instanceof RSAKey&&t.isPublic)return e.kty="RSA",e.n=hextob64u(t.n.toString(16)),e.e=hextob64u(t.e.toString(16)),e;if(t instanceof KJUR.crypto.ECDSA&&t.isPrivate){if("P-256"!==(n=t.getShortNISTPCurveName())&&"P-384"!==n)throw"unsupported curve name for JWT: "+n;var r=t.getPublicKeyXYHex();return e.kty="EC",e.crv=n,e.x=hextob64u(r.x),e.y=hextob64u(r.y),e.d=hextob64u(t.prvKeyHex),e}if(t instanceof KJUR.crypto.ECDSA&&t.isPublic){var n;if("P-256"!==(n=t.getShortNISTPCurveName())&&"P-384"!==n)throw"unsupported curve name for JWT: "+n;r=t.getPublicKeyXYHex();return e.kty="EC",e.crv=n,e.x=hextob64u(r.x),e.y=hextob64u(r.y),e}throw"not supported key object"};
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
      console.log(settings);
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
      updateConfigs: function(newConf) {
        if (newConf == null) {
          newConf = {};
        }
        if (newConf.extraparam !== void 0) {
          if (newConf.extraparam) {
            settings.extraparam = newConf.extraparam;
          } else {
            delete settings.extraparam;
          }
        }
        if (newConf.redirect_uri) {
          settings.redirect_uri = newConf.redirect_uri;
        }
        return void 0;
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


//# sourceMappingURL=an_sso-export.js.map