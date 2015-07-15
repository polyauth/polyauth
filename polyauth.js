/*
@license
The MIT License

Copyright (c) 2015 Andrei Nesterov <ae.nesterov@polyauth.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to
deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
sell copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
IN THE SOFTWARE.
*/

'use strict';

function _slicedToArray(arr, i) { if (Array.isArray(arr)) { return arr; } else if (Symbol.iterator in Object(arr)) { var _arr = []; var _n = true; var _d = false; var _e = undefined; try { for (var _i = arr[Symbol.iterator](), _s; !(_n = (_s = _i.next()).done); _n = true) { _arr.push(_s.value); if (i && _arr.length === i) break; } } catch (err) { _d = true; _e = err; } finally { try { if (!_n && _i['return']) _i['return'](); } finally { if (_d) throw _e; } } return _arr; } else { throw new TypeError('Invalid attempt to destructure non-iterable instance'); } }

window.PolyAuth = {};

(function (scope) {

	'use strict';

	var POLYAUTH_ORIGIN = 'polyauth.herokuapp.com';
	var POLYAUTH_ORIGIN_URI = 'https://' + POLYAUTH_ORIGIN;
	var POLYAUTH_API_VERSION = 'v1';
	var KEYS = ['oauth2.google-plus', 'oauth2.facebook', 'oauth2.vk', 'oauth2.ok'];

	scope.api = function (token, v) {
		v = v || POLYAUTH_API_VERSION;
		return {
			user: function user(id) {
				return id ? {
					get: function get(options) {
						return makeUserGetRequest(token, v, id, options);
					},
					remove: function remove() {
						return makeUserRemoveRequest(token, v, id);
					},
					reset: function reset() {
						return makeUserResetRequest(token, v, id);
					},
					auth: function auth(authId) {
						return authId ? {
							remove: function remove() {
								return makeUserAuthRemoveRequest(token, v, id, authId);
							}
						} : {
							list: function list() {
								return makeUserAuthListRequest(token, v, id);
							}
						};
					}
				} : {
					list: function list(options) {
						return makeUserListRequest(token, v, options);
					}
				};
			},
			profile: function profile(id) {
				return {
					get: function get() {
						return makeProfileGetRequest(token, v, id);
					},
					update: function update(options) {
						return makeProfileUpdateRequest(token, v, id, options);
					}
				};
			},
			realm: function realm(id) {
				return id ? {
					get: function get(options) {
						return makeRealmGetRequest(token, v, id, options);
					},
					update: function update(options) {
						return makeRealmUpdateRequest(token, v, id, options);
					},
					remove: function remove() {
						return makeRealmRemoveRequest(token, v, id);
					},
					reset: function reset() {
						return makeRealmResetRequest(token, v, id);
					},
					auth: function auth(key) {
						return {
							accessToken: function accessToken(options) {
								return makeAuthTokenRequest(v, id, key, options);
							},
							standaloneToken: function standaloneToken(options) {
								return makeAuthStandaloneTokenRequest(v, id, key, options);
							},
							standaloneProfile: function standaloneProfile(options) {
								return makeAuthStandaloneProfileRequest(v, id, key, options);
							}
						};
					}
				} : {
					list: function list(options) {
						return makeRealmListRequest(token, v, options);
					},
					create: function create(options) {
						return makeRealmCreateRequest(token, v, options);
					}
				};
			}
		};
	};

	{
		(function () {
			var signAcc = {};

			scope.authCodeURI = function (realmId, options) {
				if (!realmId || !options || !options.key || !options.redirectURI) {
					throw new TypeError('badarg');
				}

				options = options || {};
				var v = options.apiv || POLYAUTH_API_VERSION;
				var op = options.op || 'm/token';
				var ns = op[0];
				var state = 'state' in options ? options.state : makeState();

				var opt = {};
				if (state) {
					storeState({ value: state, op: op });
					opt.state = state;
				}

				return makeAuthCodeURI(v, realmId, ns, options.key, options.redirectURI, opt);
			};

			scope.signIn = function (realmId, options) {
				if (!realmId) {
					throw new TypeError('badarg');
				}

				options = options || {};
				var v = options.apiv || POLYAUTH_API_VERSION;
				var sign = signAcc[realmId];
				return sign ? sign : signAcc[realmId] = authenticate(v, realmId, options);
			};

			scope.signOut = function (realmId) {
				if (!realmId) {
					throw new TypeError('badarg');
				}

				delete signAcc[realmId];
				return removeSign(realmId);
			};
		})();
	}

	scope.fetch = fetchJSON;

	scope.Key = {
		all: function all() {
			return KEYS;
		},
		key: key,
		parse: parseKey
	};

	scope.State = {
		make: makeState,
		take: takeState
	};

	scope.QS = {
		parse: parseQS
	};

	scope.Hex = {
		make: makeHex
	};

	scope.Response = {
		success: respSuccess,
		json: respJSON,
		text: respText
	};

	function makeUserListRequest(token, v, options) {
		if (!v || !options.qRealmId || !token) {
			throw new TypeError('badarg');
		}
		options = options || {};

		var params = {};
		if (options.qRealmId) {
			params.q = 'realm_id:' + options.qRealmId;
		}
		if (options.fields) {
			params.fl = options.fields.join(',');
		}
		if (options.start) {
			params.start = options.start;
		}
		if (options.rows) {
			params.rows = options.rows;
		}

		var uri = makeURI('' + POLYAUTH_ORIGIN_URI + '/api/' + v + '/users', params);
		var opt = {
			method: 'GET',
			headers: addAuthrorizationHeader(token)
		};
		return new Request(uri, opt);
	}

	function makeUserGetRequest(token, v, id, options) {
		if (!v || !id) {
			throw new TypeError('badarg');
		}
		options = options || {};

		var params = {};
		if (options.fields) {
			params.fl = options.fields.join(',');
		}

		var uri = makeURI('' + POLYAUTH_ORIGIN_URI + '/api/' + v + '/users/' + id, params);
		var opt = {
			method: 'GET',
			headers: addAuthrorizationHeader(token)
		};
		return new Request(uri, opt);
	}

	function makeUserRemoveRequest(token, v, id) {
		if (!v || !id || !token) {
			throw new TypeError('badarg');
		}

		var uri = '' + POLYAUTH_ORIGIN_URI + '/api/' + v + '/users/' + id;
		var opt = {
			method: 'DELETE',
			headers: addAuthrorizationHeader(token)
		};
		return new Request(uri, opt);
	}

	function makeUserResetRequest(token, v, id) {
		if (!v || !id || !token) {
			throw new TypeError('badarg');
		}

		var uri = '' + POLYAUTH_ORIGIN_URI + '/api/' + v + '/users/' + id + '/reset';
		var opt = {
			method: 'POST',
			headers: addAuthrorizationHeader(token)
		};
		return new Request(uri, opt);
	}

	function makeUserAuthListRequest(token, v, id) {
		if (!v || !id || !token) {
			throw new TypeError('badarg');
		}

		var uri = '' + POLYAUTH_ORIGIN_URI + '/api/' + v + '/users/' + id + '/auth';
		var opt = {
			method: 'GET',
			headers: addAuthrorizationHeader(token)
		};
		return new Request(uri, opt);
	}

	function makeUserAuthRemoveRequest(token, v, id, authId) {
		if (!v || !id || !authId || !token) {
			throw new TypeError('badarg');
		}

		var uri = '' + POLYAUTH_ORIGIN_URI + '/api/' + v + '/users/' + id + '/auth/' + authId;
		var opt = {
			method: 'DELETE',
			headers: addAuthrorizationHeader(token)
		};
		return new Request(uri, opt);
	}

	function makeProfileGetRequest(token, v, id) {
		if (!v || !id) {
			throw new TypeError('badarg');
		}

		var uri = '' + POLYAUTH_ORIGIN_URI + '/api/' + v + '/profiles/' + id;
		var opt = {
			method: 'GET',
			headers: addAuthrorizationHeader(token)
		};
		return new Request(uri, opt);
	}

	function makeProfileUpdateRequest(token, v, id, options) {
		if (!v || !id || !options || !options.data || !token) {
			throw new TypeError('badarg');
		}

		var uri = '' + POLYAUTH_ORIGIN_URI + '/api/' + v + '/profiles/' + id;
		var opt = {
			method: 'PUT',
			headers: addAuthrorizationHeader(token, { 'Content-Type': 'application/json' }),
			body: JSON.stringify(options.data)
		};
		return new Request(uri, opt);
	}

	function makeRealmListRequest(token, v, options) {
		if (!v || !token) {
			throw new TypeError('badarg');
		}
		options = options || {};

		var params = {};
		if (options.start) {
			params.start = options.start;
		}
		if (options.rows) {
			params.rows = options.rows;
		}
		if (options.fields) {
			params.fl = options.fields.join(',');
		}

		var uri = makeURI('' + POLYAUTH_ORIGIN_URI + '/api/' + v + '/realms', params);
		var opt = {
			method: 'GET',
			headers: addAuthrorizationHeader(token)
		};
		return new Request(uri, opt);
	}

	function makeRealmCreateRequest(token, v, options) {
		if (!v || !options || !options.data || !token) {
			throw new TypeError('badarg');
		}

		var uri = '' + POLYAUTH_ORIGIN_URI + '/api/' + v + '/realms';
		var opt = {
			method: 'POST',
			headers: addAuthrorizationHeader(token, { 'Content-Type': 'application/json' }),
			body: JSON.stringify(options.data)
		};
		return new Request(uri, opt);
	}

	function makeRealmGetRequest(token, v, id, options) {
		if (!v || !id) {
			throw new TypeError('badarg');
		}

		var params = {};
		if (options.fields) {
			params.fl = options.fields.join(',');
		}

		var uri = makeURI('' + POLYAUTH_ORIGIN_URI + '/api/' + v + '/realms/' + id, params);
		var opt = {
			method: 'GET',
			headers: addAuthrorizationHeader(token)
		};
		return new Request(uri, opt);
	}

	function makeRealmUpdateRequest(token, v, id, options) {
		if (!v || !id || !options || !options.data || !token) {
			throw new TypeError('badarg');
		}

		var uri = '' + POLYAUTH_ORIGIN_URI + '/api/' + v + '/realms/' + id;
		var opt = {
			method: 'PUT',
			headers: addAuthrorizationHeader(token, { 'Content-Type': 'application/json' }),
			body: JSON.stringify(options.data)
		};
		return new Request(uri, opt);
	}

	function makeRealmRemoveRequest(token, v, id) {
		if (!v || !id || !token) {
			throw new TypeError('badarg');
		}

		var uri = '' + POLYAUTH_ORIGIN_URI + '/api/' + v + '/realms/' + id;
		var opt = {
			method: 'DELETE',
			headers: addAuthrorizationHeader(token)
		};
		return new Request(uri, opt);
	}

	function makeRealmResetRequest(token, v, id) {
		if (!v || !id || !token) {
			throw new TypeError('badarg');
		}

		var uri = '' + POLYAUTH_ORIGIN_URI + '/api/' + v + '/realms/' + id + '/reset';
		var opt = {
			method: 'POST',
			headers: addAuthrorizationHeader(token)
		};
		return new Request(uri, opt);
	}

	function makeAuthTokenRequest(v, realmId, key, _ref) {
		var code = _ref.code;

		if (!v || !realmId || !key || !code) {
			throw new TypeError('badarg');
		}

		var uri = '' + POLYAUTH_ORIGIN_URI + '/api/' + v + '/realms/' + realmId + '/auth/' + key + '/m/token';
		var opt = {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ code: code })
		};
		return new Request(uri, opt);
	}

	function makeAuthLinkRequest(token, v, realmId, key, _ref2) {
		var code = _ref2.code;

		if (!v || !realmId || !key || !code || !token) {
			throw new TypeError('badarg');
		}

		var uri = '' + POLYAUTH_ORIGIN_URI + '/api/' + v + '/realms/' + realmId + '/auth/' + key + '/m/link';
		var opt = {
			method: 'POST',
			headers: addAuthrorizationHeader(token, { 'Content-Type': 'application/json' }),
			body: JSON.stringify({ code: code })
		};
		return new Request(uri, opt);
	}

	function makeAuthStandaloneProfileRequest(v, realmId, key, _ref3) {
		var code = _ref3.code;

		if (!v || !realmId || !key || !code) {
			throw new TypeError('badarg');
		}

		var uri = '' + POLYAUTH_ORIGIN_URI + '/api/' + v + '/realms/' + realmId + '/auth/' + key + '/s/profile';
		var opt = {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ code: code })
		};
		return new Request(uri, opt);
	}

	function makeAuthStandaloneTokenRequest(v, realmId, key, _ref4) {
		var code = _ref4.code;
		var secret = _ref4.secret;

		if (!v || !realmId || !key || !code || !secret) {
			throw new TypeError('badarg');
		}

		var uri = '' + POLYAUTH_ORIGIN_URI + '/api/' + v + '/realms/' + realmId + '/auth/' + key + '/s/token';
		var opt = {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ code: code, client_secret: secret })
		};
		return new Request(uri, opt);
	}

	function makeAuthCodeURI(v, realmId, ns, key, redirectURI, options) {
		if (!v || !realmId || !ns || !key || !redirectURI) {
			throw new TypeError('badarg');
		}

		var params = {};
		params.redirect_uri = redirectURI;
		if (options.state) {
			params.state = options.state;
		}

		return makeURI('' + POLYAUTH_ORIGIN_URI + '/api/' + v + '/realms/' + realmId + '/auth/' + key + '/' + ns + '/code', params);
	}

	function makeURI(base, params) {
		var q = qs(params);
		return q ? base + '?' + q : base;
	}

	function qs(params) {
		var fn = function fn(key) {
			return '' + encodeURIComponent(key) + '=' + encodeURIComponent(params[key]);
		};
		return Object.keys(params).map(fn).join('&');
	}

	function parseQS() {
		return window.location.search.substr(1).split('&').reduce(function (acc, el) {
			var _el$split$map = el.split('=').map(decodeURIComponent);

			var _el$split$map2 = _slicedToArray(_el$split$map, 2);

			var key = _el$split$map2[0];
			var val = _el$split$map2[1];

			acc[key] = val ? val : true;
			return acc;
		}, {});
	}

	function key(val) {
		switch (val.prot) {

			case 'oauth2':
				if (!val.prov) {
					throw new TypeError('badarg');
				}
				return val.prot + '.' + val.prov;

			default:
				throw new TypeError('bad_key');

		}
	}

	function parseKey(key) {
		var p = key.split('.');
		switch (p[0]) {

			case 'oauth2':
				return {
					prot: p[0],
					prov: p[1]
				};

			default:
				throw new TypeError('bad_key');

		}
	}

	function flushQS() {
		window.location.href = window.location.origin + window.location.pathname;
	}

	function fetchJSON(req) {
		return fetch(req).then(respSuccess).then(respJSON);
	}

	function respSuccess(resp) {
		return new Promise(function (resolve, reject) {
			if (resp.status && (resp.status < 200 || resp.status >= 300)) {
				reject({ status: resp.status });
			} else if (resp.ok === false) {
				reject({ network: 'bad' });
			} else {
				resolve(resp);
			}
		});
	}

	function respText(resp) {
		return resp.text();
	}

	function respJSON(resp) {
		return resp.json();
	}

	function addAuthrorizationHeader(token, headers) {
		headers = headers || {};
		if (token) {
			headers.authorization = 'Bearer ' + token;
			return headers;
		}

		return headers;
	}

	function authenticate(v, realmId, options) {
		return new Promise(function (resolve, reject) {

			options = options || {};
			var redirect = options.redirect === false ? false : true;
			var verifyState = options.verifyState === false ? false : true;
			var sign = loadSign(realmId);
			var data = options.data || parseQS();
			var op = options.op || 'm/token';
			var opInitialized = options.op ? true : false;

			var done = function done(s, err) {
				return s ? resolve(s) : reject(err);
			};
			var maybeRedirect = function maybeRedirect(res) {
				if (redirect) {
					flushQS();
				}
				return resolve(res);
			};

			var error = data.error;
			var key = data.key;
			var code = data.code;
			var state = data.state;

			if (!key && !code) {
				return done(sign, { accessToken: 'required' });
			}

			if (verifyState) {
				if (!state) {
					return done(sign, { state: 'required' });
				}

				var storedState = takeState(state);
				if (!storedState) {
					return done(sign, { state: 'bad' });
				}

				if (!opInitialized) {
					op = storedState.op;
				}
			}

			if (error) {
				return reject({ error: error });
			}

			var reqOptions = { code: code };
			switch (op) {

				case 'm/token':
					return fetchJSON(makeAuthTokenRequest(v, realmId, key, reqOptions)).then(function (_ref5) {
						var access_token = _ref5.access_token;

						var sign = { accessToken: access_token };
						return resolve(storeSign(realmId, sign));
					}).then(maybeRedirect);

				case 'm/link':
					return !sign || !sign.accessToken ? reject({ accessToken: 'required' }) : fetchJSON(makeAuthLinkRequest(sign.accessToken, v, realmId, key, reqOptions)).then(function () {
						return resolve(sign);
					}).then(maybeRedirect);

				default:
					return reject({ op: 'bad' });

			}
		});
	}

	function loadSign(realmId) {
		var key = 'polyauth-sign.' + realmId;
		var val = localStorage.getItem(key);
		return val ? JSON.parse(val) : null;
	}

	function storeSign(realmId, val) {
		var key = 'polyauth-sign.' + realmId;
		localStorage.setItem(key, JSON.stringify(val));
		return val;
	}

	function removeSign(realmId) {
		var key = 'polyauth-sign.' + realmId;
		localStorage.removeItem(key);
		return null;
	}

	function loadStateArray() {
		var key = 'polyauth-state';
		var arr = sessionStorage.getItem(key);
		return arr ? JSON.parse(arr) : [];
	}

	function storeStateArray(arr) {
		var key = 'polyauth-state';
		sessionStorage.setItem(key, JSON.stringify(arr));
		return arr;
	}

	function takeState(val) {
		var arr = loadStateArray();
		if (!arr.length) {
			return null;
		}

		var _arr$reduceRight = arr.reduceRight(function (acc, state) {
			switch (state.value) {
				case val:
					acc.res = state;
					break;
				default:
					acc.rest.push(state);
			}

			return acc;
		}, { res: null, rest: [] });

		var res = _arr$reduceRight.res;
		var rest = _arr$reduceRight.rest;

		storeStateArray(rest);
		return res;
	}

	function storeState(state) {
		var arr = loadStateArray();
		arr.push(state);
		storeStateArray(arr);
		return state;
	}

	function makeState() {
		return makeHex(64);
	}

	function arrToHex(arr) {
		var acc = '';
		for (var i = 0; i < arr.length; ++i) {
			acc = acc + numToHex(arr[i]);
		}

		return acc;
	}

	function numToHex(num) {
		var hex = num.toString(16);
		return hex.length === 2 ? hex : '0' + hex;
	}

	function makeHex(len) {
		return arrToHex(makeRandomArray(len));
	}

	function makeRandomArray(len) {
		var crypto = window.crypto || window.msCrypto;
		if (crypto) {
			var arr = new Uint8Array(len);
			crypto.getRandomValues(arr);
			return arr;
		}

		return Array.apply(null, new Array(len)).map(function () {
			return Math.floor(Math.random() * 256);
		});
	}
})(window.PolyAuth);