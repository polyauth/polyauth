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

window.PolyAuth = {};

(function(scope) {

	'use strict';

	const POLYAUTH_ORIGIN = 'polyauth.herokuapp.com';
	const POLYAUTH_ORIGIN_URI = `https://${POLYAUTH_ORIGIN}`;
	const POLYAUTH_API_VERSION = 'v1';
	const KEYS =
		[	'oauth2.google-plus',
			'oauth2.facebook',
			'oauth2.vk',
			'oauth2.ok' ];
	
	scope.api =
		function(token, v) {
			v = v || POLYAUTH_API_VERSION;
			return {
				user:
					(id) => id ?
						({
							get: (options) => makeUserGetRequest(token, v, id, options),
							remove: () => makeUserRemoveRequest(token, v, id),
							reset: () => makeUserResetRequest(token, v, id),
							auth: (authId) => authId ?
								({
									remove: () => makeUserAuthRemoveRequest(token, v, id, authId)
								}) :
								({
									list: () => makeUserAuthListRequest(token, v, id)
								})
						}) :
						({
							list: (options) => makeUserListRequest(token, v, options)
						}),
				profile:
					(id) =>
						({
							get: () => makeProfileGetRequest(token, v, id),
							update: (options) => makeProfileUpdateRequest(token, v, id, options)
						}),
				realm:
					(id) => id ?
						({
							get: (options) => makeRealmGetRequest(token, v, id, options),
							update: (options) => makeRealmUpdateRequest(token, v, id, options),
							remove: () => makeRealmRemoveRequest(token, v, id),
							reset: () => makeRealmResetRequest(token, v, id),
							auth: (key) => ({
								accessToken: (options) => makeAuthTokenRequest(token, v, id, key)
							})
						}) :
						({
							list: (options) => makeRealmListRequest(token, v, options),
							create: (options) => makeRealmCreateRequest(token, v, options)
						})
			};
		};

	{
		let signAcc = {};

		scope.authCodeURI =
			function(realmId, options) {
				if (!realmId || !options || !options.key || !options.redirectURI) { throw new TypeError('badarg'); }

				options = options || {};
				let v = options.apiv || POLYAUTH_API_VERSION;
				let op = options.op || 'm/token';
				let ns = op[0];
				let state = ('state' in options) ? options.state : makeState();

				let opt = {};
				if (state) {
					storeState({value: state, op: op});
					opt.state = state;
				}

				return makeAuthCodeURI(v, realmId, ns, options.key, options.redirectURI, opt);
			};

		scope.signIn =
			function(realmId, options) {
				if (!realmId) { throw new TypeError('badarg'); }

				options = options || {};
				let v = options.apiv || POLYAUTH_API_VERSION;
				let sign = signAcc[realmId];
				return sign ? sign : signAcc[realmId] = authenticate(v, realmId, options);
			};

		scope.signOut =
			function(realmId) {
				if (!realmId) { throw new TypeError('badarg'); }

				delete signAcc[realmId];
				return removeSign(realmId);
			};
	}

	scope.fetch = fetchJSON;

	scope.Key = {
		all: () => KEYS,
		key: key,
		parse: parseKey
	};

	scope.State = {
		make: makeState
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
		if (!v || !options.qRealmId || !token) { throw new TypeError('badarg'); }
		options = options || {};

		let params = {};
		if (options.qRealmId) { params.q = `realm_id:${options.qRealmId}`; }
		if (options.fields) { params.fl = options.fields.join(','); }
		if (options.start) { params.start = options.start; }
		if (options.rows) { params.rows = options.rows; }

		let uri = makeURI(`${POLYAUTH_ORIGIN_URI}/api/${v}/users`, params);
		let opt = {
			method: 'GET',
			headers: addAuthrorizationHeader(token)
		};
		return new Request(uri, opt);
	}

	function makeUserGetRequest(token, v, id, options) {
		if (!v || !id) { throw new TypeError('badarg'); }
		options = options || {};

		let params = {};
		if (options.fields) { params.fl = options.fields.join(','); }

		let uri = makeURI(`${POLYAUTH_ORIGIN_URI}/api/${v}/users/${id}`, params);
		let opt = {
			method: 'GET',
			headers: addAuthrorizationHeader(token)
		};
		return new Request(uri, opt);
	}

	function makeUserRemoveRequest(token, v, id) {
		if (!v || !id || !token) { throw new TypeError('badarg'); }

		let uri = `${POLYAUTH_ORIGIN_URI}/api/${v}/users/${id}`;
		let opt = {
			method: 'DELETE',
			headers: addAuthrorizationHeader(token)
		};
		return new Request(uri, opt);
	}

	function makeUserResetRequest(token, v, id) {
		if (!v || !id || !token) { throw new TypeError('badarg'); }

		let uri = `${POLYAUTH_ORIGIN_URI}/api/${v}/users/${id}/reset`;
		let opt = {
			method: 'POST',
			headers: addAuthrorizationHeader(token)
		};
		return new Request(uri, opt);
	}

	function makeUserAuthListRequest(token, v, id) {
		if (!v || !id || !token) { throw new TypeError('badarg'); }

		let uri = `${POLYAUTH_ORIGIN_URI}/api/${v}/users/${id}/auth`;
		let opt = {
			method: 'GET',
			headers: addAuthrorizationHeader(token)
		};
		return new Request(uri, opt);
	}

	function makeUserAuthRemoveRequest(token, v, id, authId) {
		if (!v || !id || !authId || !token) { throw new TypeError('badarg'); }

		let uri = `${POLYAUTH_ORIGIN_URI}/api/${v}/users/${id}/auth/${authId}`;
		let opt = {
			method: 'DELETE',
			headers: addAuthrorizationHeader(token)
		};
		return new Request(uri, opt);
	}

	function makeProfileGetRequest(token, v, id) {
		if (!v || !id) { throw new TypeError('badarg'); }

		let uri = `${POLYAUTH_ORIGIN_URI}/api/${v}/profiles/${id}`;
		let opt = {
			method: 'GET',
			headers: addAuthrorizationHeader(token)
		};
		return new Request(uri, opt);
	}

	function makeProfileUpdateRequest(token, v, id, options) {
		if (!v || !id || !options || !options.data || !token) { throw new TypeError('badarg'); }

		let uri = `${POLYAUTH_ORIGIN_URI}/api/${v}/profiles/${id}`;
		let opt = {
			method: 'PUT',
			headers: addAuthrorizationHeader(token, {'Content-Type': 'application/json'}),
			body: JSON.stringify(options.data)
		};
		return new Request(uri, opt);
	}

	function makeRealmListRequest(token, v, options) {
		if (!v || !token) { throw new TypeError('badarg'); }
		options = options || {};

		let params = {};
		if (options.start) { params.start = options.start; }
		if (options.rows) { params.rows = options.rows; }
		if (options.fields) { params.fl = options.fields.join(','); }

		let uri = makeURI(`${POLYAUTH_ORIGIN_URI}/api/${v}/realms`, params);
		let opt = {
			method: 'GET',
			headers: addAuthrorizationHeader(token)
		};
		return new Request(uri, opt);
	}

	function makeRealmCreateRequest(token, v, options) {
		if (!v || !options || !options.data || !token) { throw new TypeError('badarg'); }

		let uri = `${POLYAUTH_ORIGIN_URI}/api/${v}/realms`;
		let opt = {
			method: 'POST',
			headers: addAuthrorizationHeader(token, {'Content-Type': 'application/json'}),
			body: JSON.stringify(options.data)
		};
		return new Request(uri, opt);
	}

	function makeRealmGetRequest(token, v, id, options) {
		if (!v || !id) { throw new TypeError('badarg'); }

		let params = {};
		if (options.fields) { params.fl = options.fields.join(','); }

		let uri = makeURI(`${POLYAUTH_ORIGIN_URI}/api/${v}/realms/${id}`, params);
		let opt = {
			method: 'GET',
			headers: addAuthrorizationHeader(token)
		};
		return new Request(uri, opt);
	}

	function makeRealmUpdateRequest(token, v, id, options) {
		if (!v || !id || !options || !options.data || !token) { throw new TypeError('badarg'); }

		let uri = `${POLYAUTH_ORIGIN_URI}/api/${v}/realms/${id}`;
		let opt = {
			method: 'PUT',
			headers: addAuthrorizationHeader(token, {'Content-Type': 'application/json'}),
			body: JSON.stringify(options.data)
		};
		return new Request(uri, opt);
	}

	function makeRealmRemoveRequest(token, v, id) {
		if (!v || !id || !token) { throw new TypeError('badarg'); }

		let uri = `${POLYAUTH_ORIGIN_URI}/api/${v}/realms/${id}`;
		let opt = {
			method: 'DELETE',
			headers: addAuthrorizationHeader(token)
		};
		return new Request(uri, opt);
	}

	function makeRealmResetRequest(token, v, id) {
		if (!v || !id || !token) { throw new TypeError('badarg'); }

		let uri = `${POLYAUTH_ORIGIN_URI}/api/${v}/realms/${id}/reset`;
		let opt = {
			method: 'POST',
			headers: addAuthrorizationHeader(token)
		};
		return new Request(uri, opt);
	}

	function makeAuthTokenRequest(v, realmId, key, {code}) {
		if (!v || !realmId || !key || !code) { throw new TypeError('badarg'); }

		let uri = `${POLYAUTH_ORIGIN_URI}/api/${v}/realms/${realmId}/auth/${key}/m/token`;
		let opt = {
			method: 'POST',
			headers: {'Content-Type': 'application/json'},
			body: JSON.stringify({code: code})
		};
		return new Request(uri, opt);
	}

	function makeAuthLinkRequest(token, v, realmId, key, {code}) {
		if (!v || !realmId || !key || !code || !token) { throw new TypeError('badarg'); }

		let uri = `${POLYAUTH_ORIGIN_URI}/api/${v}/realms/${realmId}/auth/${key}/m/link`;
		let opt = {
			method: 'POST',
			headers: addAuthrorizationHeader(token, {'Content-Type': 'application/json'}),
			body: JSON.stringify({code: code})
		};
		return new Request(uri, opt);
	}

	function makeAuthCodeURI(v, realmId, ns, key, redirectURI, options) {
		if (!v || !realmId || !ns || !key || !redirectURI) { throw new TypeError('badarg'); }

		let params = {};
		params.redirect_uri = redirectURI;
		if (options.state) { params.state = options.state; }

		return makeURI(`${POLYAUTH_ORIGIN_URI}/api/${v}/realms/${realmId}/auth/${key}/${ns}/code`, params);
	}

	function makeURI(base, params) {
		let q = qs(params);
		return (q ? base + '?' + q : base);
	}

	function qs(params) {
		let fn = (key) => `${encodeURIComponent(key)}=${encodeURIComponent(params[key])}`;
		return Object.keys(params).map(fn).join('&');
	}

	function parseQS() {
		return window.location.search.substr(1).split('&').reduce(function(acc, el) {
			let [key, val] = el.split('=').map(decodeURIComponent);
			acc[key] = val ? val : true;
			return acc;
		}, {});
	}

	function key(val) {
		switch (val.prot) {

			case 'oauth2':
				if (!val.prov) { throw new TypeError('badarg'); }
				return (val.prot + '.' + val.prov);

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
		return fetch(req)
			.then(respSuccess)
			.then(respJSON);
	}

	function respSuccess(resp) {
		return new Promise(function(resolve, reject) {
			if (resp.status && (resp.status < 200 || resp.status >= 300)) {
				reject({status: resp.status});
			}
			else if (resp.ok === false) {
				reject({network: 'bad'});
			}
			else {
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
			headers.authorization = `Bearer ${token}`;
			return headers;
		}

		return headers;
	}

	function authenticate(v, realmId, options) {
		return new Promise(function(resolve, reject) {

			options = options || {};
			let redirect = (options.redirect === false) ? false : true;
			let verifyState = (options.verifyState === false) ? false : true;
			let sign = loadSign(realmId);
			let data = options.data || parseQS();
			let op = options.op || 'm/token';
			let opInitialized = options.op ? true : false;

			let done = (s, err) => s ? resolve(s) : reject(err);
			let maybeRedirect =
				function(res) {
					if (redirect) {
						flushQS();
					}
					return resolve(res);
				};

			let {error, key, code, state} = data;
			if (!key && !code) {
				return done(sign, {accessToken: 'required'});
			}

			if (verifyState) {
				if (!state) {
					return done(sign, {state: 'required'});
				}

				var storedState = takeState(state);
				if (!storedState) {
					return done(sign, {state: 'bad'});
				}

				if (!opInitialized) {
					op = storedState.op;
				}
			}

			if (error) {
				return reject({error: error});
			}

			let reqOptions = {code: code};
			switch (op) {

				case 'm/token':
					return fetchJSON(makeAuthTokenRequest(v, realmId, key, reqOptions))
						.then(function({access_token}) {
							var sign = {accessToken: access_token};
							return resolve(storeSign(realmId, sign));
						})
						.then(maybeRedirect);

				case 'm/link':
					return (!sign || !sign.accessToken) ?
						reject({accessToken: 'required'}) :
						fetchJSON(makeAuthLinkRequest(sign.accessToken, v, realmId, key, reqOptions))
							.then(function() {
								return resolve(sign);
							})
							.then(maybeRedirect);

				default:
					return reject({op: 'bad'});

			}

		});
	}

	function loadSign(realmId) {
		let key = `polyauth-sign.${realmId}`;
		let val = localStorage.getItem(key);
		return val ? JSON.parse(val) : null;
	}

	function storeSign(realmId, val) {
		let key = `polyauth-sign.${realmId}`;
		localStorage.setItem(key, JSON.stringify(val));
		return val;
	}

	function removeSign(realmId) {
		let key = `polyauth-sign.${realmId}`;
		localStorage.removeItem(key);
		return null;
	}

	function loadStateArray() {
		let key = 'polyauth-state';
		let arr = sessionStorage.getItem(key);
		return arr ? JSON.parse(arr) : [];
	}

	function storeStateArray(arr) {
		let key = 'polyauth-state';
		sessionStorage.setItem(key, JSON.stringify(arr));
		return arr;
	}

	function takeState(val) {
		let arr = loadStateArray();
		if (!arr.length) {
			return null;
		}

		let {res, rest} =
			arr.reduceRight(function(acc, state) {
				switch (state.value) {
					case val:
						acc.res = state;
						break;
					default:
						acc.rest.push(state);
				}

				return acc;
			}, {res: null, rest: []});


		storeStateArray(rest);
		return res;
	}

	function storeState(state) {
		let arr = loadStateArray();
		arr.push(state);
		storeStateArray(arr);
		return state;
	}

	function makeState() {
		return makeHex(64);
	}

	function arrToHex(arr) {
		let acc = '';
		for(let i = 0; i < arr.length; ++i) {
			acc = acc + numToHex(arr[i]);
		}

		return acc;
	}

	function numToHex(num) {
		let hex = num.toString(16);
		return hex.length === 2 ? hex : '0' + hex;
	}

	function makeHex(len) {
		return arrToHex(makeRandomArray(len));
	}

	function makeRandomArray(len) {
		let crypto = window.crypto || window.msCrypto;
		if (crypto) {
			let arr = new Uint8Array(len);
			crypto.getRandomValues(arr);
			return arr;
		}
		
		return Array.apply(null, new Array(len)).map(() => Math.floor(Math.random() * 256));
	}

})(window.PolyAuth);
