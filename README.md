# [secureLink](https://github.com/totem-man/securelink)

**SecureLink** (built on [SocketIO](https://github.com/totem-man/socketio)) provides a secure link between clients 
through the use of PGP end-to-end encryption.  **SecureLink** also provides antibot technology to challenge clients, 
and a secure login mechanisim.  **SecureLink** establishes the following SocketIO protocol

	Function	Client					Channel 			Server
	==================================================================
	join			----------------- connect ---------------->
	request			----------------- join ------------------->
					<---- status || challenge || start	-------
	
	start			----------------- announce --------------->
	session			<---------------- accept* -----------------
	
	save			----------------- store ------------------>
	history			<---------------- status ------------------
	
	load			----------------- restore ---------------->
	history			<---------------- status ------------------
	
	login			----------------- login ------------------>
	request			<----- status, remove*, accept* -----------
					
	relay			----------------- relay ------------------>
	message			<---------------- relay** -----------------
	
	* sends to all clients
	** sends to all clients except the requesting client
	
## Manage

	npm install @totemstan/securelink	# install
	npm run start [ ? | $ | ...]		# Unit test
	npm run verminor					# Roll minor version
	npm run vermajor					# Roll major version
	npm run redoc						# Regen documentation

## Usage

Acquire and optionally configure **SecureLink** as follows:

	const SECLINK = require("@totemstan/securelink").config({
		key: value, 						// set key
		"key.key": value, 					// indexed set
		"key.key.": value					// indexed append
	});
	
where configuration keys follow [ENUMS deep copy conventions](https://github.com/totem-man/enums).

## Program Reference
<details>
<summary>
<i>Open/Close</i>
</summary>
## Modules

<dl>
<dt><a href="#module_SECLINK">SECLINK</a></dt>
<dd><p>Provides a private (end-to-end encrypted) message link between trusted clients and secure logins. </p>
<p>This module documented in accordance with <a href="https://jsdoc.app/">jsdoc</a>.</p>
<h2 id="env-dependencies">Env Dependencies</h2>
<pre><code>LINK_PASS = passphrase to encrypt user passwords [&quot;securePass&quot;]
LINK_HOST = name of secure link host [&quot;secureHost&quot;]
</code></pre>
</dd>
<dt><a href="#module_SECLINK-CLIENT">SECLINK-CLIENT</a></dt>
<dd><p>Provides UIs for operating private (end-to-end encrypted) messaging link 
between trusted clients.  </p>
<p>This module documented in accordance with <a href="https://jsdoc.app/">jsdoc</a>.</p>
<p>The UIs herein are created in the /site.jade and support:</p>
<pre><code>+ client login/out/reset operations
+ SecureLink and dbSync sockets (Kill, Sockets, Join)
+ data encryption (GenKeys, Encrypt, Decrypt, Encode, Decode)
</code></pre>
</dd>
</dl>

<a name="module_SECLINK"></a>

## SECLINK
Provides a private (end-to-end encrypted) message link between trusted clients and secure logins. 

This module documented in accordance with [jsdoc](https://jsdoc.app/).

## Env Dependencies
									  
	LINK_PASS = passphrase to encrypt user passwords ["securePass"]
	LINK_HOST = name of secure link host ["secureHost"]

**Requires**: <code>module:[enums](https://www.npmjs.com/package/@totemstan/enums)</code>, <code>module:[socketio](https://www.npmjs.com/package/@totemstan/socketio)</code>, <code>module:[socket.io](https://www.npmjs.com/package/socket.io)</code>, <code>module:[crypto](https://nodejs.org/docs/latest/api/)</code>  
**Author**: [ACMESDS](https://totemstan.github.io)  
**Example**  
```js
On the server:

	const
		SECLINK = require("securelink");

	SECLINK.config({
		server: server,
		sqlThread: sqlThread,
		guest: {....}
	});
								
	const
		{ sio } = SECLINK;
	
	sio.emit( "update", { // send update request
	});	
						

On the client:
	
	// <script src="securelink-client.js"></script>
	
	Sockets({	// establish sockets
		update: req => {	// intercept update request
			console.log("update", req);
		}, 

		// other sockets as needed ...
	});
```

* [SECLINK](#module_SECLINK)
    * [.host](#module_SECLINK.host)
    * [.isTrusted()](#module_SECLINK.isTrusted)
    * [.Login(login, cb)](#module_SECLINK.Login)
    * [.testClient(client, guess, res)](#module_SECLINK.testClient)
    * [.config()](#module_SECLINK.config)

<a name="module_SECLINK.host"></a>

### SECLINK.host
Domain name of host for attributing domain-owned accounts.

**Kind**: static property of [<code>SECLINK</code>](#module_SECLINK)  
<a name="module_SECLINK.isTrusted"></a>

### SECLINK.isTrusted()
Test if an account is "trusted" to use the secure com channel.

**Kind**: static method of [<code>SECLINK</code>](#module_SECLINK)  
<a name="module_SECLINK.Login"></a>

### SECLINK.Login(login, cb)
Start a secure link and return the user profile corresponding for the supplied 
	account/password login.  The provided callback LOGIN(err,profile) where LOGIN =  
	resetPassword || newAccount || newSession || guestSession determines the login session
	type being requested.

**Kind**: static method of [<code>SECLINK</code>](#module_SECLINK)  
**Cfg**: <code>Function</code>  

| Param | Type | Description |
| --- | --- | --- |
| login | <code>String</code> | account/password credentials |
| cb | <code>function</code> | callback (err,profile) to process the session |

<a name="module_SECLINK.testClient"></a>

### SECLINK.testClient(client, guess, res)
Test response of client during a session challenge.

**Kind**: static method of [<code>SECLINK</code>](#module_SECLINK)  

| Param | Type | Description |
| --- | --- | --- |
| client | <code>String</code> | name of client being challenged |
| guess | <code>String</code> | guess provided by client |
| res | <code>function</code> | response callback( "pass" || "fail" || "retry" ) |

<a name="module_SECLINK.config"></a>

### SECLINK.config()
Establish socketio channels for the SecureIntercom link (at store,restore,login,relay,status,
	sync,join,exit,content) and the insecure dbSync link (at select,update,insert,delete).

**Kind**: static method of [<code>SECLINK</code>](#module_SECLINK)  
<a name="module_SECLINK-CLIENT"></a>

## SECLINK-CLIENT
Provides UIs for operating private (end-to-end encrypted) messaging link 
between trusted clients.  

This module documented in accordance with [jsdoc](https://jsdoc.app/).

The UIs herein are created in the /site.jade and support:

	+ client login/out/reset operations
	+ SecureLink and dbSync sockets (Kill, Sockets, Join)
	+ data encryption (GenKeys, Encrypt, Decrypt, Encode, Decode)

**Requires**: <code>module:socketio</code>, <code>module:openpgp</code>, <code>module:uibase</code>  
**Author**: [ACMESDS](https://totemstan.github.io)  
</details>

## Contacting, Contributing, Following

Feel free to 
* submit and status [TOTEM issues](http://totem.hopto.org/issues.view) 
* contribute to [TOTEM notebooks](http://totem.hopto.org/shares/notebooks/) 
* revise [TOTEM requirements](http://totem.hopto.org/reqts.view) 
* browse [TOTEM holdings](http://totem.hopto.org/) 
* or follow [TOTEM milestones](http://totem.hopto.org/milestones.view) 

## License

[MIT](LICENSE)

* * *

&copy; 2012 ACMESDS
