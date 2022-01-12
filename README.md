# SecureLink

**SecureLink** is built on [SocketIO](https://github.com/totemstan/socketio) and provides a secure link between clients 
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
	
## Installation

Clone **SecureLink** from one of its repos:

	git clone https://github.com/totemstan/securelink
	git clone https://sc.appdev.proj.coe/acmesds/securelink
	git clone https://gitlab.west.nga.ic.gov/acmesds/securelink

and its dependent modules:

+ **ENUMS** [WWW](https://github.com/totemstan/enums)  [COE](https://sc.appdev.proj.coe/acmesds/enums)  [SBU](https://gitlab.west.nga.ic.gov/acmesds/enums)  
+ **SOCKETIO** [WWW](https://github.com/totemstan/socketio) [COE](https://sc.appdev.proj.coe/acmesds/socketio) [SBU](https://gitlab.west.nga.ic.gov/acmesds/socketio)  

## Env vars
									  
	LINK_PASS = passphrase to encrypt user passwords ["securePass"]
	LINK_HOST = name of secure link host ["secureHost"]
									  
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

**Requires**: <code>module:socketio</code>, <code>module:socket.io</code>, <code>module:crypto</code>  
**Author**: [ACMESDS](https://totemstan.github.io)  

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
* submit and status **TOTEM** issues (
[WWW](http://totem.zapto.org/issues.view) 
[COE](https://totem.west.ile.nga.ic.gov/issues.view) 
[SBU](https://totem.nga.mil/issues.view)
)  
* contribute to **TOTEM** notebooks (
[WWW](http://totem.zapto.org/shares/notebooks/) 
[COE](https://totem.west.ile.nga.ic.gov/shares/notebooks/) 
[SBU](https://totem.nga.mil/shares/notebooks/)
)  
* revise **TOTEM** requirements (
[WWW](http://totem.zapto.org/reqts.view) 
[COE](https://totem.west.ile.nga.ic.gov/reqts.view) 
[SBU](https://totem.nga.mil/reqts.view), 
)  
* browse **TOTEM** holdings (
[WWW](http://totem.zapto.org/) 
[COE](https://totem.west.ile.nga.ic.gov/) 
[SBU](https://totem.nga.mil/)
)  
* or follow **TOTEM** milestones (
[WWW](http://totem.zapto.org/milestones.view) 
[COE](https://totem.west.ile.nga.ic.gov/milestones.view) 
[SBU](https://totem.nga.mil/milestones.view)
).

## License

[MIT](LICENSE)

* * *

&copy; 2012 ACMESDS
