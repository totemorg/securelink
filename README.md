# SecureLink

**SecureLink** is built on [TOTEM's SocketIO](https://github.com/totemstan/socketio) and provides a secure link between TOTEM clients 
through the use of PGP end-to-end encryption.

**SecureLink** also provides antibot technology to challenge clients, and a secure login mechanisim.
	
## Installation

Clone the following into your PROJECT folder

+ [SECLINK secure link](https://github.com/totemstan/securelink) || [COE](https://sc.appdev.proj.coe/acmesds/securelink) || [SBU](https://gitlab.west.nga.ic.gov/acmesds/securelink)  
+ [SOCKETIO web sockets](https://github.com/totemstan/socketio) || [COE](https://sc.appdev.proj.coe/acmesds/socketio) || [SBU](https://gitlab.west.nga.ic.gov/acmesds/socketio)  

## Contacting, Contributing, Following

Feel free to [submit and status TOTEM issues](http://totem.zapto.org/issues.view) || [COE](https://totem.west.ile.nga.ic.gov/issues.view) || [SBU](https://totem.nga.mil/issues.view), [contribute TOTEM notebooks](http://totem.zapto.org/shares/notebooks/) || [COE](https://totem.west.ile.nga.ic.gov/shares/notebooks/) || [SBU](https://totem.nga.mil/shares/notebooks/),
[inspect TOTEM requirements](http://totem.zapto.org/reqts.view) || [COE](https://totem.west.ile.nga.ic.gov/reqts.view) || [SBU](https://totem.nga.mil/reqts.view), [browse TOTEM holdings](http://totem.zapto.org/) || [COE](https://totem.west.ile.nga.ic.gov/) || [SBU](https://totem.nga.mil/), 
or [follow TOTEM milestones](http://totem.zapto.org/milestones.view) || [COE](https://totem.west.ile.nga.ic.gov/milestones.view) || [SBU](https://totem.nga.mil/milestones.view).

## Protocol

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
	
## License

[MIT](LICENSE)

## Modules

<dl>
<dt><a href="#module_SECLINK">SECLINK</a></dt>
<dd><p>Provides a secure link between totem clients and the totem server.
Provides account login/out/reset sessions and a private (end-to-end
encrypted) message link between trusted clients. 
Documented in accordance with <a href="https://jsdoc.app/">jsdoc</a>.</p>
</dd>
<dt><a href="#module_SECLINK-CLIENT">SECLINK-CLIENT</a></dt>
<dd><p>Provides a secure link between 
clients and server for account login/out/reset operations, and provides a private (end-to-end
encrypted) message link between trusted clients. </p>
<p>This module -- required by all next-level frameworks (like jquery, extjs, etc) -- provides 
methods for:</p>
<pre><code>+ SecureLink and dbSync sockets (Kill, Sockets, Join)

+ data encryption (GenKeys, Encrypt, Decrypt, Encode, Decode)
</code></pre>
</dd>
</dl>

<a name="module_SECLINK"></a>

## SECLINK
Provides a secure link between totem clients and the totem server.
Provides account login/out/reset sessions and a private (end-to-end
encrypted) message link between trusted clients. 
Documented in accordance with [jsdoc](https://jsdoc.app/).

**Requires**: <code>module:socketio</code>, <code>module:socket.io</code>, <code>module:crypto</code>  

* [SECLINK](#module_SECLINK)
    * [.Login(login, cb)](#module_SECLINK.Login)
    * [.config()](#module_SECLINK.config)

<a name="module_SECLINK.Login"></a>

### SECLINK.Login(login, cb)
Start a secure link and return the user profile corresponding for the supplied 
account/password login.  The provided callback(err,profile) = 
resetPassword || newAccount || newSession || guestSession determines the session
type being requested.

**Kind**: static method of [<code>SECLINK</code>](#module_SECLINK)  
**Cfg**: <code>Function</code>  

| Param | Type | Description |
| --- | --- | --- |
| login | <code>String</code> | account/password credentials |
| cb | <code>function</code> | callback to process the session |

<a name="module_SECLINK.config"></a>

### SECLINK.config()
Establish socketio channels for the SecureIntercom link (at store,restore,login,relay,status,
		sync,join,exit,content) and the insecure dbSync link (at select,update,insert,delete).

**Kind**: static method of [<code>SECLINK</code>](#module_SECLINK)  
<a name="module_SECLINK-CLIENT"></a>

## SECLINK-CLIENT
Provides a secure link between 
clients and server for account login/out/reset operations, and provides a private (end-to-end
encrypted) message link between trusted clients. 

This module -- required by all next-level frameworks (like jquery, extjs, etc) -- provides 
methods for:

	+ SecureLink and dbSync sockets (Kill, Sockets, Join)

	+ data encryption (GenKeys, Encrypt, Decrypt, Encode, Decode)

**Requires**: <code>module:socketio</code>, <code>module:openpgp</code>, <code>module:uibase</code>  

* * *

&copy; 2012 ACMESDS
