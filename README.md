# SecureLink

**SecureLink** provides a secure link between US gov client through the use of PGP end-to-end encryption.  	Like its 
Socket.IO predecessors, SocketIO provides json-based web sockets, though it has hooks to support secure binary sockets 
for future VoIP, video, etc applications.

**SecureLink** also provides antibot technology to challenge clients, and a secure login mechanisim.
	
## Installation

Clone [secureLink](https://github.com/totemstan/securelink) || [COE](https://sc.appdev.proj.coe/acmesds/securelink) || [SBU](https://gitlab.gsmil/acmesds/securelink) into your PROJECT/securelink folder.   

## Contacting, Contributing, Following

Feel free to [submit and status TOTEM issues](http://totem.hopto.org/issues.view) || [COE](https://totem.west.ile.nga.ic.gov/issues.view) || [SBU](https://totem.nga.mil/issues.view), [contribute TOTEM notebooks](http://totem.hopto.org/shares/notebooks/) || [COE](https://totem.west.ile.nga.ic.gov/shares/notebooks/) || [SBU](https://totem.nga.mil/shares/notebooks/),
[inspect TOTEM requirements](http://totem.hopto.org/reqts.view) || [COE](https://totem.west.ile.nga.ic.gov/reqts.view) || [SBU](https://totem.nga.mil/reqts.view), [browse TOTEM holdings](http://totem.hopto.org/) || [COE](https://totem.west.ile.nga.ic.gov/) || [SBU](https://totem.nga.mil/), 
or [follow TOTEM milestones](http://totem.hopto.org/milestones.view) || [COE](https://totem.west.ile.nga.ic.gov/milestones.view) || [SBU](https://totem.nga.mil/milestones.view).

## Use

	const
		{ Login } = SECLINK = require("securelink");
		
	// Use CB = resetPassword || newAccount || newSession || guestSession
	
	Login( "account/password", function CB( err, profile ) {
		if ( err ) 
			// handle error condition
			
		else	// have a good user profile
			console.log(profile);
	});
	
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
<dd><p>Provides a secure link between 
    clients and server for account login/out/reset operations, and provides a private (end-to-end
    encrypted) message link between trusted clients.</p>
</dd>
<dt><a href="#module_SECLINK-CLIENT">SECLINK-CLIENT</a></dt>
<dd><p>Provides a secure link between 
    clients and server for account login/out/reset operations, and provides a private (end-to-end
    encrypted) message link between trusted clients. </p>
<pre><code>This module -- required by all next-level frameworks (like jquery, extjs, etc) -- provides 
methods for:

    + SecureLink and dbSync sockets (Kill, Sockets, Join)
    
    + data encryption (GenKeys, Encrypt, Decrypt, Encode, Decode)
</code></pre>
</dd>
</dl>

<a name="module_SECLINK"></a>

## SECLINK
Provides a secure link between 
	clients and server for account login/out/reset operations, and provides a private (end-to-end
	encrypted) message link between trusted clients.

**Requires**: <code>module:socketio</code>, <code>module:socket.io</code>, <code>module:crypto</code>  
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
