# [SOCKETIO](https://github.com/totem-man/socketio)

Provides a form-fit-functional replacement for the notoriously buggy [socket.io](https://www.npmjs.com/package/socket.io) 
and its [socket.io-client](https://www.npmjs.com/package/socket.io-client) client counterpart.  Like its socket.io predecessors, 
**SocketIO** provides json-based web sockets, though it also has hooks to support binary sockets (for VoIP, video, etc) applications.
**SocketIO** provides both a server-side and client-side modules that mimic the [socket.io](https://socket.io/docs/v3/client-initialization/)
specification (less the bugs of course).

## Manage

	npm install @totemstan/socketio	# install
	npm run start [ ? | $ | ...]	# Unit test
	npm run verminor				# Roll minor version
	npm run vermajor				# Roll major version
	npm run redoc					# Regen documentation

## Usage

Acquire **SocketIO** as follows:

	const SIO = require("@totemstan/socketio");
	
See the Program Reference for examples.

## Program Reference
<details>
<summary>
<i>Open/Close</i>
</summary>
## Modules

<dl>
<dt><a href="#module_SOCKETIO">SOCKETIO</a></dt>
<dd><p>Replaces the buggy socket.io and socket.io-client modules.
Documented in accordance with <a href="https://jsdoc.app/">jsdoc</a>.</p>
<p>ref: <a href="https://medium.com/hackernoon/implementing-a-websocket-server-with-node-js-d9b78ec5ffa8">https://medium.com/hackernoon/implementing-a-websocket-server-with-node-js-d9b78ec5ffa8</a></p>
</dd>
<dt><a href="#module_SOCKETIO-CLIENT">SOCKETIO-CLIENT</a></dt>
<dd><p>Replaces the buggy socket.io and socket.io-client modules found in the public.</p>
</dd>
</dl>

<a name="module_SOCKETIO"></a>

## SOCKETIO
Replaces the buggy socket.io and socket.io-client modules.
Documented in accordance with [jsdoc](https://jsdoc.app/).

ref: https://medium.com/hackernoon/implementing-a-websocket-server-with-node-js-d9b78ec5ffa8

**Requires**: <code>module:[@totemstan/enums](https://www.npmjs.com/package/@totemstan/enums)</code>, <code>module:[crypto](https://nodejs.org/docs/latest/api/)</code>  
**Author**: [ACMESDS](https://totemstan.github.io)  
**Example**  
```js
On the server:

	const SIO = require("socketio");
	IO = SIO(server);					// connects socketIO to your nodejs server
	
	IO.on( "connect", socket => {		// the client automatically emits a "connect" request when it calls io()  
	
		socket.on(  "CHANNEL", (req,socket) => {			// intercepts client request made on socket to this CHANNEL
			console.log( "here is the client's request", req ); 
			socket.emit({ message: "a response" });
			IO.emit({ message: "a message for everyone!" });
			IO.emitOthers("SkipThisClient", { message: "a message for everyone!" });		// useful emit extension
			IO.clients["someone@totem.org"].emit({ message: "you get an extra message"});
		});
		
		// etc for other CHANNELs 

	});	
	IO.emit({ .... })  			// to emit a request to all clients

On the client:

	// <script type="text/javascript, src="/socketio/socketio-client.js"></script>

	const
		ioSocket = io();			// connect to socketIO by emitting a "connect" request
		ioClient = "myClientName";	// set a client name to identify this socket

	ioSocket.emit("CHANNEL", {		// send request to server side on its CHANNEL
		...
	});
	
	ioSocket.on("CHANNEL", req => {
		console.log("server sent this request", req);
	});
	
```
**Example**  
```js
On the server:

	const
		SOCKETIO = require("socketio"),
		SIO = SOCKETIO(server); 	// establish sockets on provided HTTP server

	SIO.on("connect", socket => {  	// define socket listeners when client calls the socketio-client io()
		console.log("listening to sockets");

		socket.on( "join", (req,socket) => {	// trap client "join" request
		});

		// etc
	});
	

On the client:
	// The socketio interface is established when the server does a require( "socketio" ) to create a 
	// socketio = "/socketio/socketio-client.js" endpoint from which the client imports its client via a 
	// <script src=socketio> and defines a default ioClient name.

	const
		iosocket = io(); 					// connect to socketio 
		ioClient = "somewhere@org.com";		// default client nmae

		iosocket.emit( "join", {			// send join request to server
			client: ioClient,				// usually provide with request 
			message: "can I join please?"	// optional connection info
		}); 
```
<a name="module_SOCKETIO-CLIENT"></a>

## SOCKETIO-CLIENT
Replaces the buggy socket.io and socket.io-client modules found in the public.

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
