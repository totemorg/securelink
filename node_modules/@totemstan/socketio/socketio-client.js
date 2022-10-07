// UNCLASSIFIED

/**
Replaces the buggy socket.io and socket.io-client modules found in the public.

@module SOCKETIO-CLIENT
@author [ACMESDS](https://totemstan.github.io)
*/

var
	ioSocket = null,
	ioClient = "TBD";

const
	ioTrace = (...args) => console.log(">>>socketio",args),
	ioChannels = {
		disconnect: req => Log(res),
		exit: req => Log(res),
		timeout: req => Log(res),
		readable: req => Log(res),
		end: req => Log(res),
		error: req => Log(res),
	};		

function io(url) {	//< make a connect request to the server at url||window.location

	ioTrace("ws connect", url, ioClient);

	ioSocket = new WebSocket( url ? url : (window.location+"").replace("https:","wss:").replace("http:","ws:") );
	ioSocket.on = (channel,cb) => {		// attach on-event catcher
		ioTrace("attach listener on", channel);
		ioChannels[channel] = cb;
	};

	ioSocket.emit = (channel,req) => { //< emit req over channel
		ioTrace( "emit", channel, req);

		// Create a web scoket, send the req over the channel, then listen for optional ack.

		const emitSocket = new WebSocket( url ? url : (window.location+"").replace("https:","wss:").replace("http:","ws:") );

		emitSocket.addEventListener('open', () => {
			// Send a message to the WebSocket server
			emitSocket.send( JSON.stringify({		// Send a message to the WebSocket server
				channel: channel,
				message: req,
				id: ioClient
			}) );
		});  

		if (0) 	// can listen for an acknowlegement sent by the server
		emitSocket.addEventListener('message', event => {
			// The `event` object is a typical DOM event object, and the message data sent
			// by the server is stored in the `data` property
			ioTrace('ack', event.data);
		});
	};					

	// Send a connect message 
	ioTrace("connect");
	ioSocket.addEventListener('open', () => {
		// Send a message to the WebSocket server
		ioSocket.send( JSON.stringify({		// Send a message to the WebSocket server
			channel: "connect",
			message: "a request to connect",
			id: ioClient
		}) );
	});  

	if (0)	// could listen for an ack
	ioSocket.addEventListener('message', event => {
		// The `event` object is a typical DOM event object, and the message data sent
		// by the server is stored in the `data` property
		ioTrace('ack', event.data);
	});

	ioSocket.addEventListener('message', event => {		//< route socketio broadcast message to correct listener
		try {
			const
				{channel,message,id} = JSON.parse(event.data),
				cb = ioChannels[channel];

			if ( cb )
				cb( message );

			else
				ioTrace( `socketio received json on undefined channel ${channel}`, event.data);
		
		}

		catch (err) {
			ioTrace( "ctrl pk error", err, event.data);
		}
	});

	return ioSocket;
}

// UNCLASSIFIED
