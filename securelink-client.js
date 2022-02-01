// UNCLASSIFIED 

/**
Provides UIs for operating private (end-to-end encrypted) messaging link 
between trusted clients.  

This module documented in accordance with [jsdoc]{@link https://jsdoc.app/}.

The UIs herein are created in the /site.jade and support:

	+ client login/out/reset operations
	+ SecureLink and dbSync sockets (Kill, Sockets, Join)
	+ data encryption (GenKeys, Encrypt, Decrypt, Encode, Decode)

@module SECLINK-CLIENT
@author [ACMESDS](https://totemstan.github.io)

@requires socketio
@requires openpgp
@requires uibase
*/

function secure_login() {

	const
		{ secureLink,bang,initSecureLink,iosocket } = SECLINK,
		notice = document.getElementById("notice"),
		//lock = document.getElementById("lock"),
		users = document.getElementById("users");

	//alert(notice.value);
	
	try {
		const
			{ pubKeys } = SECLINK,
			login = notice.value;

		iosocket.emit("login", {
			login: login,
			client: ioClient
		});
	}

	catch (err) {
		Log("login", err);
		notice.value = "login failed";
	}

}

function secure_scroll() {
	const
		{ secureLink } = SECLINK,
		scroll = document.getElementById("scroll"),
		notice = document.getElementById("notice");
	
	if (scroll.value >= 0)
	notice.value = secureLink.history[scroll.value];
}

function secure_save() {
	const
		{ secureLink,iosocket,bang } = SECLINK,
		notice = document.getElementById("notice");
	
	Encode( notice.value, JSON.stringify(secureLink.history), msg => {
		//alert("encoded=" + msg);
		iosocket.emit("store", {
			client: ioClient,
			message: msg
		});
	});
	
}

function secure_load() {
	const
		{ secureLink,iosocket,bang } = SECLINK,
		notice = document.getElementById("notice");
	
	iosocket.emit("restore", {
		client: ioClient
	});
}

function secure_delete() {
	const
		{ secureLink } = SECLINK;
	
	delete secureLink.history;
	secureLink.history = [];
}

function secure_signal() {		//< send secure notice message to server
	const
		{ bang, secureLink, iosocket } = SECLINK;

	if ( !secureLink ) { 
		alert("SecureLink never connected");
		return;
	}

	const
		notice = document.getElementById("notice"),
		upload = document.getElementById("upload");
	
	//Log(secureLink, iosocket, secure);

	const
		{ pubKeys } = SECLINK,
		{ secure, priKey, passphrase, lookups, history, myRoom } = secureLink;

	//Log(pubKeys, priKey);

	const
		files = Array.from(upload.files),
		[msg, to] = notice.value.replaceKeys(lookups).split("=>");

	function readTextFiles( msg, files, cb) {
		var todo = files.length;

		Each( files, (key,file) => {
			//Log(key,file);
			if ( file && file.type == "text/plain" ) {
				var reader = new FileReader();
				//Log(reader);
				reader.readAsText(file, "UTF-8");
				reader.onload = function (evt) {
					//alert( evt.target.result );
					msg += evt.target.result;
					if (--todo <= 0 ) cb(msg);
					//document.getElementById("fileContents").innerHTML = evt.target.result;
				};
				reader.onerror = function (evt) {
					if (--todo <= 0 ) cb(msg);
					//document.getElementById("fileContents").innerHTML = "error reading file";
				};
			}
		});
	}

	function send(msg,to) {
		Log("signal", msg, ioClient, "=>", to );

		history.push( msg + "=>" + to /*{
			msg: msg,
			user: to,
			dir: "to",
			on: (new Date()).toUTCString()
		} */);  

		if ( pubKey = pubKeys[to] )		// use secureLink when target in ecosystem
			Encrypt( passphrase, msg, pubKey, priKey, msg => {
				Log(notice.value,msg);
				iosocket.emit("relay", {		// send encrypted pgp-armored message
					message: msg,
					from: ioClient,
					to: to,
					room: myRoom,
					route: msg, //route.slice(2),
					insecureok: !secure
				});
			});

		else						// use insecure link when target not in ecosystem
			iosocket.emit("relay", {		// send raw message
				message: msg,
				from: ioClient,
				to: to, //to.startsWith(bang) ? to.substr(bang.length) : to,
				route: msg, //route.slice(2),
				insecureok: true // !secure || to.startsWith(bang)
			});
	}

	Log(msg,"=>",to);
	if ( files.length ) 
		readTextFiles( msg, files, msg => {
			send(msg,to);
			upload.value = "";			// clear list
			upload.files.splice(0,0);	// clear list
		});

	else
	if ( to )
		to.replace(/ /g,"").split(",").forEach( to => {
			if ( to == "$all" )
				Each( pubKeys, to => send(msg,to) );
			
			else
				send( msg, to );
		});
	
	//else
		//alert("missing target");

}

function users_select(key) { 
	const
		{ secureLink,bang,initSecureLink,iosocket } = SECLINK,
		{ history } = secureLink,
		notice = document.getElementById("notice");
	
	notice.value = history[history.length]; //history.select({user: key}).map( hist => `${hist.on} ${hist.dir} ${hist.user} ${hist.msg}` ).join("\n");
}
			
//============== Extract functions to the browser's global namespace

const {
	GenKeys, Encrypt, Decrypt, Encode, Decode,
	Kill, Sockets, Join } = SECLINK = {
	
	pubKeys: {},
		
	probeClient: cb => {	// legacy
		
		// Discover client IP addresses 
		function probeIPs(callback) {		// legacy
			var ip_dups = {};

			//compatibility for firefox and chrome
			var RTCPeerConnection = window.RTCPeerConnection
				|| window.mozRTCPeerConnection
				|| window.webkitRTCPeerConnection;
			var useWebKit = !!window.webkitRTCPeerConnection;

			//bypass naive webrtc blocking using an iframe
			if(!RTCPeerConnection){
				//NOTE: you need to have an iframe in the page right above the script tag
				//
				//<iframe id="iframe" sandbox="allow-same-origin" style="display: none"></iframe>
				//<script>..._probeIPs called in here...
				//
				var win = iframe.contentWindow;
				RTCPeerConnection = win.RTCPeerConnection
					|| win.mozRTCPeerConnection
					|| win.webkitRTCPeerConnection;
				useWebKit = !!win.webkitRTCPeerConnection;
			}

			//minimal requirements for data connection
			var mediaConstraints = {
				optional: [{RtpDataChannels: true}]
			};

			var servers = {iceServers: [{urls: "stun:stun.services.mozilla.com"}]};

			//construct a new RTCPeerConnection
			var pc = new RTCPeerConnection(servers, mediaConstraints);

			function handleCandidate(candidate){
				//match just the IP address
				var ip_regex = /([0-9]{1,3}(\.[0-9]{1,3}){3}|[a-f0-9]{1,4}(:[a-f0-9]{1,4}){7})/
				var ip_addr = ip_regex.exec(candidate)[1];

				//remove duplicates
				if(ip_dups[ip_addr] === undefined) callback(ip_addr);

				ip_dups[ip_addr] = true;
			}

			//listen for candidate events
			pc.onicecandidate = function(ice){ //skip non-candidate events
				if(ice.candidate) handleCandidate(ice.candidate.candidate);
			};

			//create a bogus data channel
			pc.createDataChannel("");

			//create an offer sdp
			pc.createOffer(function(result){ 
				//trigger the stun server request
				pc.setLocalDescription(result, function(){}, function(){});

			}, function(){});

			//wait for a while to let everything done
			setTimeout( function() {
				//read candidate users from local description
				var lines = pc.localDescription.sdp.split('\n');

				lines.forEach(function(line) {
					if(line.indexOf('a=candidate:') === 0) handleCandidate(line);
				});
			}, 1000);
		}

		function probeLocation( cb ) {
			if ( navigator.geolocation )  // Discover client geolocation
				navigator.geolocation.getCurrentPosition( pos => {
					if (!pos.coords) pos.coords = {latitude:0, longitude: 0};
					
					cb( 'POINT(' + [pos.coords.longitude, pos.coords.latitude].join(" ") + ')' );
					
				}, err => {	
					cb( 'POINT(0 0)' );
				});
		}
		
		//probeIPs( ip => probeLocation( location => cb( ip, location ) ) );
		probeLocation( location => cb( "nada", location ) );
	},
	probePlatform: io,
	probeAgent: io,
		
	browser: null, 
	//ip: null, 
	//location: null,
	onLinux: false,
	onWindows: false,
	agent: null,
	platform: "",
		
	bootoff: 
`
Thank you for helping Totem protect its war fighters from bad data.
`,

	bang: "!!",

	//========== Text encoding and decoding functions to support socket.io/openpgp secureLink
		
	// one-way encryption methods
		
	Encode: async (password,cleartext,cb) => {
		const { data: encrypted } = await openpgp.encrypt({
			message: openpgp.message.fromText(cleartext), // input as Message object
			passwords: [password],                        // multiple passwords possible
			armor: true                                   // ASCII armor 
		});
		//const encrypted = message.packets.write(); // get raw encrypted packets as Uint8Array
		//Log( "encode", encrypted );
		cb ( encrypted );
	},
				 
	Decode: async (password, msg, cb) => {
		//Log(password,msg);
		const { data: decrypted } = await openpgp.decrypt({
			message:  await openpgp.message.readArmored(msg), // parse encrypted bytes
			passwords: [password]                     // decrypt with password
			//format: 'binary'                        // output as Uint8Array
		});
		
		//Log( "decode", decrypted ); 
		cb( decrypted );
	},		
	
	// two-way PKI encryption methods
		
	GenKeys: async (passphrase, cb) => {
		const { privateKeyArmored, publicKeyArmored, revocationCertificate } = await openpgp.generateKey({
			userIds: [{ 
				//abc: "some name", time: "some time"
				//name: 'Jon Smith', email: 'jon@example.com' 
			}], // you can pass multiple user IDs
			curve: 'ed25519',                                           // ECC curve name
			passphrase: passphrase						           // protects the private key
		});

		cb( publicKeyArmored, privateKeyArmored );
	},

	Encrypt: async ( passphrase, cleartext, publicKeyArmored, privateKeyArmored, cb ) => {
		
		//alert("encrypt with="+passphrase);
		
		//Log(openpgp);
		const { keys: [privateKey] } = await openpgp.key.readArmored(privateKeyArmored);
		
		//await privateKey.decrypt(passphrase);
		
		const publicKeys = publicKeyArmored.forEach
				? 	// multiple public keys provided
				await Promise.all(publicKeysArmored.map(		 
						async (key) => (await openpgp.key.readArmored(key)).keys[0] ))

				: 	// single public key provided
				(await openpgp.key.readArmored(publicKeyArmored)).keys;

		//alert("pubkey read");
		
		const { data: encrypted } = await openpgp.encrypt({
			message: openpgp.message.fromText(cleartext),   // input as Message object
			publicKeys: publicKeys,
			//privateKeys: [privateKey]                     // for signing (optional)
		});

		//alert("enc msg="+encrypted);
		cb( encrypted );
	},

	Decrypt: async ( passphrase, msgArmored, publicKeyArmored, privateKeyArmored, cb ) => {

		//alert("decrypt pass="+passphrase);
		
		const { keys: [privateKey] } = await openpgp.key.readArmored(privateKeyArmored);

		try {
			await privateKey.decrypt(passphrase);
		}
		
		catch (err) {
			Log("wrong passphrase");
			cb( null );
			return;
		} 
		
		//alert("prikey descrypted");
		
		const { data: decrypted } = await openpgp.decrypt({
			message: await openpgp.message.readArmored(msgArmored),              // parse armored message
			//publicKeys: (await openpgp.key.readArmored(publicKeyArmored)).keys, // for verification (optional)
			privateKeys: [privateKey]                                           // for decryption
		});

		//alert("dec="+decrypted);
		
		cb( decrypted );
	},

	Kill: msg => {	//< Destroy document and replace with message
		document.head.childNodes.forEach( el => el.remove() );
		document.body.childNodes.forEach( el => el.remove() );
		document.write( msg );
	},
		
	//============ socket.io support functions
	
	Join: (ip,location,cbs) => {		//< Request connection with socket.io
		
		if ( io ) {		//	socket.io supported
			Log( "join", `client=${ioClient} location=${location} ip=${ip} url=${window.location}` );
			
			const
				iosocket = SECLINK.iosocket = io(); 	// issues a connect to socketio
					// io({transports: ["websocket"] });  // for buggy socket.io

			for (var action in cbs) 				// setup socket.io callbacks
				iosocket.on(action, cbs[action]);

			//iosocket.on("connect", req => Log("connect", req, iosocket.id) );
			//iosocket.on("disconnect", req => Log("disconnect", req,iosocket.id) );
			
			iosocket.emit("join", {		// request permission to join
				client: ioClient,
				message: "can I join please?",
				location: location,
				ip: ip,
				agent: SECLINK.agent,
				platform: SECLINK.platform,
				insecureok: false 
			}); 
			//alert("join requested");
		}
		
		else
			Log("no socketio - insecure mode"); 
		
	},

	initSecureLink: ( pubKeysOnline, passphrase, cb ) => {

		const { pubKeys } = SECLINK;
		
		if ( passphrase ) 
			GenKeys( passphrase, (pubKey, priKey) => {
				const 
					{ iosocket, pubKeys } = SECLINK,
					{ secure,lookups } = SECLINK.secureLink = {
						secure: true,
							// allow only us gov and totem accts
							// (ioClient.endsWith(".mil") || ioClient.endsWith("@totem.org")) && !ioClient.match(/\.ctr@.*\.mil/),				
						passphrase: passphrase,
						priKey: priKey,
						clients: 1,
						history: [ "message => to,..." ],
						lookups: {
							$me: ioClient,
							$strike: `fire the death ray now Mr. president=>$president=>$commanders`,
							$president: `!brian.d.james@comcast.net`,
							$commanders: `brian.d.james@comcast.net,brian.d.james@comcast.net`,
							$test: `this is a test and only a test=>!$me`,
							$dogs: `Cats are small. Dogs are big. Cats like to chase mice. Dogs like to eat bones.=>!$me`,
							$drugs: `The Sinola killed everyone in the town.#terror=>!$me`,
						},
						myRoom: "default",
						rooms: ["default"]
					};

				pubKeys[ioClient] = pubKey;
				Copy( pubKeysOnline, pubKeys );

				Object.keys(pubKeys).forEach( (client,i) => lookups["$"+i] = client );
				
				//Log(lookups);
				
				iosocket.emit("announce", {		// annnouce yourself
					client: ioClient,
					pubKey: pubKey,
				});	

				//Log("keys", pubKey,priKey,lookups);
				cb(secure);	
			});
		
		else
			cb(false);

	},

	Sockets: cbs => {		//< Establish socket.io callbacks to the CRUD i/f 

		function joinService(ip,location) {
			function displayNotice(req,msg) {
				const
					{ secureLink } = SECLINK,
					{ history } = secureLink;
				
				if ( msg.startsWith("??") ) {	// challenge user
					probe.innerHTML = msg.substr(2);
					notice.size = 50;
					notice.onchange = () => {
						switch ( Ajax({
										guess: notice.value,
										client: ioClient
									}, "GET", req.callback) ) {
							case "pass":
								tick.value = 666;		// signal halt
								//alert("pass");
								break;

							case "fail":
							case "retry":
								tick.value = 0;
								tries.value --;
								break;
						}
					},
					tick.value = req.timeout;
					tries.value = req.retries;
					tick.style = "display:span";
					tries.style = "display:span";
					notice.value = "";
					
					const
						Fuse = setInterval( function () {
							if ( tick.value > 600 ) {
								clearInterval(Fuse);
								//users.innerHTML = Object.keys(pubKeys).menu("Totem");
								probe.innerHTML = "";
								tick.style = "display:none";
								tries.style = "display:none";
								notice.size = 50;
								notice.value = `Welcome ${ioClient}`;
								history.push( notice.value );
								notice.onchange= secure_signal; // "secure_signal()";
							}

							else {
								tick.value--;
								if ( tick.value <= 0 ) {
									tick.value = req.timeout;
									tries.value--;
									if ( tries.value <= 0 ) {
										clearInterval(Fuse);
										//document.write( "Goodbye" );
										Kill( SECLINK.bootoff );
									}
								}
							}
						}, 1e3 );
				}

				else {
					notice.value = msg + "<=" + req.from;
					history.push( msg + "<=" + req.from /*{
						msg: msg,
						user: req.from,
						dir: "from",
						on: (new Date()).toUTCString()
					} */); 
				}
			}

			Join( ip, location, Copy({		// join the socket.io manager

				close: req => alert("secureLink closed!"),
				
				start: req => {		// start secure link with supplied passphrase
					Log("start", req);
					if ( openpgp )
						initSecureLink( req.pubKeys, req.passphrase, secure => {
							notice.value = `Welcome ${ioClient}`;
							updateUsers();

							displayNotice( req, req.message );
						});
					
					else
						Log("secureLink not installed");
				},

				content: req => {		// ingest message history content 
					const
						{ secureLink } = SECLINK;
	
					Decode( notice.value.substr(2), req.message, content => {
						try {
							secureLink.history = JSON.parse(content);
						}

						catch (err) {
							alert("failed to load history");
						}
					});
				},

				sync: req => {
					const
						{ secureLink } = SECLINK,
						{ from,to,message } = req;

					Log("sync", req);
					pubKeys[from] = message;
					
					updateUsers();
				},

				relay: req => {			// relay message or public key
					Log("relay", req);

					const
						{ secureLink } = SECLINK,
						{ from,to,message,score } = req,
						forMe = (to == ioClient) || (to == "all");

					//Log(">>>>forme", from,to,ioClient,forMe);
					
					if ( forMe )
						if ( secureLink.passphrase && message.indexOf("BEGIN PGP MESSAGE")>=0 )
							Decrypt( secureLink.passphrase, message, pubKeys[ioClient], secureLink.priKey, 
									msg => displayNotice(req,msg) );

						else
							displayNotice(req, message + "  " + (score?Pretty(score):"") );

					else
					if ( (from==ioClient) && !pubKeys[to] )	// not for me, but outside ecosystem and I generated it
						displayNotice(req, message + "  " + (score?Pretty(score):"") );
				},

				accept: req => {
					Log("accept", req);
					const {client,pubKey} = req;
					pubKeys[client] = pubKey;
					updateUsers();
				},
				
				remove: req => {
					Log("remove",req);
					const {client} = req;
					delete pubKeys[client];
					updateUsers();
				},
				
				status: req => {
					
					Log("status", req);
					
					if ( req.cookie ) {
						document.cookie = req.cookie; 

						//alert(req.cookie + " => " + document.cookie);
						window.open(window.location+"", "_self");
						//document.cookie = "";
					}
					
					else
						notice.value = req.message;
				}
					
			}, cbs) );
		}
		
		function updateUsers(  ) {
			users.innerHTML = 
				Object.keys(pubKeys)
				.map( (name,i) => `$${i} ${name}`
					 .tag("option", { value: name }) )
				.join("")
				.tag("select", { onchange: `users_select(this.value)` }); 
		}
		
		const
			{ probeClient, pubKeys, iosocket, initSecureLink } = SECLINK,
			notice = document.getElementById("notice"),
			scroll = document.getElementById("scroll"),
			//lock = document.getElementById("lock"),
			users = document.getElementById("users"),
			probe = document.getElementById("probe"),
			//rooms = document.getElementById("rooms"),
			tick = document.getElementById("tick"),
			tries = document.getElementById("tries");

		probeClient( (ip,location) => joinService(ip,location) );
	},
		
	uploadFile: function () {
		var 
			files = document.getElementById("uploadFile").files,
			Files = [];
		
		for (var n=0,N=files.length; n<N; n++) 
			Files.push({
				name: files[n].name,
				type: files[n].type,
				size: files[n].size
			});

		//var file = files[0]; for (var n in file) alert(n+"="+file[n]);
		//alert(JSON.stringify(Files));
			
			Request( false, "POST", "/uploads.db", function (res) {
				alert(res);
			}, {
				//name: file.name,
				owner: SECLINK.user.client,
				classif: "TBD",
				tag: "upload",
				geo: SECLINK.user.location,
				files: Files
			});		
	}	
};

//============ Probe client information

if (SECLINK.probeAgent) {  // Discover clients brower
	var
		agent = SECLINK.agent = navigator.userAgent || "",
		agents = {Firefox:"Firefox/", Chrome: "Chrome/", Safari:"Safari/"};

	for (var n in agents)
		if (agent.indexOf(agents[n])>=0) {
			SECLINK.browser = n;
			break;
		}
}

if (SECLINK.probePlatform) { // Discover clients platform
	SECLINK.platform = navigator.platform || "";
	SECLINK.onLinux = navigator.platform.indexOf("Linux") == 0;
	SECLINK.onWindows = navigator.platform.indexOf("Win") == 0;
}

// UNCLASSIFIED
