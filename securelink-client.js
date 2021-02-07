// UNCLASSIFIED 

/**
	@module SECLINK-CLIENT

	[secureLink](https://github.com/totemstan/securelink.git) provides a secure link between 
	clients and server for account login/out/reset operations, and provides a private (end-to-end
	encrypted) message link between trusted clients. 
	
	This module -- required by all next-level frameworks (like jquery, extjs, etc) -- provides 
	methods for:
	
		+ basic data munging (Copy, Each, Log, tag, 
				isString, isArray, isFunction, isDate, isNumber, isError, typeOf)
				
		+ service interface (Ajax)
		
		+ SecureLink and dbSync sockets (Kill, Sockets, Send, Join)
		
		+ dom rendering (Render, Uncomment, Active) per [the skinning guide](/skinguide.view)
		
		+ data encryption (GenKeys, Encrypt, Decrypt, Signal, Encode, Decode)
		
	@requires socketio
	@requires openpgp
*/

//============= notice actions (defined by the site skin) that support the SecureIntercom (socket.io/openpgp)

function notice_login() {

	const
		{ secureLink,bang,initSecureLink,iosocket } = SECLINK,
		notice = document.getElementById("notice"),
		lock = document.getElementById("lock"),
		info = document.getElementById("info");

	if ( notice.value.startsWith(bang) ) 
		try {
			const
				{ pubKeys } = SECLINK,
				login = notice.value.substr(bang.length);
			
			iosocket.emit("login", {
				login: login,
				client: ioClient
			});
		}
	
		catch (err) {
			Log("login", err);
			notice.value = "login failed";
		}
		
	else
		alert(`supply ${bang}login/password`);

}

function notice_scroll() {
	const
		{ secureLink } = SECLINK,
		scroll = document.getElementById("scroll"),
		notice = document.getElementById("notice");
	
	notice.value = secureLink.history[scroll.value];
}

function notice_save() {
	const
		{ secureLink,iosocket,bang } = SECLINK,
		notice = document.getElementById("notice");
	
	if ( notice.value.startsWith(bang) )
		Encode( notice.value.substr(bang.length), JSON.stringify(secureLink.history), msg => {
			//alert("encoded=" + msg);
			iosocket.emit("store", {
				client: ioClient,
				message: msg
			});
		});
	
	else
		alert(`supply ${bang}encryption password`);
	
}

function notice_load() {
	const
		{ secureLink,iosocket,bang } = SECLINK,
		notice = document.getElementById("notice");
	
	if ( notice.value.startsWith(bang) )
		iosocket.emit("restore", {
			client: ioClient
		});
	
	else
		alert(`supply ${bang}encryption password`);
}

function notice_delete() {
	const
		{ secureLink } = SECLINK;
	
	delete secureLink.history;
	secureLink.history = [];
}

function notice_signal() {		//< send secure notice message to server
	const
		{ bang, secureLink, iosocket } = SECLINK,
		{ secure } = secureLink;

	if ( !secureLink ) { 
		alert("SecureLink never connected");
		return;
	}

	const
		notice = document.getElementById("notice"),
		upload = document.getElementById("upload");
	
	if ( notice.value.startsWith("!!") ) {		// not for me - for a notice control
		//alert( `Submit ${bang}option with appropriate control` );
		return;	
	}
	
	//Log(secureLink, iosocket, secure);

	const
		{ pubKeys } = SECLINK,
		{ priKey, passphrase, lookups } = secureLink;

	//Log(pubKeys, priKey);

	const
		files = Array.from(upload.files),
		[msg, to] = route = notice.value.sub(lookups).split("=>");

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
		//alert(msg);

		(to||"").replace(/ /g,"").split(",").forEach( to => {

			function send(msg,to) {
				Log("signal", msg, ioClient, "=>", to);

				if ( pubKey = pubKeys[to] )		// use secureLink when target in ecosystem
					Encrypt( passphrase, msg, pubKey, priKey, msg => {
						//Log(notice.value,msg);
						iosocket.emit("relay", {		// send encrypted pgp-armored message
							message: msg,
							from: ioClient,
							to: to,
							route: route.slice(2),
							insecureok: !secure
						});
					});

				else						// use insecure link when target not in ecosystem
					iosocket.emit("relay", {		// send raw message
						message: msg,
						from: ioClient,
						to: to.startsWith(bang) ? to.substr(bang.length) : to,
						route: route.slice(2),
						insecureok: !secure || to.startsWith(bang)
					});
			}

			switch (to) {
				case "":
					send(msg,ioClient);
					break;

				case "$all":
					Each( pubKeys, to => send(msg,to) );
					break;

				default:
					send( msg,to);
			}
		});
	}

	//Log(msg,"=>",to,lookups);
	if ( files.length ) 
		readTextFiles( msg, files, msg => {
			send(msg,to);
			upload.value = "";			// clear list
			upload.files.splice(0,0);	// clear list
		});

	else
		send(msg,to);

}


//============== Extract functions to the browser's global namespace

const {
	GenKeys, Encrypt, Decrypt, Signal, Encode, Decode,
	Copy, Each, Log, 
	Kill, Sockets, Ajax, Send, Join, Pretty,
	isString, isArray, isFunction, isDate, isNumber, isError, typeOf, 
	Render, Uncomment, Activate} = SECLINK = {
	
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
				//read candidate info from local description
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
Consider logging in to avoid the bot catcher. <br>
Thank you for helping Totem protect its war fighters from bad data. <br><br>
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
		
	Ajax: function Ajax(ctx,method,url,cb) {	//< send context hash using method to url with callback cb if async
		const
			req = new XMLHttpRequest(),
			get = method.toUpperCase() == "GET";

		req.open( method, get ? url.tag("?",ctx) : url, cb?true:false );

		if ( get ) 
			req.send();

		else 
			req.send(JSON.stringify(ctx));

		if ( cb ) 
			req.onreadystatechange = () => {
				if ( req.readyState == 4 ) cb( req.responseText );
			}; 

		else 
			return req.responseText;
	},

	Send: function Send(form,data,cb) {		//< submit form inputs that are marked for submit to the form's action url 
		for( var els = form.elements, n=0, N=els.length; n<N; n++ ) {
			var el = els[n];
			if (el.getAttribute("submit")) data[el.id] = el.value;
		}
		//Log( data ); 

		return Ajax( data, form.method, form.action, cb );
	},

	//============ socket.io support functions
	
	Join: (location,cbs) => {		//< Request connection with socket.io
		
		if ( io ) {		//	socket.io supported
			//Log("join: client="+ioClient+" location="+location+" url="+window.location);
			
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
				agent: SECLINK.agent,
				platform: SECLINK.platform,
				insecureok: false 
			}); 
		}
		
		else
			Log("no socketio - insecure mode"); 
		
	},

	Pretty: x => {
		
		if ( x == 0 ) 
			return 0+"";
		
		else
		if (x)
			if ( x.forEach ) {
				var res = "[ ";
				x.forEach( val => res += Pretty(val) + ", " );
				return res+" ]";
			}

			else
			if ( typeof x == "string" ) 
				return x;

			else
			if ( x.toFixed ) 
				return parseFloat(x.toFixed(2));

			else {
				var res = "{ ";
				Each( x, (key,val) => 
					 res += key + ": "+ Pretty(val) + ", " );

				return res+" }";
			}
		
		else
			return "null";
	},
	
	initSecureLink: ( pubKeysOnline, passphrase, cb ) => {

		const { pubKeys } = SECLINK;
		
		if ( passphrase && ioClient && openpgp ) 
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
						history: [],
						lookups: {
							$me: ioClient,
							$strike: `fire the death ray now Mr. president=>$president=>$commanders`,
							$president: `!brian.d.james@comcast.net`,
							$commanders: `brian.d.james@comcast.net,brian.d.james@comcast.net`,
							$test: `this is a test and only a test=>!$me`,
							$dogs: `Cats are small. Dogs are big. Cats like to chase mice. Dogs like to eat bones.=>!$me`,
							$drugs: `The Sinola killed everyone in the town.#terror=>!$me`,
						}
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
			cb(false, {});

	},

	Sockets: cbs => {		//< Establish socket.io callbacks to the CRUD i/f 

		function joinService(location) {
			function displayNotice(req,msg) {
				const
					{ secureLink } = SECLINK;
				
				if ( msg.startsWith("??") ) {
					info.innerHTML = msg.substr(2);
					notice.size = 5;
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
								info.innerHTML = Object.keys(pubKeys).mailto("Totem");
								tick.style = "display:none";
								tries.style = "display:none";
								notice.size = 75;
								notice.value = `Welcome ${ioClient}`;
								notice.onchange="notice_signal()";
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
					const
						t = new Date(),
						tstamp = t.toUTCString(); //t.toDateString() + " " + t.toLocaleTimeString();

					notice.value = req.from ? msg + "<=" + req.from + " on " + tstamp : msg;
					secureLink.history.push( notice.value );
				}
			}

			Join( location, Copy({		// join totem's socket.io manager

				close: req => alert("secureLink closed!"),
				
				start: req => {		// start secure link with supplied passphrase
					if ( openpgp )
						initSecureLink( req.pubKeys, req.passphrase, secure => {
							notice.value = `Welcome ${ioClient}`;
							lock.innerHTML = "".tag("img",{src:`/clients/icons/actions/${secure?"lock":"unlock"}.png`,width:15,height:15});
							info.innerHTML = Object.keys(pubKeys).mailto("Totem");
							//alert(info.innerHTML);

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
					
					info.innerHTML = Object.keys(pubKeys).mailto("Totem");
				},

				relay: req => {			// relay message or public key
					const
						{ secureLink } = SECLINK,
						{ from,to,message,score } = req,
						forMe = (to == ioClient) || (to == "all");

					Log("relay", req);

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
					info.innerHTML = Object.keys(pubKeys).mailto("Totem");	
				},
				
				remove: req => {
					Log("remove",req);
					const {client} = req;
					delete pubKeys[client];
					info.innerHTML = Object.keys(pubKeys).mailto("Totem");
				},
				
				status: req => {
					
					Log("status", req);
					
					if ( req.cookie ) {
						document.cookie = req.cookie; 

						alert(req.cookie + " => " + document.cookie);
						window.open(window.location+"", "_self");
						//document.cookie = "";
					}
					
					else
						notice.value = req.message;
				}
					
			}, cbs) );
		}
		
		const
			{ probeClient, pubKeys, iosocket, initSecureLink } = SECLINK,
			notice = document.getElementById("notice"),
			scroll = document.getElementById("scroll"),
			lock = document.getElementById("lock"),
			info = document.getElementById("info"),
			tick = document.getElementById("tick"),
			tries = document.getElementById("tries");

		probeClient( (ip,location) => joinService(ip,location) );

	},
		
	//============ general purpose data testing and output
	Log: (...args) => console.log(">>>secLink",args),
	
	typeOf: obj => obj.constructor.name,
	isString: obj => obj.constructor.name == "String",
	isNumber: obj => obj.constructor.name == "Number",
	isArray: obj => obj.constructor.name == "Array",
	isObject: obj => obj.constructor.name == "Object",
	isDate: obj => obj.constructor.name == "Date",
	isFunction: obj => obj.constructor.name == "Function",
	isError: obj => obj.constructor.name == "Error",
	
	//=========== dom parsing
		
	/**
		Remove comments from the dom.
	*/
	Uncomment: $el => {
		$el.contents().filter( (n,el) => {
			//Log(n,el.nodeName, el.nodeType, el.nodeValue);
			return el.nodeType==8;
		}).each( (i,com) => {
			//Log("remove", i, com.nodeValue);
			$(com).remove();
		});
		return $el;
	},
	
	/**
		Render widgets in the dom per the [totem skinguide](/skinguide.view).  After the dom in renderer, 
		use Activate to configure these widgets.
	*/
	Render: ( $at, cbs) => {
		//alert("render", $at[0] );
		const
			Tab = "tab";		//< keyword used by Render
		
		const
			border = cbs.border,
			widgets = [];
			
		//alert("render"+$at[0]);
		
		Object.keys(cbs).forEach( widget => {	// scan thru all provided widget types
			const
				cb = cbs[widget];
			
			$at.children( widget ).each( (j,el) => {	// process widgets of this type
				
				const	// get widget options
					$el = $(el),
					id = el.id,
					panes = {
						north: $el.attr("north"),
						south: $el.attr("south"),
						east: $el.attr("east"),
						west: $el.attr("west")
					},
					posting = panes.north || panes.south || panes.east || panes.west,
					tabs = [];

				var
					inset = "";
				
				$el.children().not(Tab).each( (i,tag) => {	// get posting html for north pane
					inset += tag.outerHTML;
					$(tag).remove();
				});
					
				$el.children(Tab).each( (i,tab) => {	// get tabs for this widget
					const $tab = $(tab);
					tabs.push( $tab );
					widgets.push( Render( $tab, cbs ) || null );
				});
				
				if ( posting || inset ) // requesting a post
					if ( cb != cbs.border ) // cant post to a border
						if ( border ) {	// must have a border agent (in last! item of cbs)
							var update = "";
							
							for( var pane in panes ) {
								var 
									post = panes[pane],
									html = (pane == "north") ? inset : "";
								
								$el.attr(pane,"");  // clear posting to prevent infinite recursion

								if (post)
									post.split(",").forEach( url => {
										if (url)
											html += "no iframes".tag("iframe", {src:url, scrolling:"auto", width:"100%", height:"600"});
									});

								/*
								Log(">>>posting", pane, $el[0], el.outerHTML, "===>", 
									( html.tag(Tab,{ id:pane } ) + el.outerHTML.tag(Tab,{id:"center"})
									).tag("border",{id:id+".help"})  ); 
								*/

								if (html) update += html.tag(Tab,{ id:pane } );
							}

							//Log(">>>posting", update);
							$el.replaceWith( // replace widget with border-ed version
								( update + el.outerHTML.tag(Tab,{id:"center"}) ).tag("border",{id:id+".help"})
							);	
							//Log(">>>", $at.html() );
						}
				
				// generate the widget
				$el.html( cb( $el, tabs ) );  
			});
		});
		
		return widgets;
	},
	
	/**
		Configure and activate widgets that were rendered with Render.
	*/
	Activate: ( $el, cbs) => {
		//Log("activate", $el[0] );
		
		Object.keys(cbs).forEach( widget => {
			const
				cb = cbs[widget];
			
			$el.find(widget).each( (i,el) => {
				const
					$el = $(el);

				//Log("activate", i, $el[0] );

				cb( $el );
			});
		});
		
	},
	
	isEmpty: opts => {
		for ( var key in opts ) return false;
		return true;
	},
	
	/**
		Copy source hash to target hash; thus Copy({...}, {}) is equivalent to new Object({...}).
		If a deep deliminator (e.g. ".") is provided, src  keys are treated as keys into the target thusly:

			{	
				A: value,			// sets target[A] = value

				"A.B.C": value, 	// sets target[A][B][C] = value

				"A.B.C.": {			// appends X,Y to target[A][B][C]
					X:value, Y:value, ...
				},	

				OBJECT: [ 			// prototype OBJECT (Array,String,Date,Object) = method X,Y, ...
					function X() {}, 
					function Y() {}, 
				... ]

			} 

		 @memberof SECLINK
		 @param {Object} src source hash
		 @param {Object} tar target hash
		 @param {String} deep copy key 
		 @return {Object} target hash
	 */
	Copy: function Copy (src,tar,deep) {
		for (var key in src) {
			var val = src[key];

			if (deep) 
				switch (key) {
					case Array: 
						val.extend(Array);
						break;

					case "String": 
						val.extend(String);
						break;

					case "Date": 
						val.extend(Date);
						break;

					case "Object": 	
						val.extend(Object);
						break;

					/*case "Function": 
						this.callStack.push( val ); 
						break; */

					default:

						var 
							keys = key.split(deep), 
							Tar = tar,
							idx = keys[0];
						
						for (  // index to the element to set/append
								var n=0,N=keys.length-1 ; 
								n < N ; 
								idx = keys[++n]	) 	
								
							if ( idx in Tar ) 
								Tar = Tar[idx];
							else
								Tar = Tar[idx] = new Array();

						if (idx)  // set target
							Tar[idx] = val;

						else  // append to target
						if (val.constructor == Object) 
							for (var n in val) 
								Tar[n] = val[n];

						else
							Tar.push( val );
				}
			
			else
				tar[key] = val;
		}

		return tar;
	},

	/**
		Enumerates src with optional callback cb(idx,val,isLast) and returns isEmpty.
		@memberof SECLINK
		@param {Object} src source hash
		@param {Function} cb callback (idx,val, isLast) returns true or false to terminate
	*/
	Each: function Each ( A, cb ) {
		Object.keys(A).forEach( key => cb( key, A[key] ) );
	},
	
	uploadFile: function () {
		var files = document.getElementById("uploadFile").files,
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
}

/**
 * Extend the opts prototype with specified methods, or, if no methods are provided, 
 * extend this ENUM with the given opts.  Array, String, Date, and Object keys are 
 * interpretted to extend their respective prototypes.  
 * @memberof Array
 */
Array.prototype.Extend = function (con) {
	this.forEach( function (proto) {
		//Log("ext", proto.name, con);
		con.prototype[proto.name] = proto;
	});
};

[ // extend Date
	/**
	 * Return MySQL compliant date string.
	 * @memberof Date
	 * @return {String} MySQL compliant version of this date
	 */
	function toJSON () {
		return this.toISOString().split(".")[0];
	}
].Extend(Date);

[  // extend String
	/*
		Spanner
		Parses a "group(key,key, ... ,group[key,key, ...]), ..." string into a set of keys, spans, and 
		html-suitable headers where ()-groups prefix their keys by group_keys and []-groups do not prefix
		their keys.
		
		Example:
		
		"a,b(x,y(u,v,w),z(ah(alpha,beta[gamma,delta]),bh)),c".Spanner() )
		 
		 keys: [
			{ name: 'a' },
			{ name: 'b_x' },
			{ name: 'b_y_u' },
			{ name: 'b_y_v' },
			{ name: 'b_y_w' },
			{ name: 'b_z_ah_alpha' },
			{ name: 'gamma' },
			{ name: 'delta' },
			{ name: 'b_z_bh' },
			{ name: 'c' }

		spans: '{"cols":10,"rows":4,"keys":{"a":null,"b":{"keys":{"b_x":null,"y":{"keys":{"b_y_u":null,"b_y_v":null,"b_y_w":null},"cols":3,"rows":2},"z":{"keys":{"ah":{"keys":{"b_z_ah_alpha":null,"beta":{"keys":{"gamma":null,"delta":null},"cols":2,"rows":4}},"cols":3,"rows":4},"b_z_bh":null},"cols":4,"rows":4}},"cols":8,"rows":4},"c":null}}'

		heads: {
		  '0': [
			{ key: 'a', colspan: 1, rowspan: 5 },
			{ key: 'c', colspan: 1, rowspan: 5 },
			{ key: 'b', colspan: 8, rowspan: 1 }
		  ],
		  '1': [
			{ key: 'b_x', colspan: 1, rowspan: 4 },
			{ key: 'y', colspan: 3, rowspan: 1 },
			{ key: 'z', colspan: 4, rowspan: 1 }
		  ],
		  '2': [
			{ key: 'b_z_bh', colspan: 1, rowspan: 3 },
			{ key: 'b_y_u', colspan: 1, rowspan: 1 },
			{ key: 'b_y_v', colspan: 1, rowspan: 1 },
			{ key: 'b_y_w', colspan: 1, rowspan: 1 },
			{ key: 'ah', colspan: 3, rowspan: 1 }
		  ],
		  '3': [
			{ key: 'b_z_ah_alpha', colspan: 1, rowspan: 2 },
			{ key: 'beta', colspan: 2, rowspan: 1 }
		  ],
		  '4': [
			{ key: 'gamma', colspan: 1, rowspan: 1 },
			{ key: 'delta', colspan: 1, rowspan: 1 }
		  ]
		}
	*/
	function Spanner(cb) {
		const
			{keys,spans,heads} = ctx = {
				keys: [],
				spans: {},
				heads: {}
			};
		
		this.Spans("",0,0,keys,spans,heads,cb || (key => new Object({name:key})) );
		return ctx;
	},
	
	function Spans(prefix,pos,depth,keys,spans,heads,cb) {
		
		function stackSpans() {
			var
				header = heads[depth] || (heads[depth] = []),
				maxRows = depth;
			
			for (var key in spans.keys ) 
				if ( span = spans.keys[key] ) 
					maxRows = max( maxRows, span.rows );
			
			for (var key in spans.keys ) {
				var span = spans.keys[key];
				if ( span ) 
					header.push({ 
						key: key,
						colspan: span.cols,
						rowspan: 1
					});
				
				else
					header.push({ 
						key: key,
						colspan: 1,
						rowspan: maxRows - depth + 1
					});
			}
			
			//Log(depth, header); 
			return header.sort( (a,b) => b.rowspan-a.rowspan );
		}

		function stackKey() {
			if (key) {
				keys.push( cb ? new Object(cb(prefix+key)) : prefix+key );
				spans.keys[prefix+key] = null;
				key = "";
				spans.cols++;
			}
		}
				
		const
			{max} = Math;
		
		var
			key = "";
		
		//Log(prefix);
		spans.cols = 0;
		spans.rows = depth;
		spans.keys = {};
		
		for ( const N = this.length; pos<N; pos++) 
			switch ( char = this.charAt(pos)) {
				case "[":
				case "(":
					var span = spans.keys[key] = {keys: {} };
					pos = this.Spans( (char=="(") ? prefix+key+"_" : prefix, pos+1, depth+1, keys, span, heads, cb);
					spans.cols += span.cols;
					spans.rows = max(spans.rows,span.rows);
					//Log(key,"next", pos, this.charAt(pos+1));
					key = "";
					break;
				
				case ",":
					stackKey();
					break;
				
				case "]":
				case ")":
					stackKey();
					stackSpans();		
					return pos;
					
				default:
					key += char;
			}

		stackKey();
		stackSpans();
		
		return pos;
	},
	
	function parseJSON (def) {
		try {
			return JSON.parse(this);
		}
		catch (err) {
			return def ? isFunction(def) ? def(this) : def : null;
		}
	},

	/**
		Tag url (el = ? || &) or html (el = html tag) with specified attributes.

		@memberof String
		@param {String} el tag element = ? || & || html tag
		@param {String} at tag attributes = {key: val, ...}
		@return {String} tagged results
	*/
	function tag(el,at) {

		//if (!at) { at = {href: el}; el = "a"; }

		if ( el == "?" || el == "&" ) {  // tag a url
			var rtn = this;

			if (at)
				Each(at, (key,val) => {
					if ( val ) {
						rtn += el + key + "=" + val;
						el = "&";
					}
				});

			return rtn;	
		}

		else {  // tag html
			var rtn = "<"+el+" ";
			//Log("tag", el, at);
			
			if (at)
				Each( at, (key,val) => {
					if ( val )
						rtn += key + "='" + val + "' ";
				});

			switch (el) {
				case "embed":
				case "img":
				case "link":
				case "input":
					return rtn+">" + this;
				default:
					//Log("tag out", rtn+">" + this + "</"+el+">" );
					return rtn+">" + this + "</"+el+">";
			}
		}
	},

	/**
		Parse "$.KEY" || "$[INDEX]" expressions given $ hash.

		@memberof String
		@param {Object} $ source hash
	*/
	function parseEval($) {
		try {
			return eval(this+"");
		}
		
		catch (err) {
			return err+"";
		}
	},
	
	function eval (def, stash) {
		//Log(">>>eval", def );
		const args = ((this+"")||def||"").split(",").$( (i,args) => args[i] = args[i].parseJSON( arg => {
			if (stash) {
				for (var key="",n=0,N=arg.length,char=arg.charAt(n); n<N; n++,char=arg.charAt(n) )
					if ( "-_.".indexOf(char) < 0 )
						if ( char == char.toUpperCase() ) key += char;
				
				return stash[key] = arg.toLowerCase();
			}
				
			else
				return arg;
		}) );
		
		return (args.length>1) ? args : args[0]; 
	},
	
	function pick (stash) {
		const 
			str = this+":",
			opts = [];
		
		// CI4:SB10:baseline(+) 0.95
		for (var size="", key="", arg="", n=0, N=str.length; n<N; n++, arg += char)
			switch (char = str.charAt(n) ) {
				case " ": break;
					
				case "0":
				case "1":
				case "2":
				case "3":
				case "4":
				case "5":
				case "6":
				case "7":
				case "8":
				case "9":
				case ".":
					size += char; break;
					
				case ":":
					opts.push( [stash[key] || arg, parseFloat(size||"2")] );
					size = "";
					key = "";
					arg = "";
					break;
					
				default:
					key += char; break;
			}
		
		return opts;
	},
	
	function sub(hash) {
		var res = this;
		Each(hash, (key,val) => res = res.replace(key,val) );
		return res;
	}
	
].Extend(String);

[ // extend Array
	function $( cb ) {
		const args = this;
		args.forEach( (arg,i) => cb( i, args )  );
		return args;
	},
	
	function mailto(subj) {
		return this.map( (name,i) => `$${i} ${name}`
				 	.tag("option",{ value:`mailto:${name}?subject=${subj}` }) )
			.join("").tag("select",{onchange:"window.location=this.value;"});
	}
].Extend(Array);

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

if (SECLINK.probePlatform) { // Doscover clients platform
	SECLINK.platform = navigator.platform || "";
	SECLINK.onLinux = navigator.platform.indexOf("Linux") == 0;
	SECLINK.onWindows = navigator.platform.indexOf("Win") == 0;
}

// UNCLASSIFIED
