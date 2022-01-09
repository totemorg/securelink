// UNCLASSIFIED

/**
Provides a secure link between totem clients and the totem server.
Provides account login/out/reset sessions and a private (end-to-end
encrypted) message link between trusted clients. 

This module in accordance with [jsdoc]{@link https://jsdoc.app/}.

@module SECLINK

@requires socketio
@requires socket.io
@requires crypto
*/

const		// globals
	ENV = process.env,
	CRYPTO = require("crypto");	

const
	// For legacy buggy socket.io
	//SOCKETIO = require('socket.io'), 				// Socket.io client mesh
	//SIOHUB = require('socket.io-clusterhub');  // Socket.io client mesh for multicore app
	//HUBIO = new (SIOHUB);

	// For working socketio
	SOCKETIO = require("socketio");

const { sqls, Each, Copy, Log, Login, errors } = SECLINK = module.exports = {
	
	Log: (...args) => console.log(">>>secLink",args),
	
	Each: ( A, cb ) => {
		Object.keys(A).forEach( key => cb( key, A[key] ) );
	},
	
	Copy: (src,tar,deep) => {

		for (var key in src) {
			var val = src[key];

			if (deep) 
				switch (key) {
					case Array: 
						val.Extend(Array);
						break;

					case "String": 
						val.Extend(String);
						break;

					case "Date": 
						val.Extend(Date);
						break;

					case "Object": 	
						val.Extend(Object);
						break;

					/*case "Function": 
						this.callStack.push( val ); 
						break; */

					default:

						var 
							keys = key.split(deep), 
							Tar = tar,
							idx = keys[0],
							N = keys.length-1;

						for ( var n=0; n < N ;  idx = keys[++n]	) { // index to the element to set/append
							if ( idx in Tar ) {
								if ( !Tar[idx] ) Tar[idx] = new Object();
								Tar = Tar[idx];
							}

							else
								Tar = Tar[idx] = new Object(); //new Array();
						}

						if (idx)  // not null so update target
							Tar[idx] = val;

						else  // null so append to target
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
	
	sqlThread: () => { throw new Error("sqlThread not configured"); },
	
	server: null,	// established on config
	sio: null,		// established on config
	
	sqls: {
		//addProfile: "INSERT INTO openv.profiles SET ?",
		getProfile: "SELECT * FROM openv.profiles WHERE Client=? LIMIT 1",
		addSession: "INSERT INTO openv.sessions SET ?",
		getRiddle: "SELECT * FROM openv.riddles WHERE ? LIMIT 1",
		
		getAccount:	"SELECT *,aes_decrypt(unhex(Password),?) AS Password FROM openv.profiles WHERE Client=?", 
		addAccount:	"INSERT INTO openv.profiles SET ?,Password=hex(aes_encrypt(?,?)),SecureCom=if(?,concat(Client,Password),'')", 
		setPassword: "UPDATE openv.profiles SET Password=hex(aes_encrypt(?,?)), SecureCom=if(?,concat(Client,Password),''), TokenID=null WHERE TokenID=?",
		getToken: "SELECT Client FROM openv.profiles WHERE TokenID=? AND Expires>now()", 
		addToken: "UPDATE openv.profiles SET TokenID=? WHERE Client=?",
		getSession: "SELECT * FROM openv.profiles WHERE SessionID=? LIMIT 1",
		addSession: "UPDATE openv.profiles SET SessionID=? WHERE Client=?",
		endSession: "UPDATE openv.profiles SET SessionID=null WHERE Client=?",		
	},
	
	// config options
	
	notify: opts => {},
	
	guest: null,		// guest profiles - guesting disabled by default
	
	/**
	Domain name of host for attributing domain-owned accounts.
	*/
	host: "nohost",
			
	challenge: {	//< for antibot client challenger 
		extend: 0,
		store: [],
		riddler: "/riddle",
		captcha: "/captcha",
		map: []
	},
	
	inspect: (doc,to,cb) => { 
		// throw new Error("securelink inspect not configured"); 
	},
	
	/**
	Test if an account is "trusted" to use the secure com channel.
	*/
	
	isTrusted: account => true,

	expireTemp: [5,10],
	expirePerm: [365,0],
	expirePass: [1,0],
	
	errors: {
		loginBlocked: new Error("account blocked"),
		noGuests: new Error("guests blocked"),
		userOnline: new Error( "account already online" ),
		userExpired: new Error( "account expired" ),
		resetFailed: new Error("password could not be reset at this time"),
		//resetPass: new Error("login with new password"),
		badPass: new Error("password not complex enough"),
		badLogin: new Error("bad login"),
		userPending: new Error("account verification pending -- see email")
	},
	
	/**
	Start a secure link and return the user profile corresponding for the supplied 
	account/password login.  The provided callback  X(err,profile) where X =  
	resetPassword || newAccount || newSession || guestSession determines the login session
	type being requested.

	@cfg {Function}
	@param {String} login account/password credentials
	@param {Function} cb callback to process the session 
	*/
	
	Login: (login,cb) => {
		function passwordOk( pass ) {
			return (pass.length >= 4);
		}

		function accountOk( acct ) {
			const
				banned = {
					"tempail.com": 1,
					"temp-mail.io":1,
					"anonymmail.net":1,
					"mail.tm": 1,
					"tempmail.ninja":1,
					"getnada.com":1,
					"protonmail.com":1,
					"maildrop	.cc":1,
					"":1,
				},

				[account,domain] = acct.split("@");

			return banned[domain] ? false : true;
		}

		function getExpires( expire ) {
			const
				{ round, random } = Math,
				[min,max] = expire,
				expires = new Date();

			expires.setDate( expires.getDate() + min + round(random()*max) );
			return expires;
		}

		function genPassword( cb ) {
			genCode(passwordLen, code => cb(code, getExpires(expirePass)) );
		}

		function genCode( len, cb ) {
			return CRYPTO.randomBytes( len/2, (err, code) => cb( code.toString("hex") ) );
		}

		function newAccount( sql, account, password, cb) {
			const
				{ guest } = SECLINK;
			
			if ( guest ) {
				const
					trust = isTrusted( account ),
					prof = Copy({
						Trusted: trust,
						Challenge: !trust,		// enable to challenge user at session join
						Client: account,
						Expires: getExpires( trust ? expireTemp : expirePerm )
					}, Copy( guest, {} ));
				
				sql.query( addAccount, [ 
					prof,  
				 	password, 
				 	encryptionPassword, 
				 	allowSecureConnect 
				], (err,info) => {
					//Log("add acct>>>>>", err, prof);
					cb( err ? null : prof );
				});
			}
			
			else 
				cb( null );
		}

		function genSession( sql, account, cb ) {
			genCode(sessionLen, code => {
				sql.query(
					addSession, 
					[code,account], err => {

						if ( err )	// has to be unqiue
							genSession( sql, account, cb );

						else cb( code, getExpires(expirePass) );
				});
			});
		}

		/*
		function genGuest( sql, account, expires, cb ) {
			genCode(accountLen, code => {
				//Log("gen guest", code);
				newAccount( sql, `guest${code}@${host}`, password, expires, (err,prof) => {
					Log("made account", prof);
					if ( !err )
						cb( prof );

					else 
						genGuest( sql, account, expires, cb );
				});
			});
		}  */

		function genToken( sql, account, cb ) {
			genCode(tokenLen, token => {
				sql.query( addToken, [ token, account], err => {
					if ( err )	// retry until token is unique
						genToken( sql, account, cb );

					else 	// relay unique token
						cb( token, getExpires(expirePass) );
				});
			});
		}

		function getProfile( sql, account, cb ) {
			//Log("get profile", account, host);
			sql.query( getAccount, [encryptionPassword, account], (err,profs) => {		

				cb( err ? null : profs[0] || null );

			});
		}
		
		const
			passwordLen = 4,
			accountLen = 16,
			sessionLen = 32,
			tokenLen = 4;

		const
			{ isTrusted, notify, sqlThread, host,
			expireTemp, expirePerm, expirePass } = SECLINK,
			{ getAccount, addAccount, addToken, getToken, getSession, addSession, endSession, setPassword } = sqls,
			encryptionPassword = ENV.PASS_PASS || "nopass",
			allowSecureConnect = true,
			[account,password] = login.split("/"),
			isGuest = account.startsWith("guest") && account.endsWith(host);
		
		Log(cb.name, login );
		
		sqlThread( sql => {
			switch ( cb.name ) {
				case "resetPassword":		// host requesting a password reset
					if ( isGuest )			// guests cannot requests a reset
						cb( errors.loginBlocked );

					else
						genToken( sql, account, (token,expires) => {	// gen a token account			
							cb( errors.userPending );

							notify({
								to: account,
								subject: "Totem password reset request",
								text: `Please login using ${token}/NEWPASSWORD by ${expires}`
							});
						});

					break;

				case "newAccount": 			// host requesting a new account
					if ( isGuest )			// only guests can request a new account
						genPassword( password => {
							//Log("gen", account, password);
							newAccount( sql, account, password, prof => {
								if ( prof ) {
									cb( prof );
									notify({
										to: account,
										subject: "Totem account verification",
										text: `You may login with ${account}/${password} until ${prof.Expires}`
									});
								}
								
								else
									cb( errors.badLogin );
							});
						});

					else
						cb( errors.loginBlocked );

					break;

				case "newSession":			// host requesting an authorized session 
				case "loginSession":
				case "authSession":
					
					getProfile( sql, account, prof => {
						if ( prof )	{	// have a valid user login
							if ( prof.Banned ) 				// account banned for some reason
								cb(	new Error(prof.Banned) );

							/*
							else
							if ( prof.Online ) 	// account already online
								cb( errors.userOnline );
							*/

							/*
							else
							if ( prof.Expires ? prof.Expires < new Date() : false )
								cb( errors.userExpired );
							*/

							else
							if ( prof.TokenID ) 	// password reset pending
								if ( passwordOk(password) )
									sql.query( setPassword, [password, encryptionPassword, allowSecureConnect, account], err => {
										cb( err ? errors.resetFailed : errors.resetPass );
									});

								else
									cb( errors.badPass );

							else
							if (password == prof.Password)		// validate login
								genSession( sql, account, (sessionID,expires) => cb(null, {
									id: sessionID, 
									expires: expires, 
									profile: prof
								}) );

							else
								cb( errors.loginBlocked );
						}
						
						else
							cb( errors.badLogin );
					});
					
					break;

				case "guestSession":		// host requesting a guest session
				case "noauthSession":
				default:
					
					getProfile( sql, account, prof => {
						//Log("prof>>>>", prof);
						if ( prof ) 
							if ( prof.Banned ) 
								cb(	new Error(prof.Banned) );	
							
							else
								cb( null, prof );
						
						else
							newAccount( sql, account, "", prof => {
								if ( prof ) 
									cb( null, prof );
								
								else
									cb( errors.badLogin );
							});

						/*
						else							// foreign account
							sql.query( getToken, [account], (err,profs) => {		// try to locate by tokenID
								if ( prof = profs[0] ) 
									cb( null, prof );

								else		// try to locate by sessionID
									sql.query( getSession, [account], (err,profs) => {		// try to locate by sessionID
										cb( err, err ? null : profs[0] || null );
									});	
							}); */
					});
			}
		});
	},
	
	/**
	Test response of client during a session challenge.
	*/
	testClient: (client,guess,res) => {
			
		const
			{ sqlThread } = SECLINK,
			{ getRiddle }= sqls;
		
		if ( getRiddle ) 
			sqlThread( sql => {
				sql.query(getRiddle, {Client:client}, (err,rids) => {

					if ( rid = rids[0] ) {
						var 
							ID = {Client:rid.ID},
							Guess = (guess+"").replace(/ /g,"");

						Log("riddle",rid);

						if (rid.Riddle == Guess) {
							res( "pass" );
							sql.query("DELETE FROM openv.riddles WHERE ?",ID);
						}
						else
						if (rid.Attempts > rid.maxAttempts) {
							res( "fail" );
							sql.query("DELETE FROM openv.riddles WHERE ?",ID);
						}
						else {
							res( "retry" );
							sql.query("UPDATE openv.riddles SET Attempts=Attempts+1 WHERE ?",ID);
						}

					}

					else
						res( "fail" );

				});
			});
		
		else
			res( "pass" );
	},
	
	/**
	Establish socketio channels for the SecureIntercom link (at store,restore,login,relay,status,
	sync,join,exit,content) and the insecure dbSync link (at select,update,insert,delete).
	*/
	config: opts => {
		
		function extendChallenger ( ) {		//< Create antibot challenges.
			const 
				{ store, extend, map, captcha } = challenge,
				{ floor, random } = Math;

			Log( `Adding ${extend} challenges from the ${captcha} imageset` );

			if ( captcha )
				for (var n=0; n<extend; n++) {
					var 
						Q = {
							x: floor(random()*10),
							y: floor(random()*10),
							z: floor(random()*10),
							n: floor(random()*map["0"].length)
						},

						A = {
							x: "".tag("img", {src: `${captcha}/${Q.x}/${map[Q.x][Q.n]}.jpg`}),
							y: "".tag("img", {src: `${captcha}/${Q.y}/${map[Q.y][Q.n]}.jpg`}),
							z: "".tag("img", {src: `${captcha}/${Q.z}/${map[Q.z][Q.n]}.jpg`})
						};

					store.push( {
						Q: `${A.x} * ${A.y} + ${A.z}`,
						A: Q.x * Q.y + Q.z
					} );
				}

			//Log(store);
		}
		
		const 
			{ inspect, sqlThread, guest, notify, server, challenge } = Copy( opts, SECLINK, "." ),
			{ getProfile, addSession } = sqls;

		const
			SIO = SECLINK.sio = SOCKETIO(server); 
				/*{ // socket.io defaults but can override ...
					//serveClient: true, // default true to prevent server from intercepting path
					//path: "/socket.io" // default get-url that the client-side connect issues on calling io()
				}),  */

		Log("config socketio");

		if (guest) {
			delete guest.ID;
			delete guest.SecureCom;
			delete guest.Password;
		}
		
		SIO.on("connect", socket => {  	// define side channel listeners when client calls io()
			Log("listening to sockets");

			socket.on("join", (req,socket) => {	// Traps client connect when client emits "join" request
				Log("socket admit client", req);
				const
					{client,message,insecureok} = req;

				sqlThread( sql => {

					if ( insecureok && addSession )	// log sessions if client permits and if allowed
						sql.query( addSession, {
							Opened: new Date(),
							Client: client,
							Location: req.location,
							IP: req.ip,
							Agent: req.agent,
							Platform: req.platform
						});

					sql.query(getProfile, [client], (err,profs) => { 

						/**
						Create an antibot challenge and relay to client with specified profile parameters

						@param {String} client being challenged
						@param {Object} profile with a .Message riddle mask
						*/
						function getChallenge (profile, cb) { 
							/**
							Check clients response req.query to a antibot challenge.

							@param {String} msg riddle mask contianing (riddle), (yesno), (ids), (rand), (card), (bio) keys
							@param {Array} rid List of riddles returned
							@param {Object} ids Hash of {id: value, ...} replaced by (ids) key
							*/
							function makeRiddles (msg,riddles,prof) { 
								const
									{ floor, random } = Math,
									rand = N => floor( random() * N ),
									N = store.length,
									randRiddle = () => store[rand(N)];

								//Log("make", N, randRiddle, prof);
								
								if (N)	
									return msg
										//.parse$(prof)
										.replace(/\#riddle/g, pat => {
											var QA = randRiddle();
											riddles.push( QA.A );
											return QA.Q;
										})
										.replace(/\#yesno/g, pat => {
											var QA = randRiddle();
											riddles.push( QA.A );
											return QA.Q;
										})
										.replace(/\#rand/g, pat => {
											riddles.push( rand(10) );
											return "random integer between 0 and 9";		
										})
										.replace(/\#card/g, pat => {
											return "cac card challenge TBD";
										})
										.replace(/\#bio/g, pat => {
											return "bio challenge TBD";
										});
								
								else
									return msg;
							}

							const
								{ riddler, store } = challenge,
								{ Message, Retries, Timeout } = profile,
								riddles = [],
								probe = makeRiddles( Message, riddles, profile );

							//Log("riddle", client, probe, riddles);

							sql.query("REPLACE INTO openv.riddles SET ?", {		// track riddle
								Riddle: riddles.join(",").replace(/ /g,""),
								Client: client,
								Made: new Date(),
								Attempts: 0,
								maxAttempts: Retries
							}, (err,info) => cb({		// send challenge to client
								message: "??"+probe,
								retries: Retries,
								timeout: Timeout,
								callback: riddler,
								passphrase: prof.SecureCom || ""
							}) );
						}

						function getOnline( cb) {
							const 
								keys = {};

							sql.query("SELECT Client,pubKey FROM openv.profiles WHERE Online")
							.on("result", rec => keys[rec.Client] = rec.pubKey )
							.on("end", () => cb( keys ) );
						}
						
						//Log(err,profs);

						try {
							if ( prof = profs[0] ) {
								if ( prof.Banned ) 
									SIO.clients[client].emit("status", {
										message: `${client} banned: ${prof.Banned}`
									});

								else
								if ( SecureCom = prof.SecureCom )	// allowed to use secure link
									if ( prof.Challenge )	// must solve challenge to enter
										getChallenge( prof, riddle => {
											Log("challenge", riddle);
											//socket.emit("challenge", riddle);
											SIO.clients[client].emit("start", riddle);
										});

									else
										getOnline( pubKeys => {
											SIO.clients[client].emit("start", {
												message: `Welcome ${client}`,
												from: "secureLink",
												passphrase: SecureCom,
												pubKeys: pubKeys
											});
										});

								else		// barred from using the secure link
									getOnline( pubKeys => {
										SIO.clients[client].emit("start", {
											message: `Welcome ${client}`,
											from: "secureLink",
											passphrase: "",
											pubKeys: pubKeys
										});
									});
							}

							else
								SIO.clients[client].emit("status", {
									message: `Cant find ${client}`
								});
						}
						
						catch (err) {
							Log(err,"Join failed");
						}
					});
				}); 
			});

			socket.on("store", (req,socket) => {
				const
					{client,ip,location,message} = req;

				Log("socket store client history", req);

				sqlThread( sql => {
					sql.query(
						"INSERT INTO openv.saves SET ? ON DUPLICATE KEY UPDATE Content=?", 
						[{Client: client,Content:message}, message],
						err => {

							try {
								SIO.clients[client].emit("status", {
									message: err ? "failed to store history" : "history stored"
								});
							}
							
							catch (err) {
								Log(err,"History load failed");
							}
					});
				});
			});

			socket.on("restore", (req,socket) => {
				const
					{client,ip,location,message} = req;

				Log("socket restore client history", req);
				sqlThread( sql => {
					sql.query("SELECT Content FROM openv.saves WHERE Client=? LIMIT 1", 
					[client],
					(err,recs) => {

						//Log("restore",err,recs);

						try {
							if ( rec = err ? null : recs[0] )
								SIO.clients[client].emit("content", {
									message: rec.Content
								});

							else
								SIO.clients[client].emit("status", {
									message: "cant restore history"
								});
						}
						
						catch (err) {
							Log(err,"History restore failed");
						}
					});
				});
			});

			socket.on("login", (req,socket) => {

				const 
					{ login, client } = req,
					[account,password] = login.split("/");
				
				//Log("login", [account,password]);

				switch ( account ) {
					case "reset":
						Login( password, function resetPassword(status) {
							Log("socket resetPassword", status);
							SIO.clients[password].emit("status", { 
								message: status,
							});
						});
						break;
				
					case "logout":
					case "logoff":
						sqlThread( sql => sql.query("UPDATE openv.profiles SET online=0 WHERE Client=?", client) );
						SIO.emit("remove", {	// broadcast client's pubKey to everyone
							client: client,
						});

						break;
						
					default:
						Login( login, function newSession(err,ses) {
							Log("socket newSession", err, ses);
							try {
								if ( err ) 
									SIO.clients[client].emit("status", { 
										message: err+"",
									});

								else {
									//sqlThread( sql => sql.query("UPDATE openv.profiles SET online=1 WHERE Client=?", account) );

									SIO.clients[client].emit("status", { 
										message: "Login completed",
										cookie: `session=${ses.id}; expires=${ses.expires.toUTCString()}; path=/`
										//passphrase: prof.SecureCom		// nonnull if account allowed to use secureLink
									});

									SIO.emit("remove", {
										client: client
									});

									SIO.emit("accept", {
										client: account,
										pubKey: ses.prof.pubKey,
									}); 
								}
							}
							
							catch (err) {
								Log(err, "Login propagation failed");
							}
					});
				}
			});
			
			socket.on("relay", (req,socket) => {
				const
					{ from,message,to,insecureok,route } = req;

				Log("socket relay", req);

				if ( message.indexOf("PGP PGP MESSAGE")>=0 ) // just relay encrypted messages
					SIO.emitOthers(from, "relay", {	// broadcast message to everyone
						message: message,
						from: from,
						to: to
					});

				else
				if ( insecureok ) 	// relay scored messages that are unencrypted
					inspect( message, to, score => {
						sqlThread( sql => {
							sql.query(
								"SELECT "
									+ "max(timestampdiff(minute,Opened,now())) AS T, "
									+ "count(ID) AS N FROM openv.sessions WHERE Client=?", 
								[from], 
								(err,recs) => {

								const 
									{N,T} = err ? {N:0,T:1} : recs[0],
									lambda = N/T;

								//Log("inspection", score, lambda, hops);

								if ( insecureok ) // if tracking permitted by client then ...
									sql.query(
										"INSERT INTO openv.relays SET ?", {
											Message: message,
											Rx: new Date(),
											From: from,
											To: to,
											New: 1,
											Score: JSON.stringify(score)
										} );

								SIO.emitOthers(from, "relay", {	// broadcast message to everyone
									message: message,
									score: Copy(score, {
										Activity:lambda, 
										Hopping:0
									}),
									from: from,
									to: to
								});
							});
						});
					});

				else 		// relay message as-is				   
					SIO.emitOthers(from, "relay", {	// broadcast message to everyone
						message: message,
						from: from,
						to: to
					});	

			});

			socket.on("announce", req => {
				Log("socket announce client", req);

				const
					{ client,pubKey } = req;

				sqlThread( sql => {
					sql.query(
						"UPDATE openv.profiles SET pubKey=?,Online=1 WHERE Client=?",
						[pubKey,client] );

					if (0)
					sql.query( "SELECT Client,pubKey FROM openv.profiles WHERE Client!=? AND length(pubKey)", [client] )
					.on("result", rec => {
						Log("##### send sync to me");
						socket.emit("sync", {	// broadcast other pubKeys to this client
							message: rec.pubKey,
							from: rec.Client,
							to: client
						});
					});
				});							

				SIO.emit("accept", {	// broadcast client's pubKey to everyone
					pubKey: pubKey,
					client: client,
				});
			});  
			
			socket.on("kill", (req,socket) => {
				Log("socket kill session", req);
				
				socket.end();
			});

		});	

		/*
		// for debugging
		SIO.on("connect_error", err => {
			Log(err);
		});

		SIO.on("disconnection", socket => {
			Log(">>DISCONNECT CLIENT");
		});	
		*/
		
		extendChallenger ( );
	},
	
}

// UNCLASSIFIED