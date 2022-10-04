// UNCLASSIFIED

/**
Provides a private (end-to-end encrypted) message link between trusted clients and secure logins. 

This module documented in accordance with [jsdoc]{@link https://jsdoc.app/}.

## Env Dependencies
									  
	LINK_PASS = passphrase to encrypt user passwords ["securePass"]
	LINK_HOST = name of secure link host ["secureHost"]
									  
@module SECLINK
@author [ACMESDS](https://totemstan.github.io)

@requires [enums](https://www.npmjs.com/package/@totemstan/enums) 
@requires [socketio](https://www.npmjs.com/package/@totemstan/socketio)

@requires [socket.io](https://www.npmjs.com/package/socket.io)
@requires [crypto](https://nodejs.org/docs/latest/api/)

@example

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
	SOCKETIO = require("@totemstan/socketio"),
	{ Copy, Each, Start, Log } = require("@totemstan/enums");

const { sqls, Trace, Login, errors } = SECLINK = module.exports = {
	
	Trace: (msg, ...args) => `sio>>>${msg}`.trace( args ),
		
	sqlThread: () => { throw new Error("sqlThread not configured"); },
	
	server: null,	// established on config
	sio: null,		// established on config
	
	sqls: {
		//addProfile: "INSERT INTO openv.profiles SET ?",
		getProfile: "SELECT * FROM openv.profiles WHERE Client=? LIMIT 1",
		
		//getSession: "SELECT * FROM openv.profiles WHERE SessionID=? LIMIT 1",
		addSession: "INSERT INTO openv.sessions SET ? ON DUPLICATE KEY UPDATE Count=Count+1,?",
		endSession: "SELECT max(timestampdiff(minute,Opened,now())) AS T, count(ID) AS N FROM openv.sessions WHERE Client=?", 

		getRiddle: "SELECT * FROM openv.riddles WHERE ? LIMIT 1",
		
		getAccount:	"SELECT *,aes_decrypt(unhex(Password),?) AS Password, hex(aes_encrypt(ID,?)) AS SessionID FROM openv.profiles WHERE Client=?", 
		addAccount:	"INSERT INTO openv.profiles SET ?,Password=hex(aes_encrypt(?,?)),SecureCom=if(?,concat(Client,':',Password),'')", 
		setPassword: "UPDATE openv.profiles SET Password=hex(aes_encrypt(?,?)), SecureCom=if(?,concat(Client,':',Password),'') WHERE Client=?",
		getToken: "SELECT Client FROM openv.profiles WHERE TokenID=? AND Expires>now()", 
		addToken: "UPDATE openv.profiles SET TokenID=? WHERE Client=?"
		//addSession: "UPDATE openv.profiles SET SessionID=? WHERE Client=?",
		//endSession: "UPDATE openv.profiles SET SessionID=null WHERE Client=?",		
	},
	
	// config options
	
	notify: opts => {},
	
	guest: null,		// guest profile - guesting disabled by default
	
	/**
	Domain name of host for attributing domain-owned accounts.
	*/
	host: ENV.LINK_HOST || "secureHost",
			
	challenge: {	//< for antibot client challenger 
		extend: 0,
		store: [],
		checkEndpoint: "/riddle",
		captchaEndpoint: "/captchaEndpoint",
		map: []
	},
	
	inspect: (doc,to,cb) => { 
		// throw new Error("securelink inspect not configured"); 
	},
	
	/**
	Test if an account is "trusted" to use the secure com channel.
	*/
	
	isTrusted: account => account.endsWith("@"+SECLINK.host),

	expireTemp: [5,10],
	expirePerm: [365,0],
	expirePass: [1,0],
	
	errors: {
		loginBlocked: new Error("account blocked"),
		noGuests: new Error("guests blocked"),
		userOnline: new Error( "account already online" ),
		userExpired: new Error( "account expired" ),
		resetFailed: new Error("password could not be reset at this time"),
		//resetOk: new Error("password reset"),
		badPass: new Error("password not complex enough"),
		badLogin: new Error("bad login"),
		nonGuest: new Error("must be guest"),
		userPending: new Error("account verification pending -- see email")
	},
	
	/**
	Start a secure link and return the user profile corresponding for the supplied 
	account/password login.  The provided callback LOGIN(err,profile) where LOGIN =  
	resetPassword || newAccount || newSession || guestSession determines the login session
	type being requested.

	@cfg {Function}
	@param {String} login account/password credentials
	@param {Function} cb callback (err,profile) to process the session 
	*/
	
	Login: (login,cb) => {
		function passwordOk( pass ) {
			return (pass.length >= passwordLen);
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
			
			if ( guest ) {	// guest profiles allowed
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
					if (err) Trace("add acct", err, info, prof);
					cb( err ? null : prof );
				});
			}
			
			else {
				Trace("Guest accounts disabled");
				cb( null );
			}
		}

		/*
		function genSession( sql, account, cb ) {
			genCode(sessionLen, id => {
				sql.query(
					addSession, 
					[id,account], err => {

						if ( err )	// has to be unqiue
							genSession( sql, account, cb );

						else 
							cb( id, getExpires(expirePass) );
				});
			});
		}
		*/

		/*
		function genGuest( sql, account, expires, cb ) {
			genCode(accountLen, code => {
				//Trace("gen guest", code);
				newAccount( sql, `guest${code}@${host}`, password, expires, (err,prof) => {
					Trace("made account", prof);
					if ( !err )
						cb( prof );

					else 
						genGuest( sql, account, expires, cb );
				});
			});
		}  */

		/*
		function genToken( sql, account, cb ) {
			genCode(tokenLen, token => {
				sql.query( addToken, [ token, account], err => {
					if ( err )	// retry until token is unique
						genToken( sql, account, cb );

					else 	// relay unique token
						cb( token, getExpires(expirePass) );
				});
			});
		}*/

		function getProfile( sql, account, cb ) {
			//Trace("get profile", account, host);
			sql.query( getAccount, [encryptionPassword, encryptionPassword, account], (err,profs) => {		

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
			{ getAccount, addAccount, addToken, getToken, setPassword } = sqls,
			encryptionPassword = ENV.LINK_PASS || "securePass",
			allowSecureConnect = true,
			[account,password] = login.split("/"),
			isGuest = account.startsWith("guest") && account.endsWith(host);
		
		Trace("login", cb.name, `${account}/${password}`);
		
		sqlThread( sql => {
			switch ( cb.name ) {
				case "resetPassword":		// host requesting a password reset
					getProfile( sql, account, prof => {
						if ( prof )	{	// have a valid user login
							if ( passwordOk(password) )
								sql.query( setPassword, [password, encryptionPassword, allowSecureConnect, account], err => {
									Trace("setpass", account, password);
									cb( err ? errors.resetFailed : null, prof );
								});

							else
								cb( errors.badPass );						
								/*genToken( sql, account, (token,expires) => {	// gen a token account			
									cb( errors.userPending );

									notify({
										to: account,
										subject: "Totem password reset request",
										text: `Please login using ${token}/NEWPASSWORD by ${expires}`
									});
								});  */
						}
						
						else
							cb( errors.badLogin );
					});

					break;

				case "newAccount": 			// host requesting a new account
					if ( true )			// only guests can request a new account
						genPassword( password => {
							//Trace("gen", account, password);
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
						cb( errors.nonGuest );

					break;

				case "newSession":			// host requesting an authorized session 
				case "loginSession":
				case "authSession":
					
					getProfile( sql, account, prof => {
						if ( prof )	{	// have a valid user login
							//Trace(password, prof);
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

							/*
							else
							if ( prof.TokenID ) 	// password reset pending
								if ( passwordOk(password) )
									sql.query( setPassword, [password, encryptionPassword, allowSecureConnect, account], err => {
										Trace("setpass", account, password);
										cb( err ? errors.resetFailed : errors.resetOk );
									});

								else
									cb( errors.badPass );
							*/
							
							else
							if (password == prof.Password)		// validate login
								cb(null, prof);
								/*genSession( sql, account, (sessionID,expires) => cb(null, Copy({
									sessionID: sessionID, 
									expires: expires
								}, prof ) ));*/

							else
								cb( errors.badLogin );
						}
						
						else
							cb( errors.badLogin );
					});
					
					break;

				case "guestSession":		// host requesting a guest session
				case "noauthSession":
				default:
					
					getProfile( sql, account, prof => {
						//Trace("getprof", prof);
						if ( prof ) 
							if ( prof.Banned ) 
								cb(	new Error(prof.Banned) );	
							
							else
								cb( null, prof );
						
						else
							newAccount( sql, account, "", prof => {
								Trace("newacct", prof);
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
	@param {String} client name of client being challenged
	@param {String} guess guess provided by client
	@param {Function} res response callback( "pass" || "fail" || "retry" )
	*/
	testClient: (client,guess,res) => {
			
		const
			{ sqlThread } = SECLINK,
			{ getRiddle }= sqls;
		
		if ( getRiddle ) 
			sqlThread( sql => {
				sql.query(getRiddle, {Client:client}, (err,recs) => {

					if ( rec = recs[0] ) {
						const 
							ID = {Client:rec.ID},
							Guess = (guess+"").replace(/ /g,"");

						Trace("riddle",rec);

						if (rec.Riddle == Guess) {
							res( "pass" );
							sql.query("DELETE FROM openv.riddles WHERE ?",ID);
						}
						else
						if (rec.Attempts > rec.maxAttempts) {
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
				{ store, extend, map, captchaEndpoint } = challenge,
				{ floor, random } = Math;

			Trace( `Adding ${extend} challenges at ${captchaEndpoint}` );

			if ( captchaEndpoint )
				for (var n=0; n<extend; n++) {
					var 
						Q = {
							x: floor(random()*10),
							y: floor(random()*10),
							z: floor(random()*10),
							n: floor(random()*map["0"].length)
						},

						A = {
							x: "".tag("img", {src: `${captchaEndpoint}/${Q.x}/${map[Q.x][Q.n]}.jpg`}),
							y: "".tag("img", {src: `${captchaEndpoint}/${Q.y}/${map[Q.y][Q.n]}.jpg`}),
							z: "".tag("img", {src: `${captchaEndpoint}/${Q.z}/${map[Q.z][Q.n]}.jpg`})
						};

					store.push( {
						Q: `${A.x} * ${A.y} + ${A.z}`,
						A: Q.x * Q.y + Q.z
					} );
				}

			//Trace(store);
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

		Trace("config socketio");

		if (guest) {
			delete guest.ID;
			delete guest.SecureCom;
			delete guest.Password;
		}
		
		SIO.on("connect", socket => {  	// define socket listeners when client calls the socketio-client io()
			Trace("listening to sockets");

			socket.on("join", (req,socket) => {	// Traps client connect when client emits "join" request
				const
					{client,message,insecureok} = req;

				Trace("channel>>>join admit client");
				sqlThread( sql => {

					if ( addSession ) {	// log sessions if allowed
						const log = {
							Opened: new Date(),
							Client: client,
							Location: req.location,
							IPclient: req.ip,
							Agent: req.agent,
							Platform: req.platform
						};
						sql.query( addSession, [log,log] );
					}
					
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
							function makeChallenge () { 
								const
									{ floor, random } = Math,
									rand = N => floor( random() * N ),
									N = store.length,
									randRiddle = () => store[rand(N)];
								
								return N ? randRiddle() : {Q:"1+0", A:"1"};
							}

							const
								{ checkEndpoint, store } = challenge,
								{ Message, Retries, Timeout } = profile,
								{ Q,A } = makeChallenge( );

							///Trace("genriddle", client, [Q,A]);

							sql.query("REPLACE INTO openv.riddles SET ?", {		// track riddle
								Riddle: A,
								Client: client,
								Made: new Date(),
								Attempts: 0,
								maxAttempts: Retries
							}, (err,info) => cb({		// send challenge to client
								message: "??"+(Message||"What is: ")+Q,
								retries: Retries,
								timeout: Timeout,
								callback: checkEndpoint,
								//passphrase: prof.SecureCom || ""
							}) );
						}

						function getOnline( cb) {
							const 
								keys = {};

							sql.query("SELECT Client,pubKey FROM openv.profiles WHERE Online")
							.on("result", rec => keys[rec.Client] = rec.pubKey )
							.on("end", () => cb( keys ) );
						}
						
						//Trace(err,profs);

						try {
							if ( prof = profs[0] ) {
								const 
									{ Banned, SecureCom, Challenge } = prof;
								
								if ( Banned ) 
									SIO.clients[client].emit("status", {
										message: `${client} banned: ${Banned}`
									});

								else
								if ( SecureCom )	// allowed to use secure link
									if ( Challenge )	// must solve challenge to enter
										getChallenge( prof, riddle => {
											Trace("challenge", riddle);
											//socket.emit("challenge", riddle);
											getOnline( pubKeys => {
												riddle.pubKeys = pubKeys;
												riddle.passphrase = SecureCom;
												SIO.clients[client].emit("start", riddle);
											});
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

								else		// cant use secure link
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
							Trace(err,"join failed");
						}
					});
				}); 
			});

			socket.on("store", (req,socket) => {
				const
					{client,ip,location,message} = req;

				Trace("channel>>>store client history");

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
								Trace(err,"History load failed");
							}
					});
				});
			});

			socket.on("restore", (req,socket) => {
				const
					{client,ip,location,message} = req;

				Trace("channel>>>restore client history");
				sqlThread( sql => {
					sql.query("SELECT Content FROM openv.saves WHERE Client=? LIMIT 1", 
					[client],
					(err,recs) => {

						//Trace("restore",err,recs);

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
							Trace(err,"History restore failed");
						}
					});
				});
			});

			socket.on("login", (req,socket) => {

				const 
					{ login, client } = req,
					[account,password,reset] = login.split("/");
				
				Trace("channel>>>login client", `${client}/${account}/${password}` );

				if ( account )
					switch ( account ) {
						/*
						case "reset":
							Login( password, function resetPassword(status) {
								Trace("socket resetPassword", status);
								SIO.clients[password].emit("status", { 
									message: status,
								});
							});
							break;
						*/
							
						case "logout":
						case "logoff":
							sqlThread( sql => sql.query("UPDATE openv.profiles SET online=0 WHERE Client=?", client) );
							SIO.emit("remove", {	// broadcast client's pubKey to everyone
								client: client,
							});

							break;

						default:
							if ( password )
								if ( reset ) 
									Login( login, function resetPassword(err,prof) {
										Trace("socket resetPassword", err);
										SIO.clients[client].emit("status", { 
											message: err ? "Password reset failed" : "Password reset",
										});
									});
							
								else
									Login( login, function newSession(err,prof) {
										Trace("socket newSession", err, prof);
										try {
											if ( err ) 
												SIO.clients[client].emit("status", { // return error msg to client
													message: err+"",
												});

											else {
												sqlThread( sql => sql.query("UPDATE openv.profiles SET online=1 WHERE Client=?", account) );

												SIO.clients[client].emit("status", { 	// return login ok msg to client with convenience cookie
													message: "Login completed",
													cookie: `session=${prof.Client}; expires=${prof.Expires.toUTCString()}; path=/`
													//passphrase: prof.SecureCom		// nonnull if account allowed to use secureLink
												});

												SIO.emit("remove", {	// remove old client then
													client: client
												});

												SIO.emit("accept", {	// accept new client
													client: account,
													pubKey: prof.pubKey,
												}); 
											}
										}

										catch (err) {
											Trace(err, "Login failed");
										}
									});

							else
								Login( login, function newAccount(err,prof) {
									Trace("socket newAccount", err, prof);
									try {
										if ( err ) 
											SIO.clients[client].emit("status", { // return error msg to client
												message: err+"",
											});

										else
											SIO.clients[client].emit("status", { 	// return login ok msg to client with convenience cookie
												message: "Account requested",
												//cookie: `session=${prof.Client}; expires=${prof.Expires.toUTCString()}; path=/`
												//passphrase: prof.SecureCom		// nonnull if account allowed to use secureLink
											});		
									}
									
									catch (err) {
										Trace(err, "Login failed");
									}
								});
					}
				
				else
					SIO.clients[client].emit("status", { // return error msg to client
						message: "invalid login credentials",
					});					
			});
			
			socket.on("relay", (req,socket) => {
				const
					{ from,message,to,insecureok,route } = req,
					{ endSessions } = sqls;

				Trace("channel>>>relay", req);

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
							sql.query( endSession, [from], (err,recs) => {
								const 
									{N,T} = err ? {N:0,T:1} : recs[0],
									lambda = N/T;

								//Trace("inspection", score, lambda, hops);

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
				Trace("channel>>>announce client");

				const
					{ client,pubKey } = req;

				sqlThread( sql => {
					sql.query(
						"UPDATE openv.profiles SET pubKey=?,Online=1 WHERE Client=?",
						[pubKey,client] );

					if (0)
					sql.query( "SELECT Client,pubKey FROM openv.profiles WHERE Client!=? AND length(pubKey)", [client] )
					.on("result", rec => {
						Trace("send sync to me");
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
				Trace("channel>>>kill session");
				
				socket.end();
			});

		});	

		/*
		// for debugging
		SIO.on("connect_error", err => {
			Trace(err);
		});

		SIO.on("disconnection", socket => {
			Trace(">>DISCONNECT CLIENT");
		});	
		*/
		
		extendChallenger ( );
		
		return SECLINK;
	},
	
}

Start("securelink", {
	ctx: SECLINK
});

// UNCLASSIFIED