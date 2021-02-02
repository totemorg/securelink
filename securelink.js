/**
	@module SECLINK
	
	[secureLink](https://github.com/totemstan/securelink.git) provides a form-fit-functional replacement for the 
	notoriously buggy [Socket.IO](https://www.npmjs.com/package/socket.io) and its close cousin 
	[Socet.IO-Client](https://www.npmjs.com/package/socket.io-client).  
	
	@requires socketio
	@requires socket.io
	@requires crypto
*/

const		// globals
	ENV = process.env,
	CRYPTO = require("crypto");	

const
	// For buggy socket.io
	//SIO = require('socket.io'), 				// Socket.io client mesh
	//SIOHUB = require('socket.io-clusterhub');  // Socket.io client mesh for multicore app
	//HUBIO = new (SIOHUB);

	// For working socketio
	SIO = require("socketio");

const { sqls, Each, Copy, Log, Login } = SECLINK = module.exports = {
	
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
	
	sqlThread: () => { throw new Error("no sqlThread"); },
	
	sendMail: opts => Log("no sendMail", opts),
	
	challenge: {	//< for antibot client challenger 
		extend: 0,
		store: [],
		riddler: "/riddle",
		captcha: "/captcha",
		map: []
	},
	
	server: null,
	
	inspector: (doc,to,cb) => { throw new Error("inspector() not configured"); },
	
	sqls: {
		addProfile: "INSERT INTO openv.profiles SET ?",
		getProfile: "SELECT * FROM openv.profiles WHERE Client=? LIMIT 1",
		addSession: "INSERT INTO openv.sessions SET ?",
		getRiddle: "SELECT * FROM openv.riddles WHERE ? LIMIT 1",
		
		getAccount:	"SELECT pubKey, Trusted, validEmail, Banned, aes_decrypt(unhex(Password),?) AS Password, SecureCom FROM openv.profiles WHERE Client=?", 
		addAccount:	"INSERT INTO openv.profiles SET ?,Password=hex(aes_encrypt(?,?)),SecureCom=if(?,concat(Client,Password),'')", 
		setPassword: "UPDATE openv.profiles SET Password=hex(aes_encrypt(?,?)), SecureCom=if(?,concat(Client,Password),''), SessionID=null WHERE SessionID=?",
		//getToken: "SELECT Client FROM openv.profiles WHERE TokenID=? AND Expires>now()", 
		//addToken: "UPDATE openv.profiles SET TokenID=? WHERE Client=?",
		getSession: "SELECT * FROM openv.profiles WHERE SessionID=? AND Expires>now() LIMIT 1",
		addSession: "UPDATE openv.profiles SET Online=1, SessionID=? WHERE Client=?",
		endSession: "UPDATE openv.profiles SET Online=0, SessionID=null WHERE Client=?",		
	},
	
	isTrusted: account => true,
	
	Login: (account,password,cb) => {
		function passwordOk(pass) {
			return (pass.length >= 4);
		}

		function accountOk(acct) {
			const
				banned = {
					"tempail.com": 1,
					"temp-mail.io":1,
					"anonymmail.net":1,
					"mail.tm": 1,
					"tempmail.ninja":1,
					"getnada.com":1,
					"protonmail.com":1,
					"maildrop.cc":1,
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
			genCode(passwordLen, code => cb(code, getExpires(expireSession)) );
		}

		function genCode ( len, cb ) {
			return CRYPTO.randomBytes( len/2, (err, code) => cb( code.toString("hex") ) );
		}

		function newAccount( sql, account, password, expires, cb) {
			const
				trust = isTrusted( account );

			sql.query(
				addAccount,
				[ prof = {
					Banned: "",  // nonempty to ban user
					QoS: 10,  // [secs] job regulation interval
					Credit: 100,  // job cred its
					Charge: 0,	// current job charges
					LikeUs: 0,	// number of user likeus
					Trusted: trust,
					Expires: expires,
					//Password: "",	
					//SecureCom: trust ? account : "",	// default securecom passphrase
					Challenge: !trust,		// enable to challenge user at session join
					Client: account,
					User: "",		// default user ID (reserved for login)
					Login: "",	// existing login ID
					Group: "app",		// default group name (db to access)
					Repoll: true,	// challenge repoll during active sessions
					Retries: 5,		// challenge number of retrys before session killed
					Timeout: 30,	// challenge timeout in secs
					Message: `What is #riddle?`		// challenge message with riddles, ids, etc					Expires: getExpires( trust ? expireGuest : expirePerm ),
				},  password, encryptionPassword, allowSecureConnect ], 	
				(err,info) => {
					//Log(err,prof);
					Log("gen",err,account);
					cb(err ? null : prof);
				});
		}

		function genSession ( sql, account, cb ) {
			genCode(sessionLen, code => {
				sql.query(
					addSession, 
					[code,account], err => {

						if ( err )	// has to be unqiue
							genSession( sql, account, cb );

						else cb( code, getExpires(expireSession) );
				});
			});
		}

		function genGuest( sql, password, expires, cb ) {
			genCode(accountLen, code => {
				//Log("gen guest", code);
				newAccount( sql, "guest"+code+"@totem.org", password, expires, prof => {
					//Log("madeacct", prof);
					if ( prof )
						cb( prof );

					else 
						genGuest( sql, password, expires, cb );
				});
			});
		}

		function genToken( sql, account, cb ) {
			genCode(tokenLen, code => {
				sql.query(
					addSession, 
					["reset"+code,account], err => {

						if ( err )	// has to be unqiue
							genToken( sql, account, cb );

						else cb( code, getExpires(expireSession) );
				});
			});
		}

		const
			expireGuest = [5,10],
			expirePerm = [365,0],
			expireSession = [1,0];

		const
			passwordPostfixLength = 4,
			passwordLen = 4,
			accountLen = 16,
			sessionLen = 32,
			tokenLen = 4;

		const
			{ isTrusted } = SECLINK,
			{ addProfile, getAccount, addAccount, getSession, addSession, endSession, setPassword } = sqls,
			encryptionPassword = ENV.USERS_PASS,
			allowSecureConnect = true;	
		
		Log("login",[account,password]);
		
		sqlThread( sql => {
			if ( cb.name == "resetPassword" ) 
				genToken( sql, account, (tokenAccount,expires) => {	// gen a token account						
					cb( `See your ${account} email for further instructions` );

					sendMail({
						to: account,
						subject: "Totem password reset request",
						text: `Please login using !!${tokenAccount}/NEWPASSWORD by ${expires}`
					});
				});
			
			else
				sql.query(
					getSession, 
					[account], (err,profs) => {		// try to locate client by sessionID
						if ( prof = profs[0] ) {
							if ( account.startsWith("reset") )
								if ( passwordOk(password) )
									sql.query( setPassword, [password, encryptionPassword, allowSecureConnect, account], err => {
										Log("password reset", err);
										if ( err ) 
											cb( new Error( "Your password could not be reset at this time" ) );

										else
											cb( new Error( `You may login to ${prof.Client} using your new password.` ) );
									});

								else
									cb( new Error( "password not complex enough" ) );

							else
								cb( null, prof );
						}
						
						else	// not a session - try account
						if ( account && getAccount )	// locate account by name
							sql.query( getAccount, [encryptionPassword,account], (err,profs) => {		

								if ( prof = profs[0] ) {			// account located
									if ( prof.Banned ) 				// account was banned for some reason
										cb(	new Error(prof.Banned) );

									else
									if ( prof.Online ) 				// account already online
										cb( new Error( "account online" ) );

									else
									if ( prof.Expires < new Date() )		// account expired
										cb( new Error( "account expired" ) );

									else
									if (password == prof.Password)	// account matched
										switch (cb.name) {
											case "newSession":
												genSession( sql, account, (sessionID,expires) => cb({
													id: sessionID, 
													expires: expires, 
													profile: prof
												}) );
												break;

											default:
												cb( null, prof );
										}

									else
										cb( new Error( "bad account/password" ) );
								}

								else
									cb( new Error("account not found") );
							});

						else 
						if ( addAccount ) 				// allowing guest accounts
							genGuest( sql, "", getExpires(expireGuest), prof => cb(null, prof) );

						else
							cb( new Error("login failed") );
				});				
		});
	},
	
	testClient: (client,guess,res) => {
			
		const
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

			Log( `extend imageset=${captcha} extend=${extend}` );

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
			{ inspector, sqlThread, sendMail, server, challenge } = Copy( opts, SECLINK, "." ),
			{ getProfile, addSession } = sqls;

		const
			IO = TOTEM.IO = SIO(server); /*{ // socket.io defaults but can override ...
					//serveClient: true, // default true to prevent server from intercepting path
					//path: "/socket.io" // default get-url that the client-side connect issues on calling io()
				}),  */

		Log("config socketio", IO.path() );

		IO.on("connect", socket => {  	// define side channel listeners 
			Log("listening to side channels");

			socket.on("join", (req,socket) => {	// Traps client connect when they call io()
				Log("admit client", req);
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
							@param {Object} profile with a .Message riddle mask and a .IDs = {key:value, ...}
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

								return msg
										.parse$(prof)
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
							}

							const
								{ riddler, store } = challenge,
								{ Message, IDs, Retries, Timeout } = profile,
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

						//Log(err,profs);

						if ( prof = profs[0] ) {
							if ( prof.Banned ) 
								socket.emit("exit", {
									message: `${client} banned: ${prof.Banned}`
								});

							else
							if ( prof.SecureCom )	// allowed to use secure link
								if ( prof.Challenge )	// must solve challenge to enter
									getChallenge(prof, riddle => {
										Log("challenge", riddle);
										//socket.emit("challenge", riddle);
										socket.emit("start", riddle);
									});
							
								else
									socket.emit("start", {
										message: `Welcome ${client}`,
										passphrase: prof.SecureCom
									});

							else		// not allowed to use secure link
								socket.emit("start", {
									message: `Welcome ${client}`,
									passphrase: ""
								});
						}

						else
							socket.emit("exit", {
								message: `Cant find ${client}`
							});

					});
				}); 
			});

			socket.on("store", (req,socket) => {
				const
					{client,ip,location,message} = req;

				Log("store client history", req);

				sqlThread( sql => {
					sql.query(
						"INSERT INTO openv.saves SET ? ON DUPLICATE KEY UPDATE Content=?", 
						[{Client: client,Content:message}, message],
						err => {

							socket.emit("status", {
								message: err ? "failed to store history" : "history stored"
							});
					});
				});
			});

			socket.on("restore", (req,socket) => {
				const
					{client,ip,location,message} = req;

				Log("restore client history", req);
				sqlThread( sql => {
					sql.query("SELECT Content FROM openv.saves WHERE Client=? LIMIT 1", 
					[client],
					(err,recs) => {

						Log("restore",err,recs);

						if ( rec = err ? null : recs[0] )
							socket.emit("content", {
								message: rec.Content
							});

						else
							socket.emit("status", {
								message: "cant restore history"
							});
					});
				});
			});

			socket.on("login", (req,socket) => {

				const 
					{ account, password, client } = req;
				
				Log("login", [account,password]);

				if ( password == "reset" )
					Login( client, "", function resetPassword(status) {
						Log("pswd reset", status);
						socket.emit("status", { 
							message: status,
						});
					});
				
				else
					Login( account, password || "", function newSession(ses) {
						Log("session", ses);
						socket.emit("status", { 
							message: "Login completed",
							client: account,
							cookie: `session=${ses.id}; expires=${ses.expires.toUTCString()}`,
							passphrase: ses.profile.SecureCom		// nonnull if account allowed to use secureLink
						});

					IO.emit("remove", {
						client: client
					});

					IO.emit("accept", {
						client: account,
						pubKey: prof.pubKey,
					}); 
				});
			});
			
			socket.on("relay", (req,socket) => {
				const
					{ from,message,to,insecureok,route } = req;

				Log("relay message", req);

				if ( message.indexOf("PGP PGP MESSAGE")>=0 ) // just relay encrypted messages
					IO.emit("relay", {	// broadcast message to everyone
						message: message,
						from: from,
						to: to
					});

				else
				if ( inspector && insecureok ) 	// relay scored messages that are unencrypted
					inspector( message, to, score => {
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

								IO.emit("relay", {	// broadcast message to everyone
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
					IO.emit("relay", {	// broadcast message to everyone
						message: message,
						from: from,
						to: to
					});	

			});

			/*
			socket.on("enter", req => {
				Log("enter client", req);

				const
					{ client,pubKey } = req;

				sqlThread( sql => {
					sql.query(
						"UPDATE openv.profiles SET pubKey=? WHERE Client=?",
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

				/ *IO.emit("sync", {	// broadcast client's pubKey to everyone
					message: pubKey,
					from: client,
					to: "all"
				}); * /
				IO.emit("accept", {	// broadcast client's pubKey to everyone
					pubKey: pubKey,
					client: client,
				});
				socket.emit("accept", {	// broadcast client's pubKey to everyone
					pubKey: pubKey,
					client: client,
				});
			});  */
			
			socket.on("kill", (req,socket) => {
				Log("kill", req);
				
				socket.end();
			});

		});	

		// for debugging
		IO.on("connect_error", err => {
			Log(err);
		});

		IO.on("disconnection", socket => {
			Log(">>DISCONNECT CLIENT");
		});	
		
		extendChallenger ( );
	},
	
}



