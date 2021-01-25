/**
	Provides a form-fit-functional replacement for the notoriously buggy [Socket.IO](https://www.npmjs.com/package/socket.io) and its close cousin 
	[Socet.IO-Client](https://www.npmjs.com/package/socket.io-client).  Like its Socket.IO predecessors, SocketIO presently
	provides json-based web sockets, though it has hooks to support binary sockets (for VoIP, video, etc) applications.
	
	@requires socketio
	@requires socket.io
	@requires crypto
*/

const		// globals
	CRYPTO = require("crypto"),	
	Log = (...args) => console.log(">>>socketio",args),
	Each = ( A, cb ) => {
		Object.keys(A).forEach( key => cb( key, A[key] ) );
	};

const
	// For buggy socket.io
	//SIO = require('socket.io'), 				// Socket.io client mesh
	//SIOHUB = require('socket.io-clusterhub');  // Socket.io client mesh for multicore app
	//HUBIO = new (SIOHUB);

	// For working socketio
	SIO = require("socketio");

const {sqls} = SECLINK = module.exports = {
	
	sqlThread: () => { throw new Error("sqlThread undefined"); },
	
	sqls: {
		getProfile: "SELECT * FROM openv.profiles WHERE Client=? LIMIT 1",
		addSession: "INSERT INTO openv.sessions SET ?"
	},
	
	/**
		Establish socketio channels for the SecureIntercom link (at store,restore,login,relay,status,
		sync,join,exit,content) and the insecure dbSync link (at select,update,insert,delete).
	*/
	config: opts => {
		
		const 
			{ riddle, inspector, sqlThread, server } = opts,
			{ getProfile, addSession } = sqls;

		const
			IO = SIO(server); /*{ // socket.io defaults but can override ...
					//serveClient: true, // default true to prevent server from intercepting path
					//path: "/socket.io" // default get-url that the client-side connect issues on calling io()
				}),  */

		Log("CONIG SOCKETS AT", IO.path() );

		IO.on("connect", socket => {  	// listen to side channels 
			Log("list to side channels");

			socket.on("join", req => {	// Traps client connect when they call io()
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
									{ riddle } = TOTEM,
									N = riddle.length,
									randRiddle = (x) => riddle[rand(N)];

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
								{ riddler } = paths,
								{ Message, IDs, Retries, Timeout } = profile,
								riddles = [],
								probe = makeRiddles( Message, riddles, profile );

							Log(client, probe, riddles);

							sql.query("REPLACE INTO openv.riddles SET ?", {		// track riddle
								Riddle: riddles.join(",").replace(/ /g,""),
								Client: client,
								Made: new Date(),
								Attempts: 0,
								maxAttempts: Retries
							}, (err,info) => cb({		// send challenge to client
								message: probe,
								retries: Retries,
								timeout: Timeout,
								callback: riddler,
								passphrase: prof.SecureCom || ""
							}) );
						}

						Log(err,profs);

						if ( prof = profs[0] ) {
							if ( prof.Banned ) 
								socket.emit("exit", {
									message: `${client} banned: ${prof.Banned}`
								});

							else
							if ( prof.Challenge && riddle.length )	// must solve challenge to enter
								getChallenge(prof, challenge => {
									Log(challenge);
									socket.emit("challenge", challenge);
								});

							else
							if ( prof.SecureCom )	// allowed to use secure link
								socket.emit("secure", {
									message: `Welcome ${client}`,
									passphrase: prof.SecureCom
								});

							else		// not allowed to use secure link
								socket.emit("status", {
									message: `Welcome ${client}`
								});
						}

						else
							socket.emit("exit", {
								message: `Cant find ${client}`
							});

					});
				}); 
			});

			socket.on("store", req => {
				const
					{client,ip,location,message} = req;

				Log("store client history", req);

				sqlThread( sql => {
					sql.query(
						"INSERT INTO openv.saves SET ? ON DUPLICATE KEY UPDATE Content=?", 
						[{Client: client,Content:message}, message],
						err => {

							socket.emit("status", {
								message: err ? "store failed" : "store completed"
							});
					});
				});
			});

			socket.on("restore", req => {
				const
					{client,ip,location,message} = req;

				Log("restore client history", req);
				sqlThread( sql => {
					sql.query("SELECT Content FROM openv.saves WHERE Client=? LIMIT 1", 
					[client],
					(err,recs) => {

						Log("restore",err,recs);

						if ( rec = recs[0] )
							socket.emit("content", {
								message: rec.Content
							});

						else
							socket.emit("status", {
								message: "cant restore content"
							});
					});
				});
			});

			socket.on("relay", req => {
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

			socket.on("login", req => {
				Log("login client", req);

				const
					{ client,pubKey } = req;

				sqlThread( sql => {
					sql.query(
						"UPDATE openv.profiles SET pubKey=? WHERE Client=?",
						[pubKey,client] );

					sql.query( "SELECT Client,pubKey FROM openv.profiles WHERE Client!=? AND length(pubKey)", [client] )
					.on("result", rec => {
						socket.emit("sync", {	// broadcast other pubKeys to this client
							message: rec.pubKey,
							from: rec.Client,
							to: client
						});
					});
				});							

				IO.emit("sync", {	// broadcast client's pubKey to everyone
					message: pubKey,
					from: client,
					to: "all"
				});
			});

		});	

		// for debugging
		IO.on("connect_error", err => {
			Log(err);
		});

		IO.on("disconnection", socket => {
			Log(">>DISCONNECT CLIENT");
		});			
	},
	
}

