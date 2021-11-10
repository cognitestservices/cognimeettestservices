/*
http://patorjk.com/software/taag/#p=display&f=ANSI%20Regular&t=Server

███████ ███████ ██████  ██    ██ ███████ ██████  
██      ██      ██   ██ ██    ██ ██      ██   ██ 
███████ █████   ██████  ██    ██ █████   ██████  
     ██ ██      ██   ██  ██  ██  ██      ██   ██ 
███████ ███████ ██   ██   ████   ███████ ██   ██                                           

dependencies: {
    compression : https://www.npmjs.com/package/compression
    dotenv      : https://www.npmjs.com/package/dotenv
    express     : https://www.npmjs.com/package/express
    ngrok       : https://www.npmjs.com/package/ngrok
    socket.io   : https://www.npmjs.com/package/socket.io
    swagger     : https://www.npmjs.com/package/swagger-ui-express
    yamljs      : https://www.npmjs.com/package/yamljs
}

*/

'use strict'; // https://www.w3schools.com/js/js_strict.asp
const { exec } = require("child_process");


require('dotenv').config();
var express = require("express");
var	mongoose = require("mongoose");

var	passport = require("passport");
var	bodyParser = require("body-parser");
var	LocalStrategy = require('passport-local').Strategy;
var	passportLocalMongoose =require("passport-local-mongoose");
	//User = require("./models/user"); 
var path = require('path');
var favicon = require('static-favicon');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var session = require('express-session')
var nodemailer = require('nodemailer');
var bcrypt = require('bcrypt-nodejs');
var async = require('async');
var crypto = require('crypto');
var flash = require('express-flash');

//newly added code for all users (only admin later) changing bg for all users
var fs = require('fs');

/* Renaming or coping the image file */
//var inStr = fs.createReadStream('www/images/2d Backgrounds/bg4.jpg');
//var outStr = fs.createWriteStream('www/images/defaultbg/defaultbg.jpg');
//inStr.pipe(outStr);
//------------ till here----------------//


passport.use(new LocalStrategy(function(username, password, done) {
    User.findOne({ username: username }, function(err, user) {
      if (err) return done(err);
      if (!user) return done(null, false, { message: 'Incorrect username.' });
      user.comparePassword(password, function(err, isMatch) {
        if (isMatch) {
          return done(null, user);
        } else {
          return done(null, false, { message: 'Incorrect password.' });
        }
      });
    });
  }));
  
  passport.serializeUser(function(user, done) {
    done(null, user.id);
  });
  
  passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      done(err, user);
    });
  });
  
  var userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    resetPasswordToken: String,
    resetPasswordExpires: Date
  });
  
  userSchema.pre('save', function(next) {
    var user = this;
    var SALT_FACTOR = 5;
  
    if (!user.isModified('password')) return next();
  
    bcrypt.genSalt(SALT_FACTOR, function(err, salt) {
      if (err) return next(err);
  
      bcrypt.hash(user.password, salt, null, function(err, hash) {
        if (err) return next(err);
        user.password = hash;
        next();
      });
    });
  });
  
  userSchema.methods.comparePassword = function(candidatePassword, cb) {
    bcrypt.compare(candidatePassword, this.password, function(err, isMatch) {
      if (err) return cb(err);
      cb(null, isMatch);
    });
  };
  
var User = mongoose.model('User', userSchema);
//mongoose.connect(url, { useNewUrlParser: true, autoIndex: false })
//var url = process.env.CUSTOMCONNSTR_MyConnectionString
//console.log(url)
mongoose.connect("mongodb://cosmos-db-one:H0aKuJeoXL7Pk56w2F0MbDGHUcudoMffF01iFSF7iVH2wodaK0nYvsNqaXLrHb1KFMXz6h4yUgVna6GUTnETkA==@cosmos-db-one.mongo.cosmos.azure.com:10255/?ssl=true&replicaSet=globaldb&retrywrites=false&maxIdleTimeMS=120000&appName=@cosmos-db-one@", { useNewUrlParser: true, autoIndex: false }) //hope this will not shown the deprecation warning
//mongoose.connect(process.env.CUSTOMCONNSTR_MyConnectionString || "mongodb://localhost/password_ejs_v2_demo_app");
//mongoose.connect("mongodb://localhost:27017/password_ejs_v2_demo_app?readPreference=primary&appname=MongoDB%20Compass&directConnection=true&ssl=false");

/*
// Connect to MongoDB
mongoose
  .connect(
    'mongodb://mongo:27017/docker-node-mongo',
    { useNewUrlParser: true }
  )
  .then(() => console.log('MongoDB Connected'))
  .catch(err => console.log(err));
*/

const compression = require('compression');


const app = express();
/*
var cors = require('cors');
app.options('*', cors()) // include before other routes
//app.use(cors());
*/


app.use(compression()); // Compress all HTTP responses using GZip

// Middleware
app.set('port', process.env.PORT || 7500);
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
app.use(favicon());
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded());
app.use(cookieParser());
app.use(session({ secret: 'session secret key' }));
app.use(flash());
app.use(passport.initialize());
app.use(passport.session());


const http = require('http');
const server = http.createServer(app);
const { Server } = require('socket.io');
const io = new Server().listen(server);
//const ngrok = require('ngrok');
const yamlJS = require('yamljs');
const swaggerUi = require('swagger-ui-express');
const swaggerDocument = yamlJS.load(__dirname + '/api/swagger.yaml');

const port = process.env.PORT || 7500; // must be the same to client.js signalingServerPort

const localHost = 'http://localhost:' + port; // http
const apiBasePath = '/api/v1'; // api endpoint path
const api_docs = localHost + apiBasePath + '/docs'; // api docs
const api_key_secret = process.env.API_KEY_SECRET || 'mirotalk_default_secret';
const ngrokEnabled = process.env.NGROK_ENABLED;
const ngrokAuthToken = process.env.NGROK_AUTH_TOKEN;
const turnEnabled = process.env.TURN_ENABLED;
const turnUrls = process.env.TURN_URLS;
const turnUsername = process.env.TURN_USERNAME;
const turnCredential = process.env.TURN_PASSWORD;

let channels = {}; // collect channels
let sockets = {}; // collect sockets
let peers = {}; // collect peers info grp by channels


//app.listen(port)//added as a extra line from heroku mongodb deployement post

// Use all static files from the www folder
app.use(express.static(path.join(__dirname, 'www')));

// Api parse body data as json
app.use(express.json());

const directory = path.join(__dirname, '/uploads');
app.use('/uploads', express.static(directory));

const meet_recordings = path.join(__dirname, '/meet_recordings');
app.use('/meet_recordings', express.static(meet_recordings));

// Remove trailing slashes in url handle bad requests
app.use((err, req, res, next) => {
    if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
        logme('Request Error', {
            header: req.headers,
            body: req.body,
            error: err.message,
        });
        return res.status(400).send({ status: 404, message: err.message }); // Bad request
    }
    if (req.path.substr(-1) === '/' && req.path.length > 1) {
        let query = req.url.slice(req.path.length);
        res.redirect(301, req.path.slice(0, -1) + query);
    } else {
        next();
    }
});


//=====================
// ROUTES
//=====================

// Showing login page even if asked for home page
app.get('/', function(req, res) {
    res.render('home', {
      user: req.user
    });
});
  
  
app.post('/', function(req, res, next) {
    passport.authenticate('local', function(err, user, info) {
      if (err) return next(err)
      if (!user) {
        return res.redirect('/login')
      }
      req.logIn(user, function(err) {
        if (err) return next(err);
        return res.redirect('/');  //redirect to the cognimeet newcall page
      });
    })(req, res, next);
});

//adding this code to retrieve the emotionsresult from client side which has came from emotions api
// Handling request 
app.post("/emotionsresult", (req, res) => {
    res.json([{
       result_recieved: req.body.result
    }])
    //console.log(res.json);
 })

/*
// Data which will write in a file.
let data = result_recieved
  
// Write data in 'Output.txt' .
fs.writeFile('Output.txt', data, (err) => {
      
    // In case of a error throw err.
    if (err) throw err;
})
*/

/* START-This code block is added for selecting scenes which are stored in db and a copy of images is present in uploads folder */
// Step 2 - connect to the database
 
/*mongoose.connect(process.env.MONGO_URL,
  { useNewUrlParser: true, useUnifiedTopology: true }, err => {
      console.log('connected')
  });
*/

// Step 5 - set up multer for storing uploaded files
 
var multer = require('multer');
 
var storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads')
    },
    filename: (req, file, cb) => {
        cb(null,file.originalname);
    }
});
 
var upload = multer({ storage: storage });

// Step 6 - load the mongoose model for Image
 
var imgModel = require('./models/models.js'); 

// Step 7 - the GET request handler that provides the HTML UI
 
app.get('/uploadcustomscene', (req, res) => {
  imgModel.find({}, (err, items) => {
      if (err) {
          console.log(err);
          res.status(500).send('An error occurred', err);
      }
      else {
          res.render('uploadcustomscene', { items: items });
      }
  });
});


// Step 8 - the POST handler for processing the uploaded file
 
app.post('/uploadcustomscene', upload.single('image'), (req, res, next) => {
  var obj = {
      name: req.file.filename, //this is filename so remove image title
      desc: req.body.desc,
      img: {
          //data: fs.readFileSync(path.join(__dirname + '/uploads/' + req.body.name + '.png')),
         //previous one done 
          data: fs.readFileSync(path.join(__dirname + '/uploads/' + req.file.filename)),
          contentType: 'image/png'
      }
  }
  
  imgModel.create(obj, (err, item) => {
      if (err) {
          console.log(err);
      }
      else {
          // item.save();
          res.redirect('/uploadcustomscene');
      }
  });
});

//view scenes stored in databases
app.get('/sceneselect', (req, res) => {
  imgModel.find({}, (err, items) => {
      if (err) {
          console.log(err);
          res.status(500).send('An error occurred', err);
      }
      else {
          res.render('sceneselect', { items: items });
      }
  });
});


//selectscene
app.get('/selectscene',function(req, res){
  imgModel.find({}, (err, items) => {
    if (err) {
        console.log(err);
        res.status(500).send('An error occurred', err);
    }
    else {
        res.render('selectscene', { items: items });
    }
});
});

//listallfiles
app.get('/listallfiles',function(req, res){
  imgModel.find({}, (err, items) => {
    if (err) {
        console.log(err);
        res.status(500).send('An error occurred', err);
    }
    else {
        res.render('listallfiles', { items: items });
    }
});
});


/* End-This code block is added for selecting scenes which are stored in db and a copy of images is present in uploads folder */

//newcall page
app.get('/newcall', function(req, res) {
    res.render('newcall', {user: req.user});
    //res.sendFile(path.join(__dirname, 'www/newcall.html'));
  });

//login
app.get('/login', function(req, res) {
    res.render('login', {
      user: req.user
    });
});
  
app.post('/login', function(req, res, next) {
    passport.authenticate('local', function(err, user, info) {
      if (err) return next(err)
      if (!user) {
        return res.redirect('/login')
      }
      req.logIn(user, function(err) {
        if (err) return next(err);
        return res.redirect('/'); //redirect to the cognimeet newcall page
        //return res.sendFile(path.join(__dirname, 'www/newcall.html'));
      });
    })(req, res, next);
  });
  
//signup
app.get('/signup', function(req, res) {
    res.render('signup', {
      user: req.user
    });
});
  
app.post('/signup', function(req, res) {
    var user = new User({
        username: req.body.username,
        email: req.body.email,
        password: req.body.password
      });
  
    user.save(function(err) {
      req.logIn(user, function(err) {
        res.redirect('/');
      });
    });
});
  
//logout
app.get('/logout', function(req, res){
    req.logout();
    res.redirect('/');
});
  
//forgot 
app.get('/forgot', function(req, res) {
    res.render('forgot', {
      user: req.user
    });
});
  
app.post('/forgot', function(req, res, next) {
    async.waterfall([
      function(done) {
        crypto.randomBytes(20, function(err, buf) {
          var token = buf.toString('hex');
          done(err, token);
        });
      },
      function(token, done) {
        User.findOne({ email: req.body.email }, function(err, user) {
          if (!user) {
            req.flash('error', 'No account with that email address exists.');
            return res.redirect('/forgot');
          }
  
          user.resetPasswordToken = token;
          user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
  
          user.save(function(err) {
            done(err, token, user);
          });
        });
      },
      function(token, user, done) {
        var smtpTransport = nodemailer.createTransport({
          host: "smtp.gmail.com", 
          auth: {
            "user": "cognitestservices@gmail.com",
            "pass": "cognitestservices@123"
        }
        });
        var mailOptions = {
          to: user.email,
          from: 'cognitestservices@gmail.com',
          subject: 'Your  Password Reset link',
          text: 'You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n' +
            'Please click on the following link, or paste this into your browser to complete the process:\n\n' +
            'http://' + req.headers.host + '/reset/' + token + '\n\n' +
            'If you did not request this, please ignore this email and your password will remain unchanged.\nThanks, \n Team Cognimeet :)'
        };
        smtpTransport.sendMail(mailOptions, function(err) {
          req.flash('info', 'Please check your spam folder as An e-mail has been sent to ' + user.email + ' with further instructions.');
          done(err, 'done');
        });
      }
    ], function(err) {
      if (err) return next(err);
      res.redirect('/forgot');
    });
});
  
app.get('/reset/:token', function(req, res) {
    User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
      if (!user) {
        req.flash('error', 'Password reset token is invalid or has expired.');
        return res.redirect('/forgot');
      }
      res.render('reset', {
        user: req.user
      });
    });
});
  
app.post('/reset/:token', function(req, res) {
    async.waterfall([
      function(done) {
        User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
          if (!user) {
            console.log('Password reset token is invalid or has expired.')
            req.flash('error', 'Password reset token is invalid or has expired.');
            return res.redirect('back');
          }
  
          user.password = req.body.password;
          user.resetPasswordToken = undefined;
          user.resetPasswordExpires = undefined;
  
          user.save(function(err) {
            req.logIn(user, function(err) {
              done(err, user);
            });
          });
        });
      },
      function(user, done) {
        var smtpTransport = nodemailer.createTransport({
          host: "smtp.gmail.com", 
          auth: {
            "user": "cognitestservices@gmail.com",
            "pass": "cognitestservices@123"
        }
        });
        var mailOptions = {
          to: user.email,
          from: 'cognitestservices@gmail.com',
          subject: 'Your password has been changed',
          text: 'Hello,\n\n' +
            'This is a confirmation that the password for your account ' + user.email + ' has just been changed.\n Thanks, \n Team Cognimeet :)'
        };
        smtpTransport.sendMail(mailOptions, function(err) {
          req.flash('success', 'Success! Your password has been changed.');
          done(err);
        });
      }
    ], function(err) {
      res.redirect('/');
    });
});



// if not allow video/audio
app.get(['/permission'], (req, res) => {
    res.sendFile(path.join(__dirname, 'www/permission.html'));
});

// privacy policy
app.get(['/privacy'], (req, res) => {
    res.sendFile(path.join(__dirname, 'www/privacy.html'));
});


// no room name specified to join
app.get('/join/', (req, res) => {
  res.redirect('/');
});


/*
//This is newly added code for authentication of join and join/* ROUTES
// join page
app.get('/join/*', function(req, res, next) {
  // If user is already logged in, then redirect to rooms page
  if(req.isAuthenticated()){
    if (Object.keys(req.query).length > 0) {
        logme('redirect:' + req.url + ' to ' + url.parse(req.url).pathname);
        res.redirect(url.parse(req.url).pathname);
        console.log('url pathname:' + url.parse(req.url).pathname)
    } else {
        res.sendFile(path.join(__dirname, 'www/client.html'));
    }
  }
  else{
    res.render("/login") //if not logged in
  }
});
*/

// join to room
//original
/*
app.get('/join/*', function(req, res) {
    if (Object.keys(req.query).length > 0) {
        console.log('redirect:' + req.url + ' to ' + url.parse(req.url).pathname);
        logme('redirect:' + req.url + ' to ' + url.parse(req.url).pathname);
        console.log(url.parse(req.url).pathname)
        res.redirect(url.parse(req.url).pathname);
    } else {
      //res.sendFile(path.join(__dirname, 'www/client.html'));
      res.render('client', {
        user: req.user
      });
    }
});
*/

//original+login auth added
app.get('/join/*', function(req, res,next) {
    if(req.isAuthenticated()){
        if (Object.keys(req.query).length > 0) {
            logme('redirect:' + req.url + ' to ' + url.parse(req.url).pathname);
            res.redirect(url.parse(req.url).pathname);
            console.log('url pathname:' + url.parse(req.url).pathname)
        } else {      //res.sendFile(path.join(__dirname, 'www/client.html'));
            res.render('client', {
              user: req.user
            });
        }
      }
      else{
        //res.render("login") //if not logged in
        res.redirect('/login');
    }
});

/**
    MiroTalk API v1
    The response will give you a entrypoint / Room URL for your meeting.
    For api docs we use: https://swagger.io/
*/

// api docs
app.use(apiBasePath + '/docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));
//const apiBasePath = '/api/v1'; // api endpoint path
// request meeting room endpoint
app.post([apiBasePath + '/meeting'], (req, res) => {
    // check if user was authorized for the api call
    let authorization = req.headers.authorization;
    if (authorization != api_key_secret) {
        logme('MiroTalk get meeting - Unauthorized', {
            header: req.headers,
            body: req.body,
        });
        return res.status(403).json({ error: 'Unauthorized!' });
    }
    // setup meeting URL
    let host = req.headers.host;
    let meetingURL = getMeetingURL(host) + '/join/' + makeId(15);
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ meeting: meetingURL }));

    // logme the output if all done
    logme('MiroTalk get meeting - Authorized', {
        header: req.headers,
        body: req.body,
        meeting: meetingURL,
    });
});

/**
 * Get get Meeting Room URL
 * @param {*} host string
 * @returns meeting Room URL
 */
function getMeetingURL(host) {
    return 'http' + (host.includes('localhost') ? '' : 's') + '://' + host;
}

/**
 * Generate random Id
 * @param {*} length int
 * @returns random id
 */
function makeId(length) {
    let result = '';
    let characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}
// end of MiroTalk API v1

/**
 * You should probably use a different stun-turn server
 * doing commercial stuff, also see:
 *
 * https://gist.github.com/zziuni/3741933
 * https://www.twilio.com/docs/stun-turn
 * https://github.com/coturn/coturn
 *
 * Check the functionality of STUN/TURN servers:
 * https://webrtc.github.io/samples/src/content/peerconnection/trickle-ice/
 */
const iceServers = [{ urls: 'stun:stun.l.google.com:19302' }];

if (turnEnabled == 'true') {
    iceServers.push({
        urls: turnUrls,
        username: turnUsername,
        credential: turnCredential,
    });
}

/**
 * Expose server to external with https tunnel using ngrok
 * https://ngrok.com
 */
/*
async function ngrokStart() {
    try {
        await ngrok.authtoken(ngrokAuthToken);
        await ngrok.connect(port);
        let api = ngrok.getApi();
        let data = await api.listTunnels();
        let pu0 = data.tunnels[0].public_url;
        let pu1 = data.tunnels[1].public_url;
        let tunnelHttps = pu0.startsWith('https') ? pu0 : pu1;
        // server settings
        logme('settings', {
            http: localHost,
            https: tunnelHttps,
            api_docs: api_docs,
            api_key_secret: api_key_secret,
            iceServers: iceServers,
            ngrok: {
                ngrok_enabled: ngrokEnabled,
                ngrok_token: ngrokAuthToken,
            },
        });
    } catch (err) {
        console.error('[Error] ngrokStart', err);
    }
}
*/


/**
 * Start Local Server with ngrok https tunnel (optional)
 */

server.listen(port, null, () => {
    logme(
        `%c

	███████╗██╗ ██████╗ ███╗   ██╗      ███████╗███████╗██████╗ ██╗   ██╗███████╗██████╗ 
	██╔════╝██║██╔════╝ ████╗  ██║      ██╔════╝██╔════╝██╔══██╗██║   ██║██╔════╝██╔══██╗
	███████╗██║██║  ███╗██╔██╗ ██║█████╗███████╗█████╗  ██████╔╝██║   ██║█████╗  ██████╔╝
	╚════██║██║██║   ██║██║╚██╗██║╚════╝╚════██║██╔══╝  ██╔══██╗╚██╗ ██╔╝██╔══╝  ██╔══██╗
	███████║██║╚██████╔╝██║ ╚████║      ███████║███████╗██║  ██║ ╚████╔╝ ███████╗██║  ██║
	╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═══╝      ╚══════╝╚══════╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝ started...

	`,
        'font-family:monospace',
    );

    // https tunnel
    if (ngrokEnabled == 'true') {
        ngrokStart();
    } else {
        // server settings
        logme('settings', {
            http: localHost,
            api_docs: api_docs,
            api_key_secret: api_key_secret,
            iceServers: iceServers,
        });
    }
});


/**
 * Users will connect to the signaling server, after which they'll issue a "join"
 * to join a particular channel. The signaling server keeps track of all sockets
 * who are in a channel, and on join will send out 'addPeer' events to each pair
 * of users in a channel. When clients receive the 'addPeer' even they'll begin
 * setting up an RTCPeerConnection with one another. During this process they'll
 * need to relay ICECandidate information to one another, as well as SessionDescription
 * information. After all of that happens, they'll finally be able to complete
 * the peer connection and will be in streaming audio/video between eachother.
 * On peer connected
 */

io.sockets.on('connect', (socket) => {
    logme('[' + socket.id + '] --> connection accepted');

    socket.channels = {};
    sockets[socket.id] = socket;

    /**
     * On peer diconnected
     */
    socket.on('disconnect', () => {
        for (let channel in socket.channels) {
            removePeerFrom(channel);
        }
        logme('[' + socket.id + '] <--> disconnected');
        delete sockets[socket.id];
    });

    /**
     * On peer join
     */
    socket.on('join', (config) => {
        logme('[' + socket.id + '] --> join ', config);

        let channel = config.channel;
        let peer_name = config.peer_name;
        let peer_video = config.peer_video;
        let peer_audio = config.peer_audio;
        let peer_hand = config.peer_hand;

        if (channel in socket.channels) {
            logme('[' + socket.id + '] [Warning] already joined', channel);
            return;
        }
        // no channel aka room in channels init
        if (!(channel in channels)) channels[channel] = {};

        // no channel aka room in peers init
        if (!(channel in peers)) peers[channel] = {};

        // room locked by the participants can't join
        if (peers[channel]['Locked'] === true) {
            logme('[' + socket.id + '] [Warning] Room Is Locked', channel);
            socket.emit('roomIsLocked');
            return;
        }

        // collect peers info grp by channels
        peers[channel][socket.id] = {
            peer_name: peer_name,
            peer_video: peer_video,
            peer_audio: peer_audio,
            peer_hand: peer_hand,
        };
         if (peer_name = "satyam"){
             logme('satyam is detected as a peer by line 783 in server.js')
         }

        logme('connected peers grp by roomId', peers);

        for (let id in channels[channel]) {
            // offer false
            channels[channel][id].emit('addPeer', {
                peer_id: socket.id,
                peers: peers[channel],
                should_create_offer: false,
                iceServers: iceServers,
            });
            
            // offer true
            socket.emit('addPeer', {
                peer_id: id,
                peers: peers[channel],
                should_create_offer: true,
                iceServers: iceServers,
            });
            logme('[' + socket.id + '] emit addPeer [' + id + ']');
        }

        channels[channel][socket.id] = socket;
        socket.channels[channel] = channel;
    });

    /**
     * Remove peers from channel aka room
     * @param {*} channel
     */
    async function removePeerFrom(channel) {
        if (!(channel in socket.channels)) {
            logme('[' + socket.id + '] [Warning] not in ', channel);
            return;
        }

        delete socket.channels[channel];
        delete channels[channel][socket.id];
        delete peers[channel][socket.id];

        switch (Object.keys(peers[channel]).length) {
            case 0:
                // last peer disconnected from the room without room status set, delete room data
                delete peers[channel];
                break;
            case 1:
                // last peer disconnected from the room having room status set, delete room data
                if ('Locked' in peers[channel]) delete peers[channel];
                break;
        }

        for (let id in channels[channel]) {
            await channels[channel][id].emit('removePeer', { peer_id: socket.id });
            await socket.emit('removePeer', { peer_id: id });
            logme('[' + socket.id + '] emit removePeer [' + id + ']');
        }
    }

    /**
     * Relay ICE to peers
     */
    socket.on('relayICE', (config) => {
        let peer_id = config.peer_id;
        let ice_candidate = config.ice_candidate;

        // logme('[' + socket.id + '] relay ICE-candidate to [' + peer_id + '] ', {
        //     address: config.ice_candidate,
        // });

        if (peer_id in sockets) {
            sockets[peer_id].emit('iceCandidate', {
                peer_id: socket.id,
                ice_candidate: ice_candidate,
            });
        }
    });

    /**
     * Relay SDP to peers
     */
    socket.on('relaySDP', (config) => {
        let peer_id = config.peer_id;
        let session_description = config.session_description;

        logme('[' + socket.id + '] relay SessionDescription to [' + peer_id + '] ', {
            type: session_description.type,
        });

        if (peer_id in sockets) {
            sockets[peer_id].emit('sessionDescription', {
                peer_id: socket.id,
                session_description: session_description,
            });
        }
    });

    /**
     * Refresh Room Status (Locked/Unlocked)
     */
    socket.on('roomStatus', (config) => {
        let peerConnections = config.peerConnections;
        let room_id = config.room_id;
        let room_locked = config.room_locked;
        let peer_name = config.peer_name;

        peers[room_id]['Locked'] = room_locked;

        if (Object.keys(peerConnections).length != 0) {
            logme('[' + socket.id + '] emit roomStatus' + ' to [room_id: ' + room_id + ' locked: ' + room_locked + ']');
            for (let peer_id in peerConnections) {
                if (sockets[peer_id]) {
                    sockets[peer_id].emit('roomStatus', {
                        peer_name: peer_name,
                        room_locked: room_locked,
                    });
                }
            }
        }
    });

    /**
     * Relay NAME to peers
     */
    socket.on('peerName', (config) => {
        let peerConnections = config.peerConnections;
        let room_id = config.room_id;
        let peer_name_old = config.peer_name_old;
        let peer_name_new = config.peer_name_new;
        let peer_id_to_update = null;

        // update peers new name in the specified room
        for (let peer_id in peers[room_id]) {
            if (peers[room_id][peer_id]['peer_name'] == peer_name_old) {
                peers[room_id][peer_id]['peer_name'] = peer_name_new;
                peer_id_to_update = peer_id;

                // logme('[' + socket.id + '] change peer name', {
                //     room_id: room_id,
                //     peer_id: peer_id,
                //     peer_name_old: peer_name_old,
                //     peer_name_new: peer_name_new,
                // });
            }
        }

        // refresh if found
        if (peer_id_to_update && Object.keys(peerConnections).length != 0) {
            logme('[' + socket.id + '] emit peerName to [room_id: ' + room_id + ']', {
                peer_id: peer_id_to_update,
                peer_name: peer_name_new,
            });
            for (let peer_id in peerConnections) {
                if (sockets[peer_id]) {
                    sockets[peer_id].emit('peerName', {
                        peer_id: peer_id_to_update,
                        peer_name: peer_name_new,
                    });
                }
            }
        }
    });

    /**
     * Relay Audio Video Hand ... Status to peers
     */
    socket.on('peerStatus', (config) => {
        let peerConnections = config.peerConnections;
        let room_id = config.room_id;
        let peer_name = config.peer_name;
        let element = config.element;
        let status = config.status;

        // update peers video-audio status in the specified room
        for (let peer_id in peers[room_id]) {
            if (peers[room_id][peer_id]['peer_name'] == peer_name) {
                switch (element) {
                    case 'video':
                        peers[room_id][peer_id]['peer_video'] = status;
                        break;
                    case 'audio':
                        peers[room_id][peer_id]['peer_audio'] = status;
                        break;
                    case 'hand':
                        peers[room_id][peer_id]['peer_hand'] = status;
                        break;
                }

                // logme('[' + socket.id + '] change ' + element + ' status', {
                //     room_id: room_id,
                //     peer_name: peer_name,
                //     element: element,
                //     status: status,
                // });
            }
        }

        // socket.id aka peer that send this status
        if (Object.keys(peerConnections).length != 0) {
            logme('[' + socket.id + '] emit peerStatus to [room_id: ' + room_id + ']', {
                peer_id: socket.id,
                element: element,
                status: status,
            });
            for (let peer_id in peerConnections) {
                if (sockets[peer_id]) {
                    sockets[peer_id].emit('peerStatus', {
                        peer_id: socket.id,
                        peer_name: peer_name,
                        element: element,
                        status: status,
                    });
                }
            }
        }
    });

    /**
     * Relay actions to peers in the same room
     */
    socket.on('peerAction', (config) => {
        let peerConnections = config.peerConnections;
        let room_id = config.room_id;
        let peer_name = config.peer_name;
        let peer_action = config.peer_action;

        // socket.id aka peer that send this status
        if (Object.keys(peerConnections).length != 0) {
            logme('[' + socket.id + '] emit peerAction to [room_id: ' + room_id + ']', {
                peer_id: socket.id,
                peer_name: peer_name,
                peer_action: peer_action,
            });
            for (let peer_id in peerConnections) {
                if (sockets[peer_id]) {
                    sockets[peer_id].emit('peerAction', {
                        peer_name: peer_name,
                        peer_action: peer_action,
                    });
                }
            }
        }
    });

    /**
     * Relay Kick out peer from room
     */
    socket.on('kickOut', (config) => {
        let room_id = config.room_id;
        let peer_id = config.peer_id;
        let peer_name = config.peer_name;

        logme('[' + socket.id + '] kick out peer [' + peer_id + '] from room_id [' + room_id + ']');

        if (peer_id in sockets) {
            sockets[peer_id].emit('kickOut', {
                peer_name: peer_name,
            });
        }
    });

    /**
     * Relay File info
     */
    socket.on('fileInfo', (config) => {
        let peerConnections = config.peerConnections;
        let room_id = config.room_id;
        let peer_name = config.peer_name;
        let file = config.file;

        file['peerName'] = peer_name;

        logme('[' + socket.id + '] Peer [' + peer_name + '] send file to room_id [' + room_id + ']', {
            fileName: file.fileName,
            fileSize: bytesToSize(file.fileSize),
            fileType: file.fileType,
        });

        function bytesToSize(bytes) {
            let sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
            if (bytes == 0) return '0 Byte';
            let i = parseInt(Math.floor(Math.log(bytes) / Math.log(1024)));
            return Math.round(bytes / Math.pow(1024, i), 2) + ' ' + sizes[i];
        }

        if (Object.keys(peerConnections).length != 0) {
            for (let peer_id in peerConnections) {
                if (sockets[peer_id]) {
                    sockets[peer_id].emit('fileInfo', file);
                }
            }
        }
    });

    /**
     * Abort file sharing
     */
    socket.on('fileAbort', (config) => {
        let peerConnections = config.peerConnections;
        let room_id = config.room_id;
        let peer_name = config.peer_name;
        if (Object.keys(peerConnections).length != 0) {
            logme('[' + socket.id + '] Peer [' + peer_name + '] send fileAbort to room_id [' + room_id + ']');
            for (let peer_id in peerConnections) {
                if (sockets[peer_id]) {
                    sockets[peer_id].emit('fileAbort');
                }
            }
        }
    });

    /**
     * Whiteboard actions for all user in the same room
     */
    socket.on('wb', (config) => {
        let peerConnections = config.peerConnections;
        delete config.peerConnections;
        if (Object.keys(peerConnections).length != 0) {
            // logme("[" + socket.id + "] whiteboard config", config);
            for (let peer_id in peerConnections) {
                if (sockets[peer_id]) {
                    sockets[peer_id].emit('wb', config);
                }
            }
        }
    });
}); // end [sockets.on-connect]

/**
 * log with UTC data time
 * @param {*} msg message any
 * @param {*} op optional params
 */
function logme(msg, op = '') {
    let dataTime = new Date().toISOString().replace(/T/, ' ').replace(/Z/, '');
    console.log('[' + dataTime + '] ' + msg, op);
}
