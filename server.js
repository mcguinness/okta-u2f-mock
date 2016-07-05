var http = require('http');
var https = require('https');
var url = require('url');
var fs = require('fs');
var path = require('path');
var os = require('os');
var yargs = require('yargs');
var express = require('express');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var session = require('express-session');
var crypto = require('crypto');
var x509 = require('x509');
var u2f = require('u2f');

/**
 * Globals
 */

var appId;
var factorsDb = {};
var app = express();
var httpServer = https.createServer({
  key: fs.readFileSync('cert.key').toString(),
  cert: fs.readFileSync('cert.pem').toString()
}, app);

app.use(logger('dev'));
app.use('/bower_components', express.static(__dirname + '/bower_components'));
app.use('/public', express.static(__dirname + '/public'));
app.use(bodyParser.json());
app.use(cookieParser());

app.set('views', path.join(__dirname, 'views'));

// view engine
app.set('view engine', 'hbs');
app.set('view options', { layout: 'layout' });

app.use(session({
  secret: "You tell me what you want and I'll tell you what you get",
  resave: false,
  saveUninitialized: true}
));

app.use(function (req, res, next) {
  if (!req.session.u2f) {
    req.session.u2f = {};
  }
  return next();
})

app.get('/', function(req, res) {
  res.render('index');
});

app.post('/factors', function(req, res) {
  if (req.body.provider === 'FIDO' && req.body.factorType === 'U2F') {
    var id = crypto.randomBytes(20)
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/\=+$/, '');
    var u2fReq = u2f.request(appId);
    var factor = {
      id: id,
      status: 'PENDING_ACTIVATION',
      factorType: 'U2F',
      provider: 'FIDO',
      profile: {

      },
      _embedded: {
        activation: {
          version: "U2F_V2",
          appId: u2fReq.appId,
          challenge: u2fReq.challenge
        }
      }
    };
    factorsDb[id] = factor;
    return res.json(factor);
  } else {
    return res.status(400).json({
      errorSummary: 'Factor type is not valid'
    })
  }
});

app.get('/factors/:id', function(req, res) {
  var factor = factorsDb[req.params.id];
  if (factor) {
    return res.status(200).json(factor);
  } else {
    return res.status(404);
  }
});

app.post('/factors/:id/lifecycle/activate', function(req, res) {
  var factor = factorsDb[req.params.id];

  if (factor) {
    if (factor.status === 'PENDING_ACTIVATION') {
      var result = u2f.checkRegistration(factor._embedded.activation, req.body);
      if (result.successful) {

        if (result.certificate) {
          console.log('Attestation Certificate:');
          var raw = result.certificate.toString('base64');
          var pem = '';
          var i = 0;
          var maxLen = 64;
          while (i + maxLen < raw.length) {
              pem += raw.substring(i, i + maxLen) + "\n";
              i += maxLen;
          }
          pem = pem + raw.substring(i, raw.length);
          console.log('-----BEGIN CERTIFICATE-----\n' + pem + '\n-----END CERTIFICATE-----');
          console.log();
        }

         var activatedFactor = {
          id: factor.id,
          status: 'ACTIVE',
          factorType: 'U2F',
          provider: 'FIDO',
          profile: {
            credentialId: factor._embedded.activation.appId,
            keys: [
              {
                version: factor._embedded.activation.version,
                keyHandle: result.keyHandle,
                publicKey: result.publicKey
              }
            ]
          }
        };
        factorsDb[req.params.id] = activatedFactor
        console.log('Activate Factor: \r\n%j', activatedFactor);
        return res.status(200).json(activatedFactor)
      } else {
        console.log('Unable to register token due to error %s', result.errorMessage);
        return res.status(400).json({
          errorSummary: result.errorMessage
        })
      }
    } else {
      return res.status(400).json({
        errorSummary: 'Factor status must be "PENDING_ACTIVATION"'
      });
    }
  } else {
    return res.status(404);
  }
});


app.post('/factor/:id/verify', function(req, res) {
  var factor = factorsDb[req.params.id];
  if (factor) {
      var txId = crypto.randomBytes(20)
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/\=+$/, '');
      var u2fReq = u2f.request(factor.profile.credentialId);
      req.session.u2f[txId] = {
        factorId: factor.id,
        challenge: u2fReq.challenge,
        createdAt: Date.now()
      };

      res.set('Location', req.originalUrl + '/' + txId);
      return res.status(201)
        .json({
          factorResult: 'CHALLENGE',
          appId: factor.profile.credentialId,
          challenge: u2fReq.challenge,
          registeredKeys: factor.profile.keys
        });
  } else {
    return res.status(404);
  }
});


app.post('/factor/:id/verify/:tx', function(req, res) {

  if (req.body.errorCode) {
    return res.status(400).json({
      errorSummary: 'Verification was not successful (ErrorCode: ' + req.body.errorCode + ')'
    });
  }

  var factor = factorsDb[req.params.id];
  if (factor && req.params.tx && req.session.u2f[req.params.tx]) {
    if (req.body.keyHandle && req.body.signatureData && req.body.clientData) {

      var tx = req.session.u2f[req.params.tx];
      var factor = factorsDb[tx.factorId];
      var publicKey;

      for (var i=0; i<factor.profile.keys.length; i++) {
        if (factor.profile.keys[i].keyHandle === req.body.keyHandle) {
          publicKey = factor.profile.keys[i].publicKey;
        }
      }

      if (publicKey === undefined) {
        return res.status(400).json({
          errorSummary: 'KeyHandle ' + req.body.keyHandle + ' is not registered'
        });
      }

      console.log('Verifying challenge [%s] with publicKey [%s] for keyHandle [%s]',
        tx.challenge, publicKey, req.body.keyHandle);

      var result = u2f.checkSignature({
        appId: factor.profile.credentialId,
        challenge: tx.challenge
      }, req.body, publicKey);

      if (result.successful) {
        return res.status(200).json({factorResult: 'SUCCESS'});
      } else {
        return res.status(403).json({
          errorSummary: result.errorMessage
        });
      }
    }
  }
});


/**
 * Start Web Server
 */

console.log('starting server...');

httpServer.listen(6080, function() {
  var scheme   = 'https',
      address  = httpServer.address(),
      hostname = os.hostname();

  appId = address.address === '0.0.0.0' ?
        scheme + '://' + hostname + ':' + address.port :
        scheme + '://localhost:' + address.port;

  console.log('listening on: ' + appId);
  console.log();
});
