const express = require("express");
const session = require("express-session");
const createError = require("http-errors");
const cookieParser = require("cookie-parser");
const logger = require("morgan");
const path = require("path");
const { createServer } = require("http");
const { auth, requiresAuth } = require("express-openid-connect");
const axios = require("axios").default;
const request = require('request');
const jwt = require("express-jwt");
const jwksRsa = require("jwks-rsa");
const jwt_decode = require("jwt-decode");
const jwtAuthz = require("express-jwt-authz");
const redis = require('ioredis');
const connectRedis = require('connect-redis');


const {
  checkUrl,
  APP_URL, // Public URL for this app
  API_URL, // URL for Expenses API
  ISSUER_BASE_URL, // Auth0 Tenant Url
  CLIENT_ID, // Auth0 Web App Client
  CLIENT_SECRET, // Auth0 Web App CLient Secret
  SESSION_SECRET, // Cookie Encryption Key
  PORT,
} = require("./env-config");

const app = express();
app.locals.env = process.env;
app.use(checkUrl()); // Used to normalize URL in Vercel
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "pug");
app.use(logger("combined"));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

const oneDay = 1000 * 60 * 60 * 24;
//
const RedisStore = require('connect-redis')(session);

const redisClient = redis.createClient({host: process.env.REDIS_HOST,
                                        port: process.env.REDIS_PORT,
                                        username: process.env.REDIS_USER,
                                        password:process.env.REDIS_PASSWORD});

redisClient.on('connect',() => {
    console.log('connected to redis successfully!');
})

redisClient.on('error',(error) => {
    console.log('Redis connection error :', error);
})

app.use(session({
    store: new RedisStore({ client: redisClient }),
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false, // if true only transmit cookie over https
        httpOnly: false, // if true prevent client side JS from reading the cookie
        maxAge: 1000 * 60 * 10 // session max age in miliseconds
    }
}))



app.use(function(req, res, next) {
  res.locals.app = app;
  res.set('Cache-Control', 'no-store')
  next();
});


app.get("/", async (req, res, next) => {
  try {
    res.render("home", {
    });
  } catch (err) {
    next(err);
  }
});

app.get("/logmeout", async (req, res, next) => {
  try {
    var url = 'https://'+process.env.DOMAIN+'/v2/logout?returnTo='+APP_URL+'&client_id='+process.env.CLIENT_ID

    res.redirect(303, url);
  } catch (err) {
    next(err);
  }
});

app.get("/authorization_code", async (req, res, next) => {

    if (req.query.code) {
      try {
        res.render("authorization_code", {
        request: "TBC", response: req.url, code: req.query.code});
      } catch (err) {
        console.log(err);
        next(err);
      }
  } else if (req.query.error) {
        try {
          res.render("authorization_code", {
          request: "TBC", response: req.url, error: req.query.error, error_description: req.query.error_description});
        } catch (err) {
          console.log(err);
          next(err);
        }
  } else {

      try {
        res.render("authorization_code", {
        });
      } catch (err) {
        console.log(err);
        next(err);
      }
  }
});

app.post("/authorization_code", async (req, res, next) => {

      if (req.body.id_token || req.body.access_token || req.body.refresh_token) {
                req.session.access_token = req.body.access_token;
                req.session.refresh_token = req.body.refresh_token;
                req.session.id_token = req.body.id_token;
                req.session.client_id = req.body.client_id;
              try {
                res.render("authorization_code", {
                access_token: req.body.access_token, id_token: req.body.id_token, refresh_token: req.body.refresh_token});
              } catch (err) {
                console.log(err);
                next(err);
              }
        } else if(req.body.error) {
            try {
              if (req.body.request) {
                  res.render("authorization_code", {
                  request: JSON.parse(req.body.request), response: JSON.parse(req.body.response), error: req.body.error, error_description: req.body.error_description});
              } else {
                  res.render("authorization_code", {
                  request: "TBC", response: req, error: req.body.error, error_description: req.body.error_description});
              }
            } catch (err) {
              console.log(err);
              next(err);
            }
      } else if (req.body.code && !req.body.client_secret) {
            try {
          res.render("authorization_code", {
          request: "TBC", response: req, code: req.body.code});
            } catch (err) {
              console.log(err);
              next(err);
            }
      } else if (req.body.client_secret) {
          var clientServerOptions = {
              uri: 'https://'+process.env.DOMAIN+'/oauth/token',
                form: {
                  grant_type: req.body.grant_type,
                  client_id: req.body.client_id,
                  client_secret: req.body.client_secret,
                  code: req.body.code,
                  redirect_uri: req.body.redirect_uri
                },
              method: 'POST',
              headers: {
                  'Content-Type': 'application/x-www-form-urlencoded'
              }
          }
          request(clientServerOptions, function (error, response) {
                const body = JSON.parse(response.body);
              try {
                req.session.access_token = body.access_token;
                req.session.refresh_token = body.refresh_token;
                req.session.id_token = body.id_token;
                req.session.client_id = req.body.client_id;
                res.render("authorization_code", {
                request: clientServerOptions, response: response, access_token: body.access_token, id_token: body.id_token, refresh_token: body.refresh_token});

              } catch (err) {
                console.log(err);
                next(err);
              }
              //return;
          });

      } else {
          try {
            var url = 'https://'+process.env.DOMAIN+'/authorize?response_mode='+req.body.response_mode+'&response_type='+req.body.response_type+'&client_id='+req.body.client_id+'&redirect_uri='+req.body.redirect_uri+'&scope='+req.body.scope+'&state='+req.body.state+'&nonce='+req.body.nonce

            if (req.body.connection!="") {
                url = url + '&connection='+req.body.connection
            }

            if (req.body.prompt!="") {
                url = url + '&prompt='+req.body.prompt
            }

            if (req.body.organization!="") {
                url = url + '&organization='+req.body.organization
            }

            if (req.body.max_age!="") {
                url = url + '&max_age='+req.body.max_age
            }

            if (req.body.login_hint!="") {
                url = url + '&login_hint='+req.body.login_hint
            }

            res.redirect(303, url);
          } catch (err) {
            next(err);
          }
  }
});

app.get("/authorization_code_pkce", async (req, res, next) => {

    if (req.query.code) {
      try {
        res.render("authorization_code_pkce", {
        request: "TBC", response: req.url, code: req.query.code});
      } catch (err) {
        console.log(err);
        next(err);
      }
  } else if (req.query.error) {
        try {
          res.render("authorization_code_pkce", {
          request: "TBC", response: req.url, error: req.query.error, error_description: req.query.error_description});
        } catch (err) {
          console.log(err);
          next(err);
        }
  } else {

      try {
        res.render("authorization_code_pkce", {
        });
      } catch (err) {
        console.log(err);
        next(err);
      }
  }
});

app.post("/authorization_code_pkce", async (req, res, next) => {

      if (req.body.id_token || req.body.access_token || req.body.refresh_token) {
                req.session.access_token = req.body.access_token;
                req.session.refresh_token = req.body.refresh_token;
                req.session.id_token = req.body.id_token;
                req.session.client_id = req.body.client_id;
              try {
                res.render("authorization_code_pkce", {
                request: JSON.parse(req.body.request), response: JSON.parse(req.body.response), access_token: req.body.access_token, id_token: req.body.id_token, refresh_token: req.body.refresh_token});
              } catch (err) {
                console.log(err);
                next(err);
              }
      } else if(req.body.error) {
          try {
            if (req.body.request) {
                res.render("authorization_code_pkce", {
                request: JSON.parse(req.body.request), response: JSON.parse(req.body.response), error: req.body.error, error_description: req.body.error_description});
            } else {
                res.render("authorization_code_pkce", {
                request: "TBC", response: req, error: req.body.error, error_description: req.body.error_description});
            }
          } catch (err) {
            console.log(err);
            next(err);
          }
      } else if(req.body.code) {
          try {
        res.render("authorization_code_pkce", {
        request: "TBC", response: req, code: req.body.code});
          } catch (err) {
            console.log(err);
            next(err);
          }
      } else {
          try {
            var url = 'https://'+process.env.DOMAIN+'/authorize?response_mode='+req.body.response_mode+'&response_type='+req.body.response_type+'&code_challenge='+req.body.code_challenge+'&code_challenge_method='+req.body.code_challenge_method+'&client_id='+req.body.client_id+'&redirect_uri='+req.body.redirect_uri+'&scope='+req.body.scope+'&state='+req.body.state+'&nonce='+req.body.nonce

            if (req.body.connection!="") {
                url = url + '&connection='+req.body.connection
            }

            if (req.body.prompt!="") {
                url = url + '&prompt='+req.body.prompt
            }

            if (req.body.organization!="") {
                url = url + '&organization='+req.body.organization
            }

            if (req.body.max_age!="") {
                url = url + '&max_age='+req.body.max_age
            }

            if (req.body.login_hint!="") {
                url = url + '&login_hint='+req.body.login_hint
            }


            res.redirect(303, url);
          } catch (err) {
            next(err);
          }
  }
});

app.get("/implicit", async (req, res, next) => {
  try {
    res.render("implicit", {
   });
  } catch (err) {
    console.log(err);
    next(err);
  }
});

app.post("/implicit", async (req, res, next) => {
  if (req.body.id_token || req.body.access_token) {
          try {
            req.session.access_token = req.body.access_token;
            req.session.id_token = req.body.id_token;
            res.render("implicit", {
            request: "TBC", response: req, access_token: req.body.access_token, id_token: req.body.id_token, refresh_token: req.body.refresh_token});

          } catch (err) {
            console.log(err);
            next(err);
          }
  } else if (req.body.error) {
      try {
        res.render("implicit", {
        request: "TBC", response: req, error: req.body.error, error_description: req.body.error_description});
      } catch (err) {
        console.log(err);
        next(err);
      }
  } else {
  try {
    var url = 'https://'+process.env.DOMAIN+'/authorize?response_mode='+req.body.response_mode+'&response_type='+req.body.response_type+'&client_id='+req.body.client_id+'&redirect_uri='+req.body.redirect_uri+'&scope='+req.body.scope+'&state='+req.body.state+'&nonce='+req.body.nonce

    if (req.body.connection!="") {
        url = url + '&connection='+req.body.connection
    }

    if (req.body.prompt!="") {
        url = url + '&prompt='+req.body.prompt
    }

    if (req.body.organization!="") {
        url = url + '&organization='+req.body.organization
    }

    if (req.body.max_age!="") {
        url = url + '&max_age='+req.body.max_age
    }

    if (req.body.login_hint!="") {
        url = url + '&login_hint='+req.body.login_hint
    }


    res.redirect(303, url);
  } catch (err) {
    next(err);
  }
  }
});


app.get("/device_code", async (req, res, next) => {
  try {
    res.render("device_code", {
    });
  } catch (err) {
    console.log(err);
    next(err);
  }
});


app.post("/device_code", async (req, res, next) => {
    if (req.body.device_code) {

          var clientServerOptions = {
              uri: 'https://'+process.env.DOMAIN+'/oauth/token',
                form: {
                  grant_type: req.body.grant_type,
                  client_id: req.body.client_id,
                  device_code: req.body.device_code
                },
              method: 'POST',
              headers: {
                  'Content-Type': 'application/x-www-form-urlencoded'
              }
          }

          request(clientServerOptions, function (error, response) {
                const body = JSON.parse(response.body);

                if (response.statusCode != 200) {
                      try {
                        res.render("device_code", {
                        request: clientServerOptions, response: response, device_code: req.body.device_code, user_code: req.body.user_code, verification_uri: req.body.verification_uri, verification_uri_complete: req.body.verification_uri_complete, error: body.error, error_description: body.error_description});
                      } catch (err) {
                        console.log(err);
                        next(err);
                      }
                } else {

                  try {
                  req.session.access_token = body.access_token;
                  refresh_token = body.refresh_token;
                  req.session.id_token = body.id_token;
                  req.session.client_id = req.body.client_id;
                    res.render("device_code", {
                    request: clientServerOptions, response: response, access_token: body.access_token, id_token: body.id_token, refresh_token: body.refresh_token});

                  } catch (err) {
                    console.log(err);
                    next(err);
                  }
              }
              //return;
          });
      } else {

            var clientServerOptions = {
                  uri: 'https://'+process.env.DOMAIN+'/oauth/device/code',
                    form: {
                      audience: req.body.audience,
                      client_id: req.body.client_id,
                      scope: getScope(req)
                    },
                  method: 'POST',
                  headers: {
                      'Content-Type': 'application/x-www-form-urlencoded'
                  }
              }


              request(clientServerOptions, function (error, response) {

                    const body = JSON.parse(response.body);

                    if (response.statusCode != 200) {
                          try {
                            res.render("device_code", {
                            request: clientServerOptions, response: response, error: body.error, error_description: body.error_description});
                          } catch (err) {
                            console.log(err);
                            next(err);
                          }
                    } else {
                    var QRCode = require('qrcode')
                    QRCode.toDataURL(body.verification_uri_complete, function (err, qr) {
                        try {
                          res.render("device_code", {
                          qr: qr, request: clientServerOptions, response: response, device_code: body.device_code, user_code: body.user_code, verification_uri: body.verification_uri, verification_uri_complete: body.verification_uri_complete});
                        } catch (err) {
                          console.log(err);
                          next(err);
                        }
                    });

                  }
                  //return;
              });

      }
});


app.get("/revoke", async (req, res, next) => {
  try {
    res.render("revoke", {
    client_id: req.session.client_id, refresh_token: req.session.refresh_token});
  } catch (err) {
    console.log(err);
    next(err);
  }
});


app.post("/revoke", async (req, res, next) => {
      var clientServerOptions = {
          uri: 'https://'+process.env.DOMAIN+'/oauth/revoke',
            form: {
              client_id: req.body.client_id,
              token: req.body.token
            },
          method: 'POST',
          headers: {
              'Content-Type': 'application/x-www-form-urlencoded'
          }
      }

      if (req.body.client_secret.length>0 && req.body.client_id == process.env.CLIENT_ID) {
        clientServerOptions.form.client_secret = req.body.client_secret
      }

      request(clientServerOptions, function (error, response) {

            const body = response.body;

            if (response.statusCode != 200) {
                  try {
                    res.render("revoke", {
                    request: clientServerOptions, response: response, error: body.error, error_description: body.error_description, refresh_token: req.body.token});
                  } catch (err) {
                    console.log(err);
                    next(err);
                  }
            } else {

              try {
                res.render("revoke", {
                request: clientServerOptions, response: response, refresh_token: req.body.token});

              } catch (err) {
                console.log(err);
                next(err);
              }
          }
          //return;
      });
});

app.get("/refresh_token", async (req, res, next) => {
  try {
    res.render("refresh_token", {
    refresh_token: req.session.refresh_token, client_id: req.session.client_id});
  } catch (err) {
    console.log(err);
    next(err);
  }
});

app.post("/refresh_token", async (req, res, next) => {
      var clientServerOptions = {
          uri: 'https://'+process.env.DOMAIN+'/oauth/token',
            form: {
              grant_type: req.body.grant_type,
              client_id: req.body.client_id,
              refresh_token: req.body.refresh_token,
              scope: getScope(req)
            },
          method: 'POST',
          headers: {
              'Content-Type': 'application/x-www-form-urlencoded'
          }
      }

      if (req.body.client_secret.length>0 && req.body.client_id == process.env.CLIENT_ID) {
        clientServerOptions.form.client_secret = req.body.client_secret
      }

      request(clientServerOptions, function (error, response) {

            const body = JSON.parse(response.body);

            if (response.statusCode != 200) {
                  try {
                    res.render("refresh_token", {
                    request: clientServerOptions, response: response, error: body.error, error_description: body.error_description, refresh_token: req.body.refresh_token});
                  } catch (err) {
                    console.log(err);
                    next(err);
                  }
            } else {

              try {
                  req.session.access_token = body.access_token;
                  req.session.client_id = req.body.client_id;
                  if (body.refresh_token) {
                      req.session.refresh_token = body.refresh_token;
                  }
                  req.session.id_token = body.id_token;
                res.render("refresh_token", {
                request: clientServerOptions, response: response, access_token: body.access_token, id_token: body.id_token, refresh_token: body.refresh_token});

              } catch (err) {
                console.log(err);
                next(err);
              }
          }
          //return;
      });
});


app.get("/client_credentials", async (req, res, next) => {
  try {
    res.render("client_credentials", {
    });
  } catch (err) {
    console.log(err);
    next(err);
  }
});

app.post("/client_credentials", async (req, res, next) => {
          var clientServerOptions = {
              uri: 'https://'+process.env.DOMAIN+'/oauth/token',
                form: {
                  grant_type: req.body.grant_type,
                  client_id: req.body.client_id,
                  client_secret: req.body.client_secret,
                  audience: req.body.audience,
                  scope: getScope(req)
                },
              method: 'POST',
              headers: {
                  'Content-Type': 'application/x-www-form-urlencoded'
              }
          }

          request(clientServerOptions, function (error, response) {

                const body = JSON.parse(response.body);

                if (response.statusCode != 200) {
                      try {
                        res.render("client_credentials", {
                        request: clientServerOptions, response: response, error: body.error, error_description: body.error_description});
                      } catch (err) {
                        console.log(err);
                        next(err);
                      }
                } else {

                  try {
                  req.session.access_token = body.access_token;
                  req.session.client_id = req.body.client_id;
                    res.render("client_credentials", {
                    request: clientServerOptions, response: response, access_token: body.access_token});

                  } catch (err) {
                    console.log(err);
                    next(err);
                  }
              }
              //return;
          });
});



app.get("/passwordless", async (req, res, next) => {

  try {
    req.session.send = "";
    res.render("passwordless", {
    send: req.session.send});

  } catch (err) {
    console.log(err);
    next(err);
  }
});


app.post("/passwordless", async (req, res, next) => {
    if (req.body.otp) {
             var clientServerOptions = {
                 uri: 'https://'+process.env.DOMAIN+'/oauth/token',
                   json: {
                     client_id: req.body.client_id,
                     client_secret: req.body.client_secret,
                     username: req.body.username,
                     realm: req.body.realm,
                     otp: req.body.otp,
                     grant_type: req.body.grant_type,
                     audience: req.body.audience,
                     scope: getScope(req)
                   },
                 method: 'POST',
                 headers: {
                     'Content-Type': 'application/json',
                     'auth0-forwarded-for': req.body.user_ip
                 }
             }
             var username = req.body.username;

             request(clientServerOptions, function (error, response) {

                   if (response.statusCode != 200) {
                         try {

                           res.render("passwordless", {
                           request: clientServerOptions, response: response, error: response.body.error, error_description: response.body.error_description, mfa_token: response.body.mfa_token, realm: req.body.realm, audience: req.body.audience, scope: req.body.scope, username: username, send: req.session.send});
                         } catch (err) {
                           console.log(err);
                           next(err);
                         }
                   } else {

                     try {
                       req.session.access_token = response.body.access_token;
                       req.session.refresh_token = response.body.refresh_token;
                       req.session.id_token = response.body.id_token;
                       req.session.client_id = req.body.client_id;
                       res.render("passwordless", {
                       request: clientServerOptions, response: response, access_token: response.body.access_token, id_token: response.body.id_token, refresh_token: response.body.refresh_token});

                     } catch (err) {
                       console.log(err);
                       next(err);
                     }
                 }
                 //return;
             });
    } else if(req.body.access_token || req.body.id_token) {
         try {
           req.session.access_token = req.body.access_token;
           req.session.refresh_token = req.body.refresh_token;
           req.session.id_token = req.body.id_token;
           req.session.client_id = req.body.client_id;
           res.render("passwordless", {
           request: req.body.request, response: req.body.response, error: req.body.error, error_description: req.body.error_description, access_token: req.body.access_token, id_token: req.body.id_token, refresh_token: req.body.refresh_token});


         } catch (err) {
           console.log(err);
           next(err);
         }
    } else {
      var clientServerOptions = {
          uri: 'https://'+process.env.DOMAIN+'/passwordless/start',
            json: {
              client_id: req.body.client_id,
              connection: req.body.connection,
              client_secret: req.body.client_secret,
              send: req.body.send,
              authParams: { redirect_uri: req.body.redirect_uri, audience: req.body.audience, scope: getScope(req), response_type: req.body.response_type, response_mode: req.body.response_mode, nonce: req.body.nonce, state: req.body.state }
            },
          method: 'POST',
          headers: {
              'Content-Type': 'application/json',
              'auth0-forwarded-for': req.body.user_ip
          }
      }
//        if (req.body.client_secret.length>0 && req.body.client_id == process.env.CLIENT_ID) {
//          clientServerOptions.json.client_secret = req.body.client_secret
//        }
      var username = "";
       if (req.body.email!="" && req.body.connection == "email") {
        clientServerOptions.json.email = req.body.email;
        username = req.body.email;
       } else if(req.body.connection == "sms" && req.body.phone_number!="") {
        clientServerOptions.json.phone_number = req.body.phone_number;
        username = req.body.phone_number;
       }
      request(clientServerOptions, function (error, response) {

            if (response.statusCode != 200) {
                  try {
                    res.render("passwordless", {
                    request: clientServerOptions, response: response, error: response.body.error, error_description: response.body.error_description, mfa_token: response.body.mfa_token});
                  } catch (err) {
                    console.log(err);
                    next(err);
                  }
            } else {

              try {
                req.session.send = req.body.send;
                res.render("passwordless", {
                request: clientServerOptions, response: response, realm: req.body.connection, audience: req.body.audience, scope: getScope(req), username: username, send: req.body.send});
              } catch (err) {
                console.log(err);
                next(err);
              }
          }
          //return;
      });
    }
});




app.get("/password", async (req, res, next) => {
  try {
    res.render("password", {
    });
  } catch (err) {
    console.log(err);
    next(err);
  }
});

function getScope(req) {

    var scope = "";

    if (req.body.scope_email) {
        scope = scope + " email"
    }

    if (req.body.scope_profile) {
        scope = scope + " profile"
    }

    if (req.body.scope_openid) {
        scope = scope + " openid"
    }

    if (req.body.scope_offline_access) {
        scope = scope + " offline_access"
    }

    if (req.body.scope_read) {
        scope = scope + " read:test"
    }

    if (req.body.scope_write) {
        scope = scope + " write:test"
    }

    if (req.body.scope_stepup) {
        scope = scope + " stepup:test"
    }

    if (req.body.scope) {
        scope = scope + " " + req.body.scope;
    }

    scope=scope.trim();

    return scope;
}


app.post("/password", async (req, res, next) => {

        req.session.test1 = "sdfsdf";

          var clientServerOptions = {
              uri: 'https://'+process.env.DOMAIN+'/oauth/token',
                form: {
                  grant_type: req.body.grant_type,
                  client_id: req.body.client_id,
                  client_secret: req.body.client_secret,
                  username: req.body.username,
                  password: req.body.password,
                  audience: req.body.audience,
                  scope: getScope(req)
                },
              method: 'POST',
              headers: {
                  'Content-Type': 'application/x-www-form-urlencoded',
                  'auth0-forwarded-for': req.body.user_ip
              }
          }
           if (req.body.realm!="" && req.body.grant_type == "http://auth0.com/oauth/grant-type/password-realm") {
            clientServerOptions.form.realm = req.body.realm;
           }
          request(clientServerOptions, function (error, response) {

                const body = JSON.parse(response.body);

                if (response.statusCode != 200) {
                      try {
                        res.render("password", {
                        request: clientServerOptions, response: response, error: body.error, error_description: body.error_description, mfa_token: body.mfa_token});
                        mfa_token = body.mfa_token;
                      } catch (err) {
                        console.log(err);
                        next(err);
                      }
                } else {

                  try {
                    req.session.access_token = body.access_token;
                    req.session.refresh_token = body.refresh_token;
                    req.session.id_token = body.id_token;
                    req.session.client_id = req.body.client_id;

                    req.session.test2 = "dfdf";
                        console.log(req.session.test1);
                        console.log(req.session.test2);
                        console.log("Your IP Addresss is: " + req.socket.localAddress);
                        req.session.save();
                    res.render("password", {
                    request: clientServerOptions, response: response, access_token: body.access_token, id_token: body.id_token, refresh_token: body.refresh_token});

                  } catch (err) {
                    console.log(err);
                    next(err);
                  }
              }
              //return;
          });
});


app.get("/mfa", async (req, res, next) => {
  try {
    res.render("mfa", {
    mfa_token: mfa_token});
  } catch (err) {
    console.log(err);
    next(err);
  }
});

app.post("/mfa", async (req, res, next) => {
          if (req.body.mfa_token && !req.body.authenticator_id && !req.body.oob_code) {
              var clientServerOptions = {
                  uri: 'https://'+process.env.DOMAIN+'/mfa/authenticators?active=true',
                  method: 'GET',
                  headers: {
                      'Authorization': 'Bearer ' + req.body.mfa_token
                  }
              }

              request(clientServerOptions, function (error, response) {

                if (response.statusCode != 200) {
                    const body = JSON.parse(response.body);
                      try {

                        res.render("mfa", {
                        request: clientServerOptions, response: response, error: body.error, error_description: body.error_description, mfa_token: req.body.mfa_token});
                      } catch (err) {
                        console.log(err);
                        next(err);
                      }
                } else {

                  try {
                      const body = JSON.parse(response.body);
                      const authenticator_id = body[0].id;
                      const authenticator_type = body[0].authenticator_type;
                    res.render("mfa", {
                    request: clientServerOptions, response: response, authenticator_id: authenticator_id, challenge_type: authenticator_type, mfa_token: req.body.mfa_token});
                  } catch (err) {
                    console.log(err);
                    next(err);
                  }
              }
                  //return;
              });
   } else if(req.body.authenticator_id && !req.body.oob_code) {

          var clientServerOptions = {
                  uri: 'https://'+process.env.DOMAIN+'/mfa/challenge',
                  method: 'POST',
                  headers: {
                      'Authorization': 'Bearer ' + req.body.mfa_token,
                      'Content-Type': 'application/json'
                  },
                  json: {
                      client_id: req.body.client_id,
                      client_secret: req.body.client_secret,
                      challenge_type: req.body.challenge_type,
                      authenticator_id: req.body.authenticator_id,
                      mfa_token: req.body.mfa_token
                  }
              }

              request(clientServerOptions, function (error, response) {
                const body = response.body;
                if (response.statusCode != 200) {

                      try {

                        res.render("mfa", {
                        request: clientServerOptions, response: response, error: body.error, error_description: body.error_description, mfa_token: req.body.mfa_token, authenticator_id: req.body.authenticator_id});
                      } catch (err) {
                        console.log(err);
                        next(err);
                      }
                } else {

                  try {
                    res.render("mfa", {
                    request: clientServerOptions, response: response, authenticator_id: req.body.authenticator_id, mfa_token: req.body.mfa_token, oob_code: body.oob_code});
                  } catch (err) {
                    console.log(err);
                    next(err);
                  }
              }
                  //return;
              });

   } else if(req.body.oob_code) {

             var clientServerOptions = {
                     uri: 'https://'+process.env.DOMAIN+'/oauth/token',
                     method: 'POST',
                     headers: {
                         'Authorization': 'Bearer ' + req.body.mfa_token,
                         'Content-Type': 'application/x-www-form-urlencoded'
                     },
                     form: {
                         grant_type: req.body.grant_type,
                         client_id: req.body.client_id,
                         client_secret: req.body.client_secret,
                         mfa_token: req.body.mfa_token,
                         oob_code:req. body.oob_code,
                         binding_code: req.body.binding_code
                     }
                 }

                 request(clientServerOptions, function (error, response) {

                   const body = JSON.parse(response.body);
                    if (response.statusCode != 200) {
                      try {
                        res.render("mfa", {
                        request: clientServerOptions, response: response, error: body.error, error_description: body.error_description});
                        mfa_token = body.mfa_token;
                      } catch (err) {
                        console.log(err);
                        next(err);
                      }
                } else {

                  try {
                    req.session.access_token = body.access_token;
                    req.session.refresh_token = body.refresh_token;
                    req.session.id_token = body.id_token;
                    res.render("mfa", {
                    request: clientServerOptions, response: response, access_token: body.access_token, id_token: body.id_token, refresh_token: body.refresh_token});

                  } catch (err) {
                    console.log(err);
                    next(err);
                  }
              }
                     //return;
                 });

      }
});



app.get("/user_info", async (req, res, next) => {
  try {
    res.render("user_info", { access_token: req.session.access_token, id_token: req.session.id_token});
  } catch (err) {
    next(err);
  }
});

app.post("/user_info", async (req, res, next) => {
 try {

      var clientServerOptions = {
          uri: req.body.user_info_endpoint,
          method: 'GET',
          headers: {
              'Authorization': 'Bearer ' + req.body.access_token
          }
      }

      request(clientServerOptions, function (error, response) {

            if (response.statusCode == 200) {
                   res.render("user_info", {
                     request: clientServerOptions, response: response, data: response.body, access_token: access_token
                   });
            } else {
                res.render("user_info", {
                request: clientServerOptions, response: response, error: response.body, access_token: access_token
                });
            }

   });
 } catch (err) {
    console.log(err);
   next(err);
 }
});

app.get("/call_api", async (req, res, next) => {
  try {
    console.log(req.session.test1);
    console.log(req.session.test2);
    console.log("Your IP Addresss is: " + req.socket.localAddress);
    req.session.save();
    res.render("call_api", { access_token: req.session.access_token});
  } catch (err) {
    next(err);
  }
});

app.post("/call_api", async (req, res, next) => {
 try {
     var uri = "/read-api";
     if (req.body.action == "write") {
        uri = "/write-api";
     }

      var clientServerOptions = {
          uri: process.env.API_URL + uri,
          method: 'GET',
          headers: {
              'Authorization': 'Bearer ' + req.body.access_token
          }
      }

      request(clientServerOptions, function (error, response) {

            if (response.statusCode == 200) {
                   res.render("call_api", {
                     request: clientServerOptions, response: response, data: response.body, access_token: req.session.access_token
                   });
            } else {
                res.render("call_api", {
                request: clientServerOptions, response: response, error: response.body, access_token: req.session.access_token
                });
            }

   });
 } catch (err) {
    console.log(err);
   next(err);
 }
});

// catch 404 and forward to error handler
app.use(function (req, res, next) {
  next(createError(404));
});

// error handler
//app.use(function (err, req, res, next) {
//  res.locals.message = err.message;
//  res.locals.error = err;
//
//  // render the error page
//  res.status(err.status || 500);
//  res.render("error", {
//    user: req.oidc && req.oidc.user,
//  });
//});

createServer(app).listen(PORT, () => {
  console.log(`WEB APP: ${APP_URL}`);
});
