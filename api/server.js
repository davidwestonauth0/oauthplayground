 // server/server.js
require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const app = express();
const port = process.env.API_PORT || 5002;

const jwt = require("express-jwt");
const jwksRsa = require("jwks-rsa");
const jwt_decode = require("jwt-decode");
const jwtAuthz = require("express-jwt-authz");


app.use(bodyParser.json());
app.use(cors());
app.use(express.urlencoded({ extended: true }));

const expenses = [
  {
    date: new Date(),
    description: "Parcel one",
    value: 102,
  },
  {
    date: new Date(),
    description: "Parcel two",
    value: 42,
  }
];

// Create middleware to validate the JWT using express-jwt
const checkJwt = jwt({
  // Provide a signing key based on the key identifier in the header and the signing keys provided by your Auth0 JWKS endpoint.
  secret: jwksRsa.expressJwtSecret({
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 5,
    jwksUri: `https://${process.env.DOMAIN}/.well-known/jwks.json`,
  }),

  // Validate the audience (Identifier) and the issuer (Domain).
  audience: process.env.AUDIENCE,
  issuer: process.env.ISSUER_BASE_URL+"/",
  algorithms: ["RS256"],
});

// Middleware to check that the access token has the manage:users permission
const checkReadPermission = jwtAuthz(["read:test"], {
  customScopeKey: "permissions",
});

// Middleware to check that the access token has the manage:users permission
const checkWritePermission = jwtAuthz(["write:test"], {
  customScopeKey: "permissions",
});

app.get("/read-api", checkJwt, checkReadPermission, async (req, res) => {

      try {

        res.status(200).send(expenses);

      } catch (err) {
        console.log(err);
        res.status(401).send(err);
      }

});

app.get("/write-api", checkWritePermission, checkJwt, async (req, res) => {

      try {


        res.status(200).send(expenses);

      } catch (err) {
        console.log("IN ERROR");
        console.log(err);
        res.status(401).send(err);
      }

});



app.get("/", (req, res) => {
  res.send(`Hi! Server is listening on port ${port}`);
});

app.use(function (error, req, res, next) {
  // Any request to this server will get here, and will send an HTTP
  // response with the error message 'woops'
  console.log(error);
  res.json({ message: error });
});

// listen on the port
app.listen(port);
