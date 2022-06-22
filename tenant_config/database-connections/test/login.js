function login(email, password, callback) {
  const request = require('request');

  request.post({
    url: 'https://next-plc-test.eu-dev.janraincapture.com/oauth/auth_native_traditional',
    form: {
      client_id: "k79xk7us4wbnewhxrqgp6dun4swb9j3g",
      client_secret:"87tzz53f5y9ppym7mg4bq2k3yyy2e75t",
      flow: "standard",      
      form: "signInForm",
      accountNoOrEmail: email,
      currentPassword: password,
      locale: "en-US",
      redirect_uri: "http://localhost:5000/forgotpassword/token",
      accountTypeId: 3
    }
    //for more options check:
    //https://github.com/mikeal/request#requestoptions-callback
  }, function(err, response, body) {
    if (err) return callback(err);
    if (response.statusCode === 401) return callback();
    const user = JSON.parse(body);
    //console.log(user);
    console.log(user.capture_user.uuid);
    console.log(user.capture_user.accountNumber);
    console.log(user.capture_user.email);

    callback(null, {
      user_id: user.capture_user.uuid,
      nickname: user.capture_user.accountNumber,
      email: user.capture_user.email,
      user_metadata: user.user_metadata
    });
  });
}