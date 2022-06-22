function addPersistenceAttribute(user, context, callback) {
  context.clientMetadata = context.clientMetadata || {};
  context.idToken.country_code =  context.clientMetadata.country_code || 'GB';
  context.idToken.acc_number = user.acc_number;
  context.accessToken.acc_number = user.acc_number;

  auth0.users
    .updateUserMetadata(user.user_id, user.user_metadata)
    .then(function () {
      callback(null, user, context);
    })
    .catch(function (err) {
      callback(err);
    });
}