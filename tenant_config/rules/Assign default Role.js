function (user, context, callback) {

    const count = context.stats && context.stats.loginsCount ? context.stats.loginsCount : 0;
    if (count > 1) {
        return callback(null, user, context);
    }

    const ManagementClient = require('auth0@2.27.0').ManagementClient;
    var management = new ManagementClient({
      domain: configuration.AUTH0_DOMAIN,
      clientId: configuration.APIV2_CLIENT_ID,
      clientSecret: configuration.APIV2_CLIENT_SECRET,
      scope: 'read:users update:users'
    });
const params =  { id : user.user_id};
    const data = { "roles" : ["rol_DXamPvYoNnIeihMb"]};
  	console.log(data);

    management.users.assignRoles(params, data, function (err) {
  if (err) {
    console.log(err);
    // Handle error.
  }

  // User assigned roles
    callback(null, user, context);
    });
    
}