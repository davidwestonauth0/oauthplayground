function (user, context, callback) {
  if (context.clientMetadata && context.clientMetadata.shopify_domain && context.clientMetadata.shopify_multipass_secret)
  {
    const RULE_NAME = 'shopify-multipasstoken';
    const CLIENTNAME = context.clientName;
    console.log(`${RULE_NAME} started by ${CLIENTNAME}`);

    const now = (new Date()).toISOString();
    let shopifyToken = {
      email: user.email,
      created_at: now,
      identifier: user.user_id,
      remote_ip: context.request.ip
    };
    if (context.request && context.request.query && context.request.query.return_to){
      shopifyToken.return_to = context.request.query.return_to;
    }

    if (context.user_metadata)
    {
      shopifyToken.first_name = user.user_metadata.given_name;
      shopifyToken.last_name= user.user_metadata.family_name;
    }

    const hash = crypto.createHash("sha256").update(context.clientMetadata.shopify_multipass_secret).digest();
    const encryptionKey = hash.slice(0, 16);
    const signingKey = hash.slice(16, 32);

    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-128-cbc', encryptionKey, iv);
    const cipherText = Buffer.concat([iv, cipher.update(JSON.stringify(shopifyToken), 'utf8'), cipher.final()]);

    const signed = crypto.createHmac("SHA256", signingKey).update(cipherText).digest();

    const token = Buffer.concat([cipherText, signed]).toString('base64');
    const urlToken = token.replace(/\+/g, '-').replace(/\//g, '_');

   context.redirect = {
     url: `https://${context.clientMetadata.shopify_domain}/account/login/multipass/${urlToken}`
   };
  }
  return callback(null, user, context);
}