require('dotenv').config()

const auth0Cli = require('auth0-deploy-cli')
const config = require('./config.json')


// Retrieve Auth0 Configuration
auth0Cli.dump({
    output_folder: `tenant_config`,
    config: config,
    env: true
})
    .then(() => console.log('Auth0 config dumped successfully!'))
    .catch(err => console.log(`An error occured while attempting to dump Auth0 config: ${err}`))