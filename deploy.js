require('dotenv').config()

const auth0Cli = require('auth0-deploy-cli')
const config = require('./config.json')

auth0Cli.deploy({
    input_file: 'tenant_config',
    config: config,
    env: true
})
    .then(() => console.log('Auth0 config deployed successfully!'))
    .catch(err => {
        console.error(`An error occured while attempting to update Auth0 config: ${err}`)
        process.exit(1)
    })