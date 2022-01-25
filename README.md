### What

A simple way to acquire TLS certificates without running an HTTP server. Useful for other protocols that work with TLS.

Currently, HTTP-based protocols have an unfair advantage where they are reasonably easy to set up and run via a reverse proxy, where TLS is handled and terminated that the reverse proxy.

However, most other protocols don't get the same advantage, for example SMTP and et cetra absolutely need TLS but there's no turnkey, self-contained way to get certificates without also carrying the burden of manually maintaining them. In the case that you do, you lose source IP and port information that you don't necessarily need to lose if you do it right.

This is a self-contained library that acquires and renews certificates for domains you configure, persisting such state at an environment variable specified location.

### How

```shell
npm i git+https://github.com/maccolgan/easy-tls.git#dfcca61d537c53786fa5474ce84b84bf6aa4b77c
yarn add git+https://github.com/maccolgan/easy-tls.git#dfcca61d537c53786fa5474ce84b84bf6aa4b77c
```

```javascript
// Set the environment variable EASY_TLS_EMAIL to whoever's responsible
const easyTLS = require('easy-tls')

const { privateKey, certificate } = await easyTLS.initializeCertificates({
  commonName: 'my.domain'
})
// Run your server

easyTLS.emitter.on('certificateRenewed', async function () {
  // Most libraries don't support changing the TLS certificate in place, but if you do manage to do so, you can do it here
  // Otherwise you can just restart your server here
})
```

You can configure the environment variable `EASY_TLS_DIR` to set where your want the state to be persisted.
