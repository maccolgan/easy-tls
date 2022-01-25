const fs = require('fs').promises
const path = require('path')
const events = require('events')

const express = require('express')
const ACMEClient = require('acme-client')

const EASYTLS_DIR = process.env.EASY_TLS_DIR ? path.resolve(process.env.EASY_TLS_DIR) : path.resolve('.easytls')
const CERT_KEY_PATH = path.join(EASYTLS_DIR, 'cert.key')
const CERT_CRT_PATH = path.join(EASYTLS_DIR, 'cert.pem')
const ACCOUNT_KEY_PATH = path.join(EASYTLS_DIR, 'account.key')

let acmeClient
const emitter = new events.EventEmitter({ captureRejections: true })

const ONE_DAY = 1000 * 60 * 60 * 24
const TIMER_LIMIT = Math.pow(2, 31)

function token2Path (challenge) {
  return ['.well-known', 'acme-challenge', challenge.token].join('/')
}

async function acquireCertificate ({ certificateKey, termsOfServiceAgreed, commonName, altNames }) {
  console.warn('WARNING, IF YOU SET termsOfServiceAgreed to true, YOU AFFIRM YOU HAVE READ THROUGH THE TERMS OF SERVICE AND AGREE WITH IT ENTIRELY.')
  const app = express()
  const dMap = new Map()
  console.log('EASYTLS | ACQUIRING NEW CERTIFICATE FOR:', commonName)
  app.use(function (req, res) {
    const pth = req.path.slice(1)
    console.log('EASYTLS | REQUEST FOR:\t', pth, '\tIP:', req.ip)
    const v = dMap.get(pth)
    if (v != null) {
      res.status(200).contentType('application/octet-stream').send(v)
    } else {
      res.sendStatus(404)
    }
  })
  // Must be 80
  const server = app.listen(80)
  const [, CSR] = await ACMEClient.forge.createCsr({
    commonName,
    altNames
  }, certificateKey)
  console.log('EASYTLS | ACQUIRING CERTIFICATE IN AUTOMODE!')
  const certificate = await acmeClient.auto({
    csr: CSR,
    email: process.env.EASY_TLS_EMAIL,
    termsOfServiceAgreed,
    challengePriority: ['http-01'],
    challengeCreateFn: async (authz, challenge, keyAuthorization) => {
      const path = token2Path(challenge)
      dMap.set(path, keyAuthorization)
    },
    challengeRemoveFn: async (authz, challenge, keyAuthorization) => {
      const path = token2Path(challenge)
      dMap.delete(path)
    }
  })
  // Asynchronous but we aren't going to wait for it to end
  server.close()
  console.log('EASYTLS | ACQUIRED CERTIFICATE IN AUTOMODE')
  return certificate
}

function setupTimers (expiry, config) {
  const timeRemainingTillNextExpiry = (expiry - ONE_DAY) - Date.now()
  const isBeyondLimit = timeRemainingTillNextExpiry >= TIMER_LIMIT

  const func = async () => {
    const certificateData = await acquireCertificate(config)
    await fs.writeFile(CERT_CRT_PATH, certificateData)
    await processCertificate(certificateData, config)
    emitter.emit('certificateRenewed', certificateData)
  }

  if (expiry <= 0) {
    return func()
  } else if (isBeyondLimit) {
    setTimeout(() => setupTimers(expiry, config), timeRemainingTillNextExpiry - isBeyondLimit)
  } else {
    setTimeout(func, timeRemainingTillNextExpiry)
  }
}

async function processCertificate (certificateData, config) {
  const certInfo = await ACMEClient.forge.readCertificateInfo(certificateData)
  const expiryDateMS = certInfo.notAfter.getTime()
  const nowMS = Date.now()

  // If expiry is within 1 day of the cert
  if ((expiryDateMS - nowMS) <= ONE_DAY) {
    const newCertificateData = await acquireCertificate(config)
    await fs.writeFile(CERT_CRT_PATH, newCertificateData)
    return processCertificate(newCertificateData)
  }
  setupTimers(expiryDateMS, config)
}

async function initializeEasyTLS () {
  let accountKey

  try {
    await fs.mkdir(EASYTLS_DIR)
  } catch (e) {
    console.error('Caught error, but most probably harmless:', e)
  }

  try {
    accountKey = await fs.readFile(ACCOUNT_KEY_PATH)
  } catch (e) {
    if (e.code === 'ENOENT') {
      accountKey = await ACMEClient.forge.createPrivateKey(4096)
      await fs.writeFile(ACCOUNT_KEY_PATH, accountKey)
    } else {
      throw e
    }
  }

  acmeClient = new ACMEClient.Client({
    directoryUrl: ACMEClient.directory.letsencrypt.production,
    accountKey
  })
}

async function initializeCertificates ({ commonName, altNames, termsOfServiceAgreed }) {
  let certificateKey, certificateData

  if (acmeClient == null) {
    await initializeEasyTLS()
  }
  try {
    certificateKey = await fs.readFile(CERT_KEY_PATH)
  } catch (e) {
    if (e.code === 'ENOENT') {
      certificateKey = await ACMEClient.forge.createPrivateKey(4096)
      await fs.writeFile(CERT_KEY_PATH, certificateKey)
    } else {
      throw e
    }
  }

  try {
    certificateData = await fs.readFile(CERT_CRT_PATH)
  } catch (e) {
    if (e.code === 'ENOENT') {
      certificateData = await acquireCertificate({ certificateKey, commonName, altNames, termsOfServiceAgreed })
      await fs.writeFile(CERT_CRT_PATH, certificateData)
    } else {
      throw e
    }
  }
  await processCertificate(certificateData, { certificateKey, commonName, altNames, termsOfServiceAgreed })
  return {
    certificate: certificateData,
    privateKey: certificateKey
  }
}

exports.emitter = emitter
exports.initializeEasyTLS = initializeEasyTLS
exports.acquireCertificate = acquireCertificate
exports.initializeCertificates = initializeCertificates
