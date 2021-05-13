const util = require('util');
const jsonwebtoken = require('jsonwebtoken');
const jwkToPem = require('jwk-to-pem');
const ssm = new (require('aws-sdk/clients/ssm'))();

const identityServiceUrl = process.env.IDENTITY_SERVICE_URL || 'http://internal-new-customer-platform-dev-alb-685991238.ap-southeast-1.elb.amazonaws.com';
if (!identityServiceUrl) {
  throw new Error('env var required for identity service url');
}
const identityIssuer = `${identityServiceUrl}/auth/realms/identity`;

const identityServicePublicKeyParameterName = process.env.IDENTITY_SERVICE_PUBLIC_KEY_PARAMETER_NAME || 'identity-service-keycloak-public-key';
if (!identityServicePublicKeyParameterName) {
  throw new Error('env var required for ssm parameter name of identity service public key');
}

let cacheKeys;
const getPublicKeys = async () => {
  if (!cacheKeys) {
    const ssmGetResult = await ssm.getParameter({
      Name: identityServicePublicKeyParameterName
    }).promise();
    const ssmParameterValue = JSON.parse(ssmGetResult.Parameter.Value);
    const publicKeys = ssmParameterValue.keys;
    cacheKeys = publicKeys.reduce((agg, current) => {
      const pem = jwkToPem(current);
      agg[current.kid] = { instance: current, pem };
      return agg;
    }, {});
    return cacheKeys;
  } else {
    return cacheKeys;
  }
};

const verifyPromised = util.promisify(jsonwebtoken.verify.bind(jsonwebtoken));

async function verifyAccessToken(token) {
  let result;
  try {
    const tokenSections = (token || '').split('.');
    if (tokenSections.length < 2) {
      throw new Error('requested token is invalid');
    }
    const headerJSON = Buffer.from(tokenSections[0], 'base64').toString('utf8');
    const header = JSON.parse(headerJSON);
    const keys = await getPublicKeys();
    const key = keys[header.kid];
    if (key === undefined) {
      throw new Error('claim made for unknown kid');
    }
    const claim = await verifyPromised(token, key.pem);
    const currentSeconds = Math.floor((new Date()).valueOf() / 1000);
    if (currentSeconds > claim.exp || currentSeconds < claim.auth_time) {
      throw new Error('claim is expired or invalid');
    }
    if (claim.iss !== identityIssuer) {
      throw new Error('claim issuer is invalid');
    }
    result = { username: claim.customer_uuid, clientId: claim.azp, scope: claim.scope, isValid: true };
  } catch (error) {
    console.log(error);
    result = { username: '', clientId: '', error, isValid: false };
  }
  console.log(`identity verify result: ${JSON.stringify(result)}`);
  return result;
}

module.exports = { verifyAccessToken }