
const cognitoService = require('./cognito-service');
const identityService = require('./identity-service');
const scopeValidator = require('./scope-validator')

exports.handler = async function (event, context, callback) {
  var accessToken = event.authorizationToken;

  const verifyAccessTokenResult = await verifyAccessToken(accessToken);
  if (!verifyAccessTokenResult.isValid) {
    callback("Unauthorized");
  }

  const validateScopeResult = scopeValidator.validateScope(event.methodArn, verifyAccessTokenResult.scope);
  if (!validateScopeResult.isValid) {
    callback(null, generatePolicy('user', 'Deny', event.methodArn));
  }

  callback(null, generatePolicy('user', 'Allow', event.methodArn));
};

async function verifyAccessToken(accessToken) {
  const cognitoTokenValidateResult = await cognitoService.verifyAccessToken(accessToken);
  if (cognitoTokenValidateResult.isValid) {
    return cognitoTokenValidateResult;
  }

  const identityTokenValidateResult = await identityService.verifyAccessToken(accessToken);
  return identityTokenValidateResult;
}

function generatePolicy(principalId, effect, resource) {
  var authResponse = {};

  authResponse.principalId = principalId;
  if (effect && resource) {
    var policyDocument = {};
    policyDocument.Version = '2012-10-17';
    policyDocument.Statement = [];
    var statementOne = {};
    statementOne.Action = 'execute-api:Invoke';
    statementOne.Effect = effect;
    statementOne.Resource = resource;
    policyDocument.Statement[0] = statementOne;
    authResponse.policyDocument = policyDocument;
  }

  return authResponse;
}