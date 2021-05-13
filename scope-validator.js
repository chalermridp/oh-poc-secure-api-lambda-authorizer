const permissionDict = {}

permissionDict['service-api/general'] = [
  { method: 'GET', resource: '^/v0/products/([^/]+)$' },
  { method: 'POST', resource: '^/v0/products$' },
  { method: 'GET', resource: '^/v0/products/categories/([^/]+)$' },
  { method: 'GET', resource: '^/v0/products/promotions$' },
  { method: 'GET', resource: '^/v0/products/search/suggestions$' },
];

permissionDict['L00'] = [
  { method: 'GET', resource: '^/v0/products/([^/]+)$' },
  { method: 'POST', resource: '^/v0/products$' },
  { method: 'GET', resource: '^/v0/products/categories/([^/]+)$' },
  { method: 'GET', resource: '^/v0/products/promotions$' },
  { method: 'GET', resource: '^/v0/products/search/suggestions$' },
];

permissionDict['L12'] = [
  { method: 'GET', resource: '^/v0/products/([^/]+)$' },
  { method: 'POST', resource: '^/v0/products$' },
  { method: 'GET', resource: '^/v0/products/categories/([^/]+)$' },
  { method: 'GET', resource: '^/v0/products/promotions$' },
  { method: 'GET', resource: '^/v0/products/search/suggestions$' },
];

function validateScope(methodArn, scope) {
  var methodArnSplitted = methodArn.split('/');
  var method = methodArnSplitted[2];
  var resource = '';
  for (var i = 4; i < methodArnSplitted.length; i++) {
    resource += '/' + methodArnSplitted[i];
  }

  const scopes = scope.split(' ');
  for (var i = 0; i < scopes.length; i++) {
    const currentScope = scopes[i];
    const permissionList = permissionDict[currentScope];
    if (permissionList) {
      const allowList = permissionList.filter(i => i.method === method && new RegExp(i.resource).test(resource));
      if (allowList) {
        return { isValid: true }
      }
    }
  }

  return { isValid: false };
}

module.exports = { validateScope }