var request = require('./request').request,
  async = require('async'),
  fs = require('fs'),
  parser = require('xml2js'),
  path = require('path'),
  saml = fs.readFileSync(__dirname + '/config/saml.xml').toString();


var extractCookies = function(headers) {
  var cookies = {};
  headers['set-cookie'].forEach(function(value) {
    var parsedCookies = value.split(/\=(.+)?/);
    parsedCookies[1] = parsedCookies[1].substr(0, parsedCookies[1].indexOf(';'));
    cookies[parsedCookies[0]] = parsedCookies[1];
  });

  return cookies;
};

function getCustomerDomain(host) {
  var hostParts = host.split('://');
  var hostname = hostParts[1].split('/')[0].split('.')[0];
  return hostname;
}

function xml2js(resp) {
  return new Promise(function(resolve, reject) {
    parser.parseString(resp.body, {explicitArray: false}, function(err, result) {
      err ? reject({message: 'Error parsing XML: ' + err}) : resolve(result);
    });
  });
}

module.exports = function(options, callback) {
  var asyncTasks = [];
  var customerDomain = getCustomerDomain(options.host).trim();

  //Replace username, pwd and URL into SAML.xml
  asyncTasks.push(function(callback) {
    var samlBody = saml;
    samlBody = samlBody.replace('{username}', options.auth.username);
    samlBody = samlBody.replace('{password}', options.auth.password);
    samlBody = samlBody.replace('{url}', options.host);
    callback(null, samlBody);
  });

  // Get the Security Token
  asyncTasks.push(function(samlBody, cb) {
    var options = {
      method: 'POST',
      url: 'https://login.microsoftonline.com/extSTS.srf',
      body: samlBody,
      strictSSL: false,
      followRedirect: true
    };

    request(options)
    .then(xml2js)
    .then(function(body) {
      var responseBody = body['S:Envelope']['S:Body'];
      var samlError = responseBody['S:Fault'];

      if (samlError) {
        return cb({statusCode: 401, message: 'Error logging in - SAML fault detected.'});
      }

      var token = responseBody['wst:RequestSecurityTokenResponse']['wst:RequestedSecurityToken']['wsse:BinarySecurityToken']._;

      if (!token) {
        return cb({message: 'No token found in response body'});
      }

      cb(null, token);
    })
    .catch(function(exception) {
      cb(exception);
    });
  });

  // Get the Cookies
  asyncTasks.push(function(token, callback) {
    var options = {
      url: 'https://' + customerDomain + '.sharepoint.com/_forms/default.aspx?wa=wsignin1.0',
      method: 'POST',
      body: token,
      followAllRedirects: true,
      jar: true
    };

    request(options)
    .then(function(resp) {
      var cookies = extractCookies(resp.headers);

      callback(null, cookies);
    })
    .catch(function(exception) {
      callback(exception);
    });
  });

  // Get the request digest
  asyncTasks.push(function(cookies, cb) {
    var options = {
      method: 'POST',
      url: 'https://' + customerDomain + '.sharepoint.com/_api/contextinfo',
      followAllRedirects: true,
      headers: {
        'Cookie': 'FedAuth='+ cookies.FedAuth + ';' + 'rtFa=' + cookies.rtFa,
        'Content-Type': 'application/json; odata=verbose',
        'Accept': 'application/json; odata=verbose'
      }
    };

    request(options)
    .then(function(resp) {
      var data = JSON.parse(resp.body),
        requestDigest = data.d.GetContextWebInformation.FormDigestValue,
        requestDigestTimeoutSeconds = data.d.GetContextWebInformation.FormDigestTimeoutSeconds;

      callback(null, {
        requestDigest: requestDigest,
        requestDigestTimeoutSeconds: requestDigestTimeoutSeconds,
        cookies: {
          FedAuth: cookies.FedAuth,
          rtFa: cookies.rtFa
        }
      });
    })
    .catch(function(exception) {
      callback('Exception getting request digest '+ exception);
    });
  });

  return async.waterfall(asyncTasks, callback);
};