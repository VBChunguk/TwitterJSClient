/*
 Twitter client app
 */

var OAuth = require('oauth').OAuth;
var qs = require('qs');

function Twitter(config) {
    this.consumerKey = config.consumerKey;
    this.consumerSecret = config.consumerSecret;
    this.accessToken = config.accessToken;
    this.accessTokenSecret = config.accessTokenSecret;
    this.callBackUrl = config.callBackUrl;
    this.debug = config.debug;
    this.baseUrl = [config.baseUrl, config.version].join('/');
    this.oauth = new OAuth(
        'https://api.twitter.com/oauth/request_token',
        'https://api.twitter.com/oauth/access_token',
        this.consumerKey,
        this.consumerSecret,
        '1.0',
        this.callBackUrl,
        'HMAC-SHA1'
    );
}

Twitter.prototype.getOAuthRequestToken = function (next) {
    this.oauth.getOAuthRequestToken((function (error, oauth_token, oauth_token_secret, results) {
        if (error) {
            if (this.debug)
                console.error('ERROR: ' + error);
            next(error);
        }
        else {
            var oauth = {};
            oauth.token = oauth_token;
            oauth.token_secret = oauth_token_secret;
            if (this.debug) {
                console.error('oauth.token: ' + oauth.token);
                console.error('oauth.token_secret: ' + oauth.token_secret);
            }
            next(null, oauth);
        }
    }).bind(this));
};

Twitter.prototype.getOAuthRequestTokenAsync = function() {
    return new Promise((function(resolve, reject) {
        this.getOAuthRequestToken(function(err, oauth) {
            if (err) reject(err);
            else resolve(oauth);
        })
    }).bind(this));
};

Twitter.prototype.getOAuthAccessToken = function (oauth, next) {
    this.oauth.getOAuthAccessToken(oauth.token, oauth.token_secret, oauth.verifier,
        (function (error, oauth_access_token, oauth_access_token_secret, results) {
            if (error) {
                if (this.debug)
                    console.error('ERROR: ' + error);
                next(error);
            } else {
                oauth.access_token = oauth_access_token;
                oauth.access_token_secret = oauth_access_token_secret;
                if (this.debug) {
                    console.error('oauth.token: ' + oauth.token);
                    console.error('oauth.token_secret: ' + oauth.token_secret);
                    console.error('oauth.access_token: ' + oauth.access_token);
                    console.error('oauth.access_token_secret: ' + oauth.access_token_secret);
                }
                next(null, oauth);
            }
        }).bind(this)
    );
};

Twitter.prototype.getOAuthAccessTokenAsync = function(oauth) {
    return new Promise((function(resolve, reject) {
        this.getOAuthAccessToken(oauth, function(err, oauth) {
            if (err) reject(err);
            else resolve(oauth);
        });
    }).bind(this));
};

Twitter.prototype.postMedia = function (params) {
    var url = 'https://upload.twitter.com/1.1/media/upload.json';
    return new Promise((function(resolve, reject) {
        this.doPost(url, params, function(err, response, body) {
            reject({
                error: err,
                response: response,
                body: body
            });
        }, function(body, limits) {
            resolve({
                data: body,
                limits: limits
            });
        }, contentType);
    }).bind(this));
};

Twitter.prototype.get = function (url, params) {
    var path =  url + this.buildQS(params);
    var url = this.baseUrl + path;
    return new Promise((function(resolve, reject) {
        this.doRequest(url, function(err, response, body) {
            reject({
                error: err,
                response: response,
                data: body
            });
        }, function(body, limits) {
            resolve({
                data: body,
                limits: limits
            });
        });
    }).bind(this));
};

Twitter.prototype.post = function (url, params, contentType) {
    var path =  url;
    var url = this.baseUrl + path;
    return new Promise((function(resolve, reject) {
        this.doPost(url, params, function(err, response, body) {
            reject({
                error: err,
                response: response,
                body: body
            });
        }, function(body, limits) {
            resolve({
                data: body
            });
        }, contentType);
    }).bind(this));
};

Twitter.prototype.doRequest = function (url, error, success) {
    // Fix the mismatch between OAuth's  RFC3986's and Javascript's beliefs in what is right and wrong ;)
    // From https://github.com/ttezel/twit/blob/master/lib/oarequest.js
    url = url.replace(/\!/g, "%21")
        .replace(/\'/g, "%27")
        .replace(/\(/g, "%28")
        .replace(/\)/g, "%29")
        .replace(/\*/g, "%2A");

    this.oauth.get(url, this.accessToken, this.accessTokenSecret, (function (err, body, response) {
        if (this.debug)
            console.error('URL [%s]', url);

        if (!err && response.statusCode < 400) {
            var limits = {
                "x-rate-limit-limit": response.headers['x-rate-limit-limit'],
                "x-rate-limit-remaining": response.headers['x-rate-limit-remaining'],
                "x-rate-limit-reset": response.headers['x-rate-limit-reset']
            };
            success(JSON.parse(body), limits);
        } else {
            error(err, response, JSON.parse(body));
        }
    }).bind(this));
};

Twitter.prototype.doPost = function (url, post_body, error, success, contentType) {
    // Fix the mismatch between OAuth's  RFC3986's and Javascript's beliefs in what is right and wrong ;)
    // From https://github.com/ttezel/twit/blob/master/lib/oarequest.js
    url = url.replace(/\!/g, "%21")
        .replace(/\'/g, "%27")
        .replace(/\(/g, "%28")
        .replace(/\)/g, "%29")
        .replace(/\*/g, "%2A");
    //(url, oauth_token, oauth_token_secret, post_body, post_content_type, callback
    this.oauth.post(url, this.accessToken, this.accessTokenSecret, post_body, contentType || "application/x-www-form-urlencoded", (function (err, body, response) {
        if (this.debug)
            console.log('URL [%s]', url);
        if (err || response.statusCode >= 400) {
            error(err, response, JSON.parse(body));
        } else {
            success(JSON.parse(body));
        }
    }).bind(this));
};

Twitter.prototype.buildQS = function (params) {
    if (params && Object.keys(params).length > 0) {
        return '?' + qs.stringify(params);
    }
    return '';
};

module.export = Twitter;
