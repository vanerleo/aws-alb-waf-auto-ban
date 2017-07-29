"use strict";

var AWS = require('aws-sdk');
var Promise = require('bluebird');
var os = require('os');
var albLogParser = require('alb-log-parser');
var zlib = Promise.promisifyAll(require('zlib'));
const util = require('util')

module.exports.process = (event, context, callback) => {

  console.log(event);
  AWS.config.region = process.env.AWS_REGION;

  var waf = new AWS.WAFRegional({
    region: process.env.AWS_REGION
  });

  return _getIps(event.Records)
    .then(function (ipExceedingMaxRequests) {
      return _createIfMissingIpSet(waf)
        .then(function (ipSet) {
          return _createIfMissingRuleWithIpSet(waf, ipSet)
            .then(function (rule) {
              return _updateWebACL(waf, rule)
                .then(function () {
                  return _updateIpsInSet(waf, ipSet, ipExceedingMaxRequests);
                });
            });
        });

    }).then(function () {

      var response = {
        statusCode: 200,
        body: JSON.stringify({
          message: 'Processed',
          input: event,
        }),
      };
      callback(null, response);
    }).catch(function (err) {
      callback(err);
    });
};

function _getIps(s3Records) {

  var s3 = new AWS.S3();
  var ipSetName = process.env.AWS_LAMBDA_FUNCTION_NAME;
  var maxRequestsPerIP = process.env.MAX_REQUESTS_PER_IP;
  var ipExceedingMaxRequests = [];
  return Promise.map(s3Records, function (s3Record) {
    var bucket = s3Record.s3.bucket.name;
    var key = s3Record.s3.object.key;

    var param = {
      Bucket: bucket,
      Key: key
    };
    return s3.getObject(param).promise().then(function (data) {
      // console.log('data', typeof (data), data);
      return zlib.gunzipAsync(data.Body)
        .then(function (buffer) {
          var text = buffer.toString('utf8');
          var lines = text.split(os.EOL);

          var allRequests = [];

          return Promise.map(lines, function (line) {
            if (!line) {
              return;
            }

            var logObj = albLogParser(line);
            if (!allRequests[logObj.client]) {
              allRequests[logObj.client] = [];
            }
            allRequests[logObj.client].push(logObj);
          }).then(function () {
            Object.keys(allRequests).map(function (key) {
              if (allRequests[key] && allRequests[key].length > maxRequestsPerIP) {
                console.log('IP: ', key, 'Accessed: ', allRequests[key].length);
                ipExceedingMaxRequests.push(key);
              }
            });
          });

        });

    });
  }).then(function () {
    return ipExceedingMaxRequests;
  });
}

function _createIfMissingIpSet(waf) {

  var ipSetName = process.env.AWS_LAMBDA_FUNCTION_NAME;
  var params = {
    Limit: 100
  };
  return waf.listIPSets(params).promise()
    .then(function (data) {
      console.log('listIPSets', data);
      var ipSets = data.IPSets.filter(function (ipSet) {
        return ipSet.Name === ipSetName;
      });
      console.log('ipSet', ipSets);
      if (ipSets.length === 1) {
        return ipSets[0];
      }

      params = {};
      console.log('waf.getChangeToken');
      return waf.getChangeToken(params).promise()
        .then(function (data) {
          var changeToken = data.ChangeToken;

          params = {
            ChangeToken: changeToken,
            Name: ipSetName
          };
          console.log('waf.createIPSet');
          return waf.createIPSet(params).promise()
            .then(function (data) {
              console.log('creared', data);
              return data.IPSet;
            });
        })
    });
}

function _updateIpsInSet(waf, ipSet, ipExceedingMaxRequests) {

  var params = {
    IPSetId: ipSet.IPSetId,
  };
  return waf.getIPSet(params).promise()
    .then(function (data) {
      console.log('waf.getIPSet', util.inspect(data, false, null));
      var currentlyBlockedIPs = [];
      data.IPSet.IPSetDescriptors.map(function (iPSetDescriptor) {
        currentlyBlockedIPs.push(iPSetDescriptor.Value);
      });

      var ipsToBlock = [];
      ipExceedingMaxRequests.map(function (ip) {
        ipsToBlock.push(ip + '/32');
      });

      var ipsToAllow = currentlyBlockedIPs.filter(function (currentlyBlockedIP) {
        return ipsToBlock.indexOf(currentlyBlockedIP) === -1;
      });
      console.log('ipsToBlock', ipsToBlock, 'ipsToAllow', ipsToAllow);

      params = {};
      return waf.getChangeToken(params).promise()
        .then(function (data) {
          var changeToken = data.ChangeToken;
          params = {
            ChangeToken: changeToken,
            IPSetId: ipSet.IPSetId,
            Updates: []
          };

          if (ipsToBlock.length === 0 && ipsToAllow.length === 0) {
            return;
          }

          ipsToBlock.map(function (ip) {
            params.Updates.push({
              Action: 'INSERT',
              IPSetDescriptor: {
                Type: 'IPV4',
                Value: ip
              }
            });
          });

          ipsToAllow.map(function (ip) {
            params.Updates.push({
              Action: 'DELETE',
              IPSetDescriptor: {
                Type: 'IPV4',
                Value: ip
              }
            });
          });

          console.log('params.Updates', params.Updates);
          waf.updateIPSet(params).promise()
            .then(function () {
              console.log('Finished waf.updateIPSet', ipSet);
              return ipSet;
            });
        });
    });
}

function _createIfMissingRuleWithIpSet(waf, ipSet) {
  var ruleName = process.env.AWS_LAMBDA_FUNCTION_NAME;

  var params = {
    Limit: 100
  };
  return waf.listRules(params).promise()
    .then(function (data) {
      var rules = data.Rules.filter(function (rule) {
        return rule.Name === ruleName;
      });
      console.log('rules', rules);
      if (rules.length === 1) {
        return rules[0];
      }
      params = {};
      return waf.getChangeToken(params).promise()
        .then(function (data) {
          var changeToken = data.ChangeToken;
          params = {
            ChangeToken: changeToken,
            MetricName: "IPMatch",
            Name: ruleName
          };
          return waf.createRule(params).promise()
            .then(function (data) {
              console.log('waf.createRule', data);
              var rule = data.Rule;
              params = {};
              return waf.getChangeToken(params).promise()
                .then(function (data) {
                  changeToken = data.ChangeToken;
                  params = {
                    ChangeToken: changeToken,
                    RuleId: rule.RuleId,
                    Updates: [{
                      Action: "INSERT",
                      Predicate: {
                        DataId: ipSet.IPSetId,
                        Negated: false,
                        Type: "IPMatch"
                      }
                    }]
                  };
                  console.log('Params for :  waf.updateRule', params);
                  return waf.updateRule(params).promise()
                    .then(function (data) {
                      console.log('waf.updateRule', data);
                      return rule;
                    });
                });
            });
        });
    });
}

function _updateWebACL(waf, rule) {
  var webAclID = process.env.WebACL_ID;
  var ruleName = process.env.AWS_LAMBDA_FUNCTION_NAME;

  var params = {
    WebACLId: webAclID
  };
  return waf.getWebACL(params).promise()
    .then(function (data) {
      var webAclRules = data.WebACL.Rules.filter(function (webAclRules) {
        return webAclRules.RuleId === rule.RuleId;
      });
      console.log('waf.getWebACL.Rules', data.WebACL.Rules);
      if (webAclRules.length > 0) {
        return;
      }
      params = {};
      return waf.getChangeToken(params).promise()
        .then(function (data) {
          var changeToken = data.ChangeToken;
          params = {
            ChangeToken: changeToken,
            DefaultAction: {
              Type: "ALLOW"
            },
            Updates: [{
              Action: "INSERT",
              ActivatedRule: {
                Action: {
                  Type: "BLOCK"
                },
                Priority: 1,
                RuleId: rule.RuleId,
              }
            }],
            WebACLId: webAclID
          };
          return waf.updateWebACL(params).promise()
            .then(function (data) {
              console.log('waf.updateWebAC', data);
            });
        });
    });
}