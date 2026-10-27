// Exercise the actual packaged Wazuh client, including its HTTPS agent and
// authentication method. The same request must succeed with the correct CA
// and fail specifically for certificate trust with an unrelated CA.
const { ServerAPIClient } = require(process.argv[2]);
const expected = process.argv[3];
const client = new ServerAPIClient({}, {
  get: async () => ({url: 'https://server', port: 55000,
                    username: 'wazuh-wui', password: 'Test-password-42!'})
}, {});
client.asInternalUser.authenticate('test').then(token => {
  if (expected !== 'success' || token !== 'test-token') process.exit(1);
}).catch(error => {
  const code = error.code || (error.cause && error.cause.code);
  if (expected !== 'untrusted' || ![
    'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'SELF_SIGNED_CERT_IN_CHAIN',
    'UNABLE_TO_GET_ISSUER_CERT_LOCALLY', 'DEPTH_ZERO_SELF_SIGNED_CERT'
  ].includes(code)) {
    console.error(error);
    process.exit(1);
  }
});
