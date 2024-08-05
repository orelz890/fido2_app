const express = require('express');
const bodyParser = require('body-parser');
const { Fido2Lib } = require('fido2-lib');
const cors = require('cors');
const session = require('express-session');
const fs = require('fs');

const app = express();
app.use(bodyParser.json());
app.use(cors({
  origin: 'http://localhost:3000',
  credentials: true
}));

app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false, httpOnly: true, sameSite: 'lax' }
}));

const fido2 = new Fido2Lib({
  timeout: 60000,
  rpId: "localhost",
  rpName: "Company",
  challengeSize: 32,
  authenticatorAttachment: "cross-platform",
  authenticatorRequireResidentKey: false,
  authenticatorUserVerification: "preferred"
});

let users = [];
const loadData = () => {
  if (fs.existsSync('users.json')) {
    const data = fs.readFileSync('users.json');
    users = JSON.parse(data);
    console.log('Loaded users:', users);
  }
};

const saveData = () => {
  fs.writeFileSync('users.json', JSON.stringify(users, null, 2));
  console.log('Saved users:', users);
};

loadData();

let signedInUsers = new Set();

app.post('/register-request', async (req, res) => {
  const { username } = req.body;
  const user = users.find(u => u.username === username);
  if (user) return res.status(400).send('User already exists');

  const registrationOptions = await fido2.attestationOptions();
  registrationOptions.challenge = Buffer.from(registrationOptions.challenge).toString('base64');
  registrationOptions.user = {
    id: Buffer.from(username).toString('base64'),
    name: username,
    displayName: username,
  };

  req.session.challenge = registrationOptions.challenge;
  req.session.username = username;

  console.log('Register Request:', req.session);

  res.json(registrationOptions);
});

app.post('/register', async (req, res) => {
  const { username, attestationResponse } = req.body;
  if (!req.session.challenge) {
    return res.status(400).send('Challenge not found in session');
  }

  attestationResponse.rawId = Uint8Array.from(atob(attestationResponse.rawId), c => c.charCodeAt(0)).buffer;
  attestationResponse.response.clientDataJSON = Uint8Array.from(atob(attestationResponse.response.clientDataJSON), c => c.charCodeAt(0)).buffer;
  attestationResponse.response.attestationObject = Uint8Array.from(atob(attestationResponse.response.attestationObject), c => c.charCodeAt(0)).buffer;

  const attestation = await fido2.attestationResult(attestationResponse, {
    challenge: Buffer.from(req.session.challenge, 'base64'),
    origin: "http://localhost:3000",
    factor: "first"
  });

  const user = {
    username,
    credentials: [{
      credId: Buffer.from(attestation.authnrData.get("credId")).toString('base64'),
      publicKey: attestation.authnrData.get("credentialPublicKeyPem"),
      counter: attestation.authnrData.get("counter")
    }]
  };

  users.push(user);
  saveData();

  console.log('Registered user:', user);

  res.send('User registered');
});

app.post('/login-request', async (req, res) => {
  const { username } = req.body;
  const user = users.find(u => u.username === username);
  if (!user) return res.status(404).send('User not found');

  const assertionOptions = await fido2.assertionOptions();
  assertionOptions.challenge = Buffer.from(assertionOptions.challenge).toString('base64');
  assertionOptions.allowCredentials = user.credentials.map(cred => ({ type: 'public-key', id: cred.credId }));

  req.session.challenge = assertionOptions.challenge;
  req.session.username = username;

  console.log('Login Request:', req.session);

  res.json(assertionOptions);
});

app.post('/login', async (req, res) => {
  const { username, assertionResponse } = req.body;
  if (!req.session.challenge) {
    return res.status(400).send('Challenge not found in session');
  }

  console.log('Received login request with assertionResponse:', assertionResponse);

  assertionResponse.rawId = Uint8Array.from(atob(assertionResponse.rawId), c => c.charCodeAt(0)).buffer;
  assertionResponse.response.clientDataJSON = Uint8Array.from(atob(assertionResponse.response.clientDataJSON), c => c.charCodeAt(0)).buffer;
  assertionResponse.response.authenticatorData = Uint8Array.from(atob(assertionResponse.response.authenticatorData), c => c.charCodeAt(0)).buffer;
  assertionResponse.response.signature = Uint8Array.from(atob(assertionResponse.response.signature), c => c.charCodeAt(0)).buffer;
  if (assertionResponse.response.userHandle) {
    assertionResponse.response.userHandle = Uint8Array.from(atob(assertionResponse.response.userHandle), c => c.charCodeAt(0)).buffer;
  } else {
    assertionResponse.response.userHandle = null;
  }

  const user = users.find(u => u.username === username);
  if (!user) {
    console.log('User not found:', username);
    return res.status(404).send('User not found');
  }

  console.log('User credentials:', user.credentials);

  const cred = user.credentials.find(c => c.credId === Buffer.from(assertionResponse.rawId).toString('base64'));
  if (!cred) {
    console.log('Credential not found for ID:', Buffer.from(assertionResponse.rawId).toString('base64'));
    return res.status(404).send('Credential not found');
  }

  console.log('Login credential found:', cred);

  const assertion = await fido2.assertionResult(assertionResponse, {
    challenge: Buffer.from(req.session.challenge, 'base64'),
    origin: "http://localhost:3000",
    factor: "either",
    publicKey: cred.publicKey,
    prevCounter: cred.counter,
    userHandle: assertionResponse.response.userHandle
  });

  // Update the counter
  cred.counter = assertion.authnrData.get("counter");
  saveData();

  signedInUsers.add(username);
  console.log('User logged in:', username);

  res.send('User logged in');
});

app.post('/logout', (req, res) => {
  const { username } = req.body;
  signedInUsers.delete(username);
  console.log('User logged out:', username);
  res.send('User logged out');
});

app.get('/current-users', (req, res) => {
  res.json(Array.from(signedInUsers));
});

const port = process.env.PORT || 3001;
app.listen(port, () => console.log(`Server running on port ${port}`));
