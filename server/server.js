const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const { Fido2Lib } = require('fido2-lib');
const cors = require('cors');
const session = require('express-session');

const app = express();
app.use(bodyParser.json());
app.use(cors({
  origin: 'http://localhost:3000', // Your frontend URL
  credentials: true
}));

// Set up session management
app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false, httpOnly: true, sameSite: 'lax' } // Adjust as needed
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
  }
};

const saveData = () => {
  fs.writeFileSync('users.json', JSON.stringify(users, null, 2));
};

loadData();

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

  console.log('Register Request:', req.session); // Logging

  res.json(registrationOptions);
});

app.post('/register', async (req, res) => {
  const { username, attestationResponse } = req.body;
  console.log('Register:', req.session); // Logging
  if (!req.session.challenge) {
    return res.status(400).send('Challenge not found in session');
  }

  // Convert response fields to ArrayBuffer
  attestationResponse.rawId = Uint8Array.from(atob(attestationResponse.rawId), c => c.charCodeAt(0)).buffer;
  attestationResponse.response.clientDataJSON = Uint8Array.from(atob(attestationResponse.response.clientDataJSON), c => c.charCodeAt(0)).buffer;
  attestationResponse.response.attestationObject = Uint8Array.from(atob(attestationResponse.response.attestationObject), c => c.charCodeAt(0)).buffer;

  const attestation = await fido2.attestationResult(attestationResponse, {
    challenge: Buffer.from(req.session.challenge, 'base64'),
    origin: "http://localhost:3000",
    factor: "first" // Change this line
  });

  users.push({ username, credentials: [attestation.authnrData], checkedIn: false });
  saveData();

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

  console.log('Login Request:', req.session); // Logging

  res.json(assertionOptions);
});

app.post('/login', async (req, res) => {
  const { username, assertionResponse } = req.body;
  console.log('Login:', req.session); // Logging
  if (!req.session.challenge) {
    return res.status(400).send('Challenge not found in session');
  }

  // Convert response fields to ArrayBuffer
  assertionResponse.rawId = Uint8Array.from(atob(assertionResponse.rawId), c => c.charCodeAt(0)).buffer;
  assertionResponse.response.clientDataJSON = Uint8Array.from(atob(assertionResponse.response.clientDataJSON), c => c.charCodeAt(0)).buffer;
  assertionResponse.response.authenticatorData = Uint8Array.from(atob(assertionResponse.response.authenticatorData), c => c.charCodeAt(0)).buffer;
  assertionResponse.response.signature = Uint8Array.from(atob(assertionResponse.response.signature), c => c.charCodeAt(0)).buffer;
  if (assertionResponse.response.userHandle) {
    assertionResponse.response.userHandle = Uint8Array.from(atob(assertionResponse.response.userHandle), c => c.charCodeAt(0)).buffer;
  }

  const user = users.find(u => u.username === username);
  if (!user) return res.status(404).send('User not found');

  const assertion = await fido2.assertionResult(assertionResponse, {
    challenge: Buffer.from(req.session.challenge, 'base64'),
    origin: "http://localhost:3000",
    factor: "either"
  });

  res.send('User logged in');
});

app.post('/attendance', async (req, res) => {
  const { username, action } = req.body;
  const user = users.find(u => u.username === username);
  if (!user) return res.status(404).send('User not found');

  user.checkedIn = action === 'checkin';
  saveData();

  res.send(`User ${action} successful`);
});

app.get('/current-users', async (req, res) => {
  const currentUsers = users.filter(user => user.checkedIn);
  res.json(currentUsers.map(user => user.username));
});

const port = process.env.PORT || 3001;
app.listen(port, () => console.log(`Server running on port ${port}`));
