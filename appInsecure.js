const express = require('express');
const bodyParser = require('body-parser');

const app = express();
const port = 3001;

app.use(bodyParser.json());

app.post('/unsicher/auth', (req, res) => {
    const username = req.body.username;
    const password = req.body.password;

    if (username === 'admin' && password === 'admin123') {
        res.send('Unsicherer Authentifizierungs- und Autorisierungsendpunkt - Zugriff gestattet');
    } else {
        res.status(401).send('Unsicherer Authentifizierungs- und Autorisierungsendpunkt - Zugriff verweigert');
    }
});

app.listen(port, () => {
    console.log(`Unsichere App läuft auf http://localhost:${port}`);
});
