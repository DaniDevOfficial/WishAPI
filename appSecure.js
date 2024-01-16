const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const fs = require('fs');
const cors = require('cors');

const app = express();
const port = 3000;
const secretKey = 'MeinGeheimesSchluesselwort';
const saltRounds = 10;
// Benutzerdaten (normalerweise in einer Datenbank gespeichert)
const users = [
    { id: 1, username: 'admin', hashedPassword: '', role: 'admin' },
    { id: 2, username: 'user', hashedPassword: '', role: 'user' },
];

const allowedOrigins = ['https://david-bischof.ch'];
const corsOptions = {
    origin: function (origin, callback) {
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Unerlaubter Zugriff von der angegebenen Domäne.'));
        }
    },
    optionsSuccessStatus: 200,
};

app.use(cors(corsOptions));

const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: 'Zu viele Anfragen von dieser IP, bitte versuchen Sie es später erneut.',
    handler: (req, res) => {
        logToFile(`Rate limit exceeded`);
        res.status(429).send('Zu viele Anfragen von dieser IP, bitte versuchen Sie es später erneut.');
    },
});

app.use(apiLimiter);

const authenticateToken = (req, res, next) => {
    const token = req.header('Authorization');
    if (!token) return res.status(401).send('Fehlende Berechtigung');

    jwt.verify(token, secretKey, (err, user) => {
        if (err) return res.status(403).send('Ungültiger Token');
        req.user = user;
        next();
    });
};

users.forEach(user => {
    bcrypt.hash('admin123', saltRounds, (err, hash) => {
        if (!err) user.hashedPassword = hash;
    });
});

const isValidInput = (input) => /^[a-zA-Z0-9]+$/.test(input);

// Logging-Funktion
const logToFile = (data) => {
    fs.appendFile('log.txt', `${new Date().toISOString()}: ${data}\n`, (err) => {
        if (err) {
            console.error('Fehler beim Schreiben des Logs:', err);
        }
    });
};

app.get('/sicher/auth', authenticateToken, (req, res) => {
    logToFile('Authentifizierter Zugriff auf /sicher/auth');
    if (req.user.role !== 'admin') return res.status(403).send('Keine ausreichenden Berechtigungen');
    res.send('Sicherer Authentifizierungs- und Autorisierungsendpunkt');
});

app.post('/login', bodyParser.json(), (req, res) => {
    const { username, password } = req.body;

    if (!isValidInput(username) || !isValidInput(password)) {
        logToFile(`Ungültige Benutzername oder Passwort: ${username}`);
        return res.status(400).send('Ungültige Benutzername oder Passwort');
    }

    const user = users.find(u => u.username === username);

    if (!user) {
        logToFile(`Ungültige Anmeldeinformationen für Benutzer: ${username}`);
        return res.status(401).send('Ungültige Anmeldeinformationen');
    }

    bcrypt.compare(password, user.hashedPassword, (err, result) => {
        if (result) {
            logToFile(`Erfolgreiche Anmeldung für Benutzer: ${username}`);
            const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, secretKey);
            res.json({ token });
        } else {
            logToFile(`Fehlgeschlagene Anmeldung für Benutzer: ${username}`);
            res.status(401).send('Ungültige Anmeldeinformationen');
        }
    });
});

app.get('/example', (req, res) => {
    logToFile('Anfrage an /example');
    res.send('Diese Route erlaubt nur Anfragen von https://david-bischof.ch.');
});

app.listen(port, () => {
    console.log(`Server läuft auf http://localhost:${port}`);
});
