const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');

const app = express();
const port = 3000;
const secretKey = 'MeinGeheimesSchluesselwort'; // sollte aus einer Umgebungsvariable kommen
const saltRounds = 10;
const cors = require('cors');

// Benutzerdaten (normalerweise in einer Datenbank gespeichert)
const users = [
    { id: 1, username: 'admin', hashedPassword: '', role: 'admin' },
    { id: 2, username: 'user', hashedPassword: '', role: 'user' },
];

const allowedOrigins = ['https://david-bischof.ch'];
// https://portfolio-dbischof.web.app/apitest hier funktioniert es nicht, da es nicht in der Liste der erlaubten Domänen ist
// https://david-bischof.ch/apitest hier funktioniert es, da es in der Liste der erlaubten Domänen ist
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
    windowMs: 15 * 60 * 1000, // 15 Minuten
    max: 100, // Maximal 100 Anfragen für die gesamte API innerhalb des Zeitraums
    message: 'Zu viele Anfragen von dieser IP, bitte versuchen Sie es später erneut.',
});

app.use(apiLimiter);

// Middleware für die Authentifizierung
const authenticateToken = (req, res, next) => {
    const token = req.header('Authorization');
    if (!token) return res.status(401).send('Fehlende Berechtigung');

    jwt.verify(token, secretKey, (err, user) => {
        if (err) return res.status(403).send('Ungültiger Token');
        req.user = user;
        next();
    });
};

// Hashen des Passworts hier für jeden user das selbe Passwort (real in der Datenbank gespeichert)
users.forEach(user => {
    bcrypt.hash('admin123', saltRounds, (err, hash) => {
        if (!err) user.hashedPassword = hash;
    });
});

// Einfache Eingabevalidierung für Benutzername und Passwort
const isValidInput = (input) => /^[a-zA-Z0-9]+$/.test(input);

app.get('/sicher/auth', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).send('Keine ausreichenden Berechtigungen');
    res.send('Sicherer Authentifizierungs- und Autorisierungsendpunkt');
});

app.post('/login', bodyParser.json(), (req, res) => {
    const { username, password } = req.body;

    // Überprüfen Sie die Gültigkeit von Benutzername und Passwort
    if (!isValidInput(username) || !isValidInput(password)) {
        return res.status(400).send('Ungültige Benutzername oder Passwort');
    }

    const user = users.find(u => u.username === username);

    if (!user) return res.status(401).send('Ungültige Anmeldeinformationen');

    bcrypt.compare(password, user.hashedPassword, (err, result) => {
        if (result) {
            const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, secretKey);
            res.json({ token });
        } else {
            res.status(401).send('Ungültige Anmeldeinformationen');
        }
    });
});

app.get('/example', (req, res) => {
    res.send('Diese Route erlaubt nur Anfragen von https://david-bischof.ch.');
});
app.listen(port, () => {
    console.log(`Server läuft auf http://localhost:${port}`);
});
