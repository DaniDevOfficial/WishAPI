const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const app = express();
const port = 3000;
const secretKey = 'MeinGeheimesSchluesselwort'; // sollte aus einer Umgebungsvariable kommen
const saltRounds = 10; 

// Benutzerdaten (normalerweise in einer Datenbank gespeichert)
const users = [
    { id: 1, username: 'admin', hashedPassword: '', role: 'admin' },
    { id: 2, username: 'user', hashedPassword: '', role: 'user' },
];

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

// Hashen des Passworts hier für jeden user das selbe Passwort
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

app.listen(port, () => {
    console.log(`Server läuft auf http://localhost:${port}`);
});
