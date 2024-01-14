const express = require('express');
const app = express();
const port = 3000;

app.get('/', (req, res) => {
    res.send('Willkommen zur API!');
});

app.get('/benutzer/:id', (req, res) => {
    const userId = req.params.id;
    res.send(`Benutzer-ID: ${userId}`);
});

// Starten Sie den Server
app.listen(port, () => {
    console.log(`Server läuft auf http://localhost:${port}`);
});
