# WishAPI Sicherheit

## 1. Einleitung 
Die WishAPI wurde entwickelt, um den Prozess des Testens und Überprüfens der Sicherheit in einer API zu visualisieren. Diese API dient als umfassendes Testumfeld, in dem verschiedene Sicherheitsaspekte analysiert und bewertet werden können. Ihr Hauptzweck liegt in der Identifikation von potenziellen Sicherheitslücken und der Entwicklung von Gegenmassnahmen, um eine robuste und geschützte API zu gewährleisten.

Anmerkung: Um besser zu verstehen, was hier im ReadMe geschrieben ist, wird es empfohlen, die API zu starten.

## 2. Sicherheitsaspekte

### 2.1 Authentifizierung und Autorisierung

Der folgende Code zeigt eine sehr unsichere Version der Authentifizierung, da der Benutzername und das Passwort direkt im Code enthalten sind. Es ist anzumerken, dass das Fehlen der Token-Verwendung die Sicherheitslage weiter verschärft.

```javascript
app.post('/unsicher/auth', (req, res) => {
    const username = req.body.username;
    const password = req.body.password;

    if (username === 'admin' && password === 'admin123') {
        res.send('Unsicherer Authentifizierungs- und Autorisierungsendpunkt - Zugriff gestattet');
    } else {
        res.status(401).send('Unsicherer Authentifizierungs- und Autorisierungsendpunkt - Zugriff verweigert');
    }
});
```

Um das Ganze sicherer zu gestalten, können wir folgendermassen vorgehen:

```javascript
app.get('/sicher/auth', authenticateToken, (req, res) => {
    logToFile('Authentifizierter Zugriff auf /sicher/auth');
    if (req.user.role !== 'admin') return res.status(403).send('Keine ausreichenden Berechtigungen');
    res.send('Sicherer Authentifizierungs- und Autorisierungsendpunkt');
});
```

Hier wird die Authentifizierung über den "authenticateToken" überprüft, und je nach den Rechten eines Accounts, der mit dem Token verbunden ist, wird eine entsprechende Antwort generiert.

Um diesen Token zu erhalten, müssen wir uns mit dem folgenden Beispiel einloggen:

```javascript
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
```

In dieser Login-Route muss man einen Benutzernamen und ein Passwort eingeben. Wenn diese jedoch nicht gültig sind, wird dies geloggt und der Vorgang abgebrochen. Wenn die Daten jedoch gültig sind, wird überprüft, ob ein Account mit diesem Benutzernamen und Passwort existiert. Für die Sicherheit des Passworts wird Bcrypt verwendet, um dieses nicht als Klartext in der Datenbank zu speichern.

Wenn der Account existiert und man das richtige Passwort eingegeben hat, erhält man einen JWT-Token, der dann bei der Authentifizierung verwendet werden kann.

### 2.2 Rate Limiting

Um die API vor DDoS-Angriffen zu schützen, verwenden wir einen Rate Limiter. In diesem Beispiel ist das Limit pro IP-Adresse auf 100 Anfragen alle 15 Minuten eingestellt. (Um dies zu testen, kann man auch das Maximallimit ändern und dann selbst überprüfen.)

```javascript
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: 'Zu viele Anfragen von dieser IP, bitte versuchen Sie es später erneut.',
});

app.use(apiLimiter);
```

Die letzte Zeile setzt das Rate Limit für die gesamte Seite. In einer realen API

 sollte je nach Route am besten ein angepasstes Rate Limit eingestellt werden. Dies dient auch als Schutz vor Brute-Force-Angriffen.

### 2.3 Input-Validierung 

Dieser Punkt wurde bei der 2.1 bereits angesprochen, aber hier genauer erklärt.

```javascript
const isValidInput = (input) => /^[a-zA-Z0-9]+$/.test(input);
```

Im Falle der WishAPI ist diese Validierung nur eine Zeile, dies hilft beim Filtern gegen SQL-Injections und XSS-Inputs. Mit dem beigeführten Postman-Projekt kann man das Ganze auch selbst ausprobieren und feststellen, dass die SQL-Injection blockiert wird.

In einem realen Produkt würde man etwas wie DOMPurify verwenden, um das Ganze sicherer zu machen.

```javascript
// Beispiel: Verwendung von DOMPurify für XSS-Schutz
const DOMPurify = require('dompurify');
const sanitizedInput = DOMPurify.sanitize(userInput);
```

### 2.4 Fehlermeldungen

```javascript
Z. 25: callback(new Error('Unerlaubter Zugriff von der angegebenen Domäne.'));
Z. 36: message: 'Zu viele Anfragen von dieser IP, bitte versuchen Sie es später erneut.'
Z. 47 if (!token) return res.status(401).send('Fehlende Berechtigung');
Z. 50: if (err) return res.status(403).send('Ungültiger Token');
Z. 68: console.error('Fehler beim Schreiben des Logs:', err);
Z. 76: res.send('Sicherer Authentifizierungs- und Autorisierungsendpunkt');
Z. 84: return res.status(400).send('Ungültige Benutzername oder Passwort');
Z. 91: return res.status(401).send('Ungültige Anmeldeinformationen');
Z. 101: res.status(401).send('Ungültige Anmeldeinformationen');
```

Hier sind alle Responses, die eine Fehlermeldung zurückgeben. Beim Lesen dieser Returns wird schnell klar, dass es zwar ungefähr sagt, was falsch ist, jedoch wird so vage wie möglich formuliert, was passiert ist, sodass eine Person mit schlechten Absichten nicht genau weiss, was er bei seinem z.B. Hack fixen muss, damit er funktioniert. Wenn wir bei Z. 80 genau sagen würden, was falsch ist, kann man schnell Accounts finden, welche existieren und dies sollten wir als Besitzer vermeiden. Was das Ganze hauptsächlich macht, ist dass das Hacken oder schlechte Verwenden der API sehr erschwert wird.

### 2.5 Logging und Monitoring

Mit Logging und Monitoring kann man erkennen, wenn jemand zum Beispiel sich mit einer Brute-Force-Attacke versucht, sich in einen Account einzuloggen. Jeden einzelnen Loggin Attempt würde man im Logfile dann sehen.

Die WishAPI hat folgende Logging-Methode:

```javascript
const logToFile = (data) => {
    fs.appendFile('log.txt', `${new Date().toISOString()}: ${data}\n`, (err) => {
        if (err) {
            console.error('Fehler beim Schreiben des Logs:', err);
        }
    });
};
```

Diese Logging-Funktion funktioniert darüber, dass beim Aufrufen ein Text als Parameter mitgegeben wird, sodass dies dann geloggt werden kann. Wenn man ein wenig mit der API spielt, kann man sehr schnell ein Log-File entdecken, welches alle Aktivitäten der Nutzer loggt.

### 2.6 Cross-Origin Resource Sharing (CORS)

Um die API gegen unerlaubten Zugriff von verschiedenen Domänen zu schützen, wurde Cross-Origin Resource Sharing (CORS) implementiert. Die API erlaubt nur Anfragen von vordefinierten, vertrauenswürdigen Domänen. In diesem Beispiel ist nur der Zugriff von der Domäne 'https://david-bischof.ch' erlaubt.

```javascript
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
```

Die `allowedOrigins` Liste enthält die Domänen, die berechtigt sind, auf die API zuzugreifen. Jede Anfrage von einer nicht autorisierten Domäne wird blockiert und mit einer Fehlermeldung zurückgegeben. Dies trägt dazu bei, dass die API vor unerwünschten CORS-Anfragen geschützt ist und nur vertrauenswürdigen Quellen den Zugriff gestattet.

Um dies zu Testen, kann man auf: https://david-bischof.ch/apitest sehen, dass die API dort etwas zurückgibt. Auf: https://portfolio-dbischof.web.app/apitest kann man nichts sehen, da diese Domain nicht auf der Allowed List ist.

## 3. Testing

Hierfür wird Postman benötigt und die API muss am Laufen sein. Es wird empfohlen, das Postman Projekt zu forken.

[![Fork Postman Project](https://run.pstmn.io/button.svg)](https://app.getpostman.com/run-collection/27955045-9c4d8f6e-f8a5-4b92-8a66-1eb84e1b4416?action=collection%2Ffork&source=rip_markdown&collection-url=entityId%3D27955045-9c4d8f6e-f8a5-4b92-8a66-1eb84e1b4416%26entityType%3Dcollection%26workspaceId%3D582dfada-5bb9-45e7-b627-8791289ac85f)

### 3.1 Simples Login Testing 

Hierfür wird der "Login with Admin" Request verwendet, bei dem folgende Daten mitgeschickt werden:

```json
{
    "username": "admin",
    "password": "admin123"
}
```
Die API gibt daraufhin, solange die Daten richtig sind, einen JWT-Token. In diesem Token sind mehr Informationen über den Account vorhanden.

### 3.2 Autorisierung mit Token

Mit dem vorherigen Test erhalten wir einen Token, der ungefähr so aussieht:

```json
{
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwidXNlcm5hbWUiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTcwNTM4NzY5MX0.2vanbd92_5z7r9vBkiOwpdimvrDq0nO4fMWAjqnDUbQ"
}
```

Wenn man diesen Token dann bei der Autorisierung eines Accounts mitgibt, erhält man mehr Informationen über den Account. Bei einem Versuch, sich mit einem Nicht-Admin-Token in diesem Postman-Beispiel anzumelden, wird ein Fehler zurückgegeben, der besagt, dass man zu wenige Rechte hat.

### 3.3 Login mit invaliden Daten

Wenn sich ein Nutzer mit nicht erlaubten Benutzernamen oder Passwörtern anmelden möchte, schlägt die Input-Validierung fehl:

```javascript
const isValidInput = (input) => /^[a-zA-Z0-9]+$/.test(input);
```

Im Postman-Projekt gibt es zwei verschiedene ungültige Inputs. Einer enthält einfach nicht erlaubte Zeichen, der andere ist eine SQL-Injection, die durch diese Validierung abgewehrt wird.

```json
// Ungültiger Input
{
    "username": "!@#$",
    "password": "123"
}
// SQL-Injection
{
    "username": "' OR '1'='1' --",
    "password": "whatever"
}
```

### 3.4 CORS

Wie bereits weiter oben erklärt, kann man die CORS-Berechtigungen ebenfalls testen.

```javascript
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
```

Da hier nur eine gültige Domain angegeben ist, kann man auf https://david-bischof.ch/apitest erkennen, dass die Anfrage akzeptiert wird und man dort dann auch etwas sehen kann. Im Logfile selbst sieht man auch, dass eine Anfrage von einer erlaubten Domain gekommen ist:

```
2024-01-16T09:26:21.707Z: Anfrage an /example
```

Wenn man jedoch auf eine nicht erlaubte Domain geht, wie zum Beispiel https://portfolio-dbischof.web.app/apitest, und von dort einen Request schickt, wird dieser abgelehnt, und man kann dort auch nichts sehen.

### 3.5 Test des Rate Limiting

Um das Rate Limit zu testen, kann im Code der API selbst die Zahl für das Maximal-Limit herabgesetzt werden, sodass man nicht wie ursprünglich 100 Mal einen Request schicken müsste.

```javascript
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100, // <== Diese Zahl herabsetzen
    message: 'Zu viele Anfragen von dieser IP, bitte versuchen Sie es später erneut.',
    handler: (req, res) => {
        logToFile(`Rate limit exceeded`);
        res.status(429).send('Zu viele Anfragen von dieser IP, bitte versuchen Sie es später erneut.');
    },
});

app.use(apiLimiter);
```

Wenn man nun dieses Rate Limit erreicht, wird dem Benutzer als Antwort die Nachricht gesendet, und im Logfile wird der LogToFile-Eintrag vermerkt.

## 4. Abschlussfazit

Abschliessend lässt sich feststellen, dass die WishAPI mehrere Sicherheitsaspekte berücksichtigt, um eine robuste und geschützte API-Umgebung zu gewährleisten. Die Implementierung von Token-basierter Authentifizierung verbessert die Sicherheit erheblich und ermöglicht eine feinere Steuerung der Zugriffsrechte. Die Input-Validierung schützt vor ungültigen Benutzerdaten und SQL-Injection-Angriffen.

Die Nutzung von CORS (Cross-Origin Resource Sharing) schränkt den Zugriff auf die API auf vertrauenswürdige Domänen ein, um unerlaubten Zugriff zu verhindern. Das Rate Limiting bietet Schutz vor DDoS-Angriffen und Brute-Force-Versuchen. Das Logging und Monitoring ermöglicht die Überwachung von Aktivitäten und die frühzeitige Erkennung von potenziellen Bedrohungen.

Insgesamt zeigt die API eine durchdachte Sicherheitsstrategie, die verschiedene Angriffsvektoren berücksichtigt. Die vorgenommenen Tests demonstrieren die Funktionalität dieser Sicherheitsmassnahmen. Es ist jedoch wichtig, regelmässige Überprüfungen und Aktualisierungen vorzunehmen, um aufkommende Sicherheitsrisiken zu adressieren und die Effektivität der Sicherheitsmassnahmen aufrechtzuerhalten.