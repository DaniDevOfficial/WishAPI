# WishAPI Sicherhet

## 1. Einleitung 
Die WishAPI wurde entwickelt, um den Prozess des Testens und Überprüfens der Sicherheit in einer API zu visualisieren. Diese API dient als umfassendes Testumfeld, in dem verschiedene Sicherheitsaspekte analysiert und bewertet werden können. Ihr Hauptzweck liegt in der Identifikation von potenziellen Sicherheitslücken und der Entwicklung von Gegenmaßnahmen, um eine robuste und geschützte API zu gewährleisten.

Anmerkung: Um besser zu verstehen was hier im ReadMe geschreieben ist, wird es empfolen die API zu starten.

## 2. Sicherheits-Aspekte

### 2.1 Authentifizierungs- und Autorisierung

Der Folgende Code zeigt eine sehr unsichere Version der Authentifixierung, da der Name und Passwort gerade im code selbst stehen. Weiter ist anzumerken, dass das ganze keinen Token verwendet und deshabt wird das ganze noch einmal unsicherer.
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

Um das Ganze sicherer zu machen können wir etwas wie folgt machen: 
````javascript
app.get('/sicher/auth', authenticateToken, (req, res) => {
    logToFile('Authentifizierter Zugriff auf /sicher/auth');
    if (req.user.role !== 'admin') return res.status(403).send('Keine ausreichenden Berechtigungen');
    res.send('Sicherer Authentifizierungs- und Autorisierungsendpunkt');
});

````

Hier wird die Authentifixierung selbst über den "authenticateToken" überprüft und jeh nach dem welche rechte ein Account, der mit dem Token verbunden ist, wird etwas anderes in die Response getan. 

Um diesen Token zu erhalten müssen wir uns mit dem folgendem Beispiel Einloggen: 
````javascript
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

````

In dieser login route muss man einen Namen und Passwort eingeben, wenn dieser jedoch nicht Valid ist, wird das ganze geloggt und dann abgebrochen. Wenn die date jedoch Valid sind, geht es weiter, damit, dass überprüft wird, ob eine Account mit diesem Namen und Passwort exisitert. Für die Sicherheit des Passworts wir Bcrypt verwendet, sodass wir dieses nicht Plaintext in der DatenBank speichern. 

Wenn der Account existiert und man das richtige Passwort eingegeben hat, erhält man einen jwt Token, welcher dann bei der Auth verwendet werden könnte. 

### 2.2 Rate Limiting

Sodass wir unsere API gegen eine DDoS attake schützen können, verwenden wir ein Rate Limiter. In diesem Beispiel ist das Limit Pro IP-Adresse 100 Anfragen alle 15 Minuten eingestellt. (Um das zu testen kann man auch das max anpassen und dann selbst überprüfen)

````javascript
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: 'Zu viele Anfragen von dieser IP, bitte versuchen Sie es später erneut.',
});

app.use(apiLimiter);
````
Mit der Lezten Zeile wird das Rate Limit für die ganze Seite eingestellt, bei einer Realen API solte jeh nach route am besten ein angepasstes RateLimit eingestellt werden. Die dient auch zur hilfe gegen Brute Force Attaken. 

### 2.3 Input Validierung 

Dieser Punkt wurde bei 2.1 schon ein wenig angesprochen, aber hier genauer erklärt. 

````javascript
const isValidInput = (input) => /^[a-zA-Z0-9]+$/.test(input);
````

Im falle der WishAPI ist diese Validierung nur eine Zeile, dies hilft beim Filtern gegen SQL-Injections und XSS Inputs. Mit dem Beigefürhrten PostMan Projekt kann man das ganze auch selbst ausprobieren und feststellen, dass die SQL injection geblockt wird. 

In einem Realem Produkt würde man etwas wie DOMpurify verwenden, um das ganze Sicherere Zu machen. 

````javascript
// Beispiel: Verwendung von DOMPurify für XSS-Schutz
const DOMPurify = require('dompurify');
const sanitizedInput = DOMPurify.sanitize(userInput);
````

### 2.4 Fehlermeldungen

````javascript
Z. 25: callback(new Error('Unerlaubter Zugriff von der angegebenen Domäne.'));
Z. 36: message: 'Zu viele Anfragen von dieser IP, bitte versuchen Sie es später erneut.',
Z. 47 if (!token) return res.status(401).send('Fehlende Berechtigung');
Z. 50: if (err) return res.status(403).send('Ungültiger Token');
Z. 68: console.error('Fehler beim Schreiben des Logs:', err);
Z. 76: res.send('Sicherer Authentifizierungs- und Autorisierungsendpunkt');
Z. 84: return res.status(400).send('Ungültige Benutzername oder Passwort');
Z. 91: return res.status(401).send('Ungültige Anmeldeinformationen');
Z. 101: res.status(401).send('Ungültige Anmeldeinformationen');
````
Hier sind alle Responses die Eine Fehlermeldung zurückgeben. Beim Lesen dieser Returns wird schnell klar, dass es zwar ungefähr sagt was falsch ist, jedoch wird so wage wie möglich formuliert, was passiert ist, sodass ein Person mit schlechten intentionen nicht genau weiss, was er bei seinem z.B. Hack fixen muss, sodass er funktioniert. Wenn wir bei Z. 80 genau sagen würden, was falsch ist, kann man schnell Accounts finden, welche existieren und dies Solten wir als Besitzer vermeiden. Was das ganze hauptsächlich macht, ist dass das Hacken oder schlechten verwenden der API sehr erschwert wird. 


### 2.5 Logging und Monitoring

Mit Logging und Monitoring kann man erkennen, wenn jemand zum beispiel sich mit einer Brute-Force attake versucht sicht in einen Account einzuloggen. Jeden einzelnen Loggin Attempt würde man im Log file dann sehen. 

Die WishAPI hat folgende Logging Methode: 
````javascript
const logToFile = (data) => {
    fs.appendFile('log.txt', `${new Date().toISOString()}: ${data}\n`, (err) => {
        if (err) {
            console.error('Fehler beim Schreiben des Logs:', err);
        }
    });
};
````
Diese Logging funktion funktioniert darüber, dass beim aufrufen ein Text als Parameter mitgegeben wird, sodass dies dan Geloggt werden kann. Wenn man ein wenig mit der API rumspielt kann man sehr schnell ein Log-File entdecken, welches alle ativitäten der Nutzer Loggt. 


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

Um dies zu Testen kann man auf: https://david-bischof.ch/apitest sehen, dass die API dort etwas zurückgibt. Auf: https://portfolio-dbischof.web.app/apitest kann man nichts sehen, da diese Domaine nicht auf der Allowed List ist.

## 3. Testing

Hierfür wird Postman benötigt und die API muss am laufen sein. Es wird empfohlen das Postman Projekt zu Forken 

[![Fork Postman Project](https://run.pstmn.io/button.svg)](https://app.getpostman.com/run-collection/27955045-9c4d8f6e-f8a5-4b92-8a66-1eb84e1b4416?action=collection%2Ffork&source=rip_markdown&collection-url=entityId%3D27955045-9c4d8f6e-f8a5-4b92-8a66-1eb84e1b4416%26entityType%3Dcollection%26workspaceId%3D582dfada-5bb9-45e7-b627-8791289ac85f)


### 3.1 Simples Login Testing 

Hierfür wird der "Login with Admin" Request verwendet, bei welchem folgende date mitgeschickt werden:
````json
{
    "username": "admin",
    "password": "admin123"
}
````

Die API gibt daraufhin, solagen die Daten richtig sind einen jwt-token. In diesem Token sind mehr informationen über den Account vorhanden.

### 3.2 Autorisierung mit Token

Mit dem Vorherigen test erhalten wir einen Token der ungefähr so aussieht: 
````json
{
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwidXNlcm5hbWUiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTcwNTM4NzY5MX0.2vanbd92_5z7r9vBkiOwpdimvrDq0nO4fMWAjqnDUbQ"
}
````
Wenn man diesen Token dann bei der Autorisierung eines Accounts mitgegeben um mehr über den Account herauszufinden. Wenn man sich in diesem Postman beispiel mit einem nicht admin Token versucht anzumelden, wird ein Fehler zurückgegeben, der sagt, dass man zu wenige Rechte hat. 

### 3.3 Login mit Invalid Daten

Wenn ein nutzer sich entweder mit nicht erlaubten nutzernamen oder Passwörtern versucht anzumelden, dann schlägt die Input Validierung aus:
````javascript
const isValidInput = (input) => /^[a-zA-Z0-9]+$/.test(input);

````
Im Postman Projekt hat es zwei verschiedene invalid inputs. Einer sind einfach nicht erlaubte Zeichen und der andere ist eine SQL injection, die von dieser Validierung Abgewehrt wird.
````json
// invalid Input
{
    "username": "!@#$",
    "password": "123"
}
// SQL injection
{
    "username": "' OR '1'='1' --",
    "password": "whatever"
}

````

### 3.4 CORS

Wie schon weiter oben erklärt, kann man die CORS-Berechtigungen auch Testen. 
````javascript
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
````

Da  hier als valid Domaine nur eine angegeben ist, kann man auf https://david-bischof.ch/apitest erkennt werden, dass der request akzeptiert wird und man dort dann auch etwas sehen kann. Im Log file selbst kann man auch sehen, dass ein Request von einer Domaine aus gekommen wurde:
````
2024-01-16T09:26:21.707Z: Anfrage an /example
````

Wenn man jedoch auf eine nicht erlaubte Domaine wie: https://portfolio-dbischof.web.app/apitest geht, welche einen Request schickt, wird dieser Abgelehnt und man kann dann dort auch nichts sehen.

### 3.5 Testing des Rate Limiting

Um das Rate Limit zu testen, kann im Code der API selbst eine zahl geändert werden, um das max limit herunterzusetzer, sodass man nicht wie original 100 mal einen Request schicken müsste.
````javascript
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100, // <== diese Zahl heruntersetzen
    message: 'Zu viele Anfragen von dieser IP, bitte versuchen Sie es später erneut.',
    handler: (req, res) => {
        logToFile(`Rate limit exceeded`);
        res.status(429).send('Zu viele Anfragen von dieser IP, bitte versuchen Sie es später erneut.');
    },
});

app.use(apiLimiter);
```` 

Wenn man nun dieses Rate Limit erreicht, wird dem User als Response die message gesented und im Logfile wird der LogToFile eingeschireben.


