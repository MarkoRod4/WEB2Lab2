const express = require('express');
const session = require('express-session');
const db_service = require('./db_service');
const path = require('path');
const bcrypt = require('bcryptjs');
const bodyParser = require("body-parser");
const xss = require("xss");

const app = express();

const externalUrl = process.env.RENDER_EXTERNAL_URL;
const port = externalUrl && process.env.PORT ? parseInt(process.env.PORT) : 3000;

if (externalUrl) {
    const hostname = '0.0.0.0';
    app.listen(port, hostname, () => {
    console.log(`Server locally running at http://${hostname}:${port}/ and from outside on ${externalUrl}`);
    });
} else {
    app.listen(3000, () =>{
        console.log('App listening on port 3000');
    })
}

app.use(express.static(path.join(__dirname, 'styles')));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
    secret: 'SessionSecret',
    resave: false,
    saveUninitialized: true,
    cookie: {
        httpOnly: false,
        secure: false,
    }
}));
app.set('view engine', 'ejs');

const upute1 ="Unosite <script>alert(document.cookie)</script>" +
                "\nRanjivost uključena - pokreće se javascript kod unutar script elementa upisanog u text element" +
                "\nRanjivost isključena - uneseni tekst se sanitizira i prikazuje na stranici";
const upute2 ="Ranjivost uključena - lozinka korisnika koji se registrira se sprema u bazu podataka kao plain text" +
                "\nRanjivost isključena - lozinka korisnika koji se registrira se hashira i zatim sprema u bazu podataka" +
                "\nOvo demonstrira lošu praksu spremanja lozinki" +
                "\nZapise u bazi podataka se može vidjeti klikom na gumb 'Pregled podataka o korisnicima'" +
                "\nFunkcionalnost je moguće provjeriti formom za prijavu korisnika" +
                "\nOPREZ - LOZINKE SU VIDLJIVE SVIMA"
                ;

// Methods

app.get('/', (req, res) => {
    if (!req.session.user) {
        req.session.user = `user_cookie_info`;
    }
    res.render("index", {"upute1": upute1, "upute2": upute2});
});

app.post('/xssattack', (req, res) =>{
    if(req.body.xssattackswitch){
        // Napad moguc
        var text = req.body.textinput;
        res.send(`
            <p>Unesen tekst: ${text}</p>
            <form method="get" action="/">
                <button type="submit">Back</button>
            </form>
          `);
    }else{
        // Napad nije moguc
        var text = xss(req.body.textinput);
        res.send(`
            <p>Unesen tekst: ${text}</p>
            <form method="get" action="/">
                <button type="submit">Back</button>
            </form>
        `);
    }
});

app.post('/register', async(req, res) => {
    try{
        const { username, password, confirmpassword} = req.body;
        let safeswitch = req.body.safeswitch ? true : false;

        if(password != confirmpassword){
            return res.send(400).send('Unesene dvije razlicite lozinke');
        }else{
            var userPassword = password;
            if(!safeswitch){
                var userPassword = await bcrypt.hash(password, 10);
            } 

            const insertResult = await db_service.query('INSERT INTO users (username, password, vulnerable) VALUES ($1, $2, $3) RETURNING username;', [username, userPassword, safeswitch]);
            if(insertResult){
                res.send(`
                    <p>Registriran korisnik: ${username}</p>
                    <form method="get" action="/">
                        <button type="submit">Back</button>
                    </form>                  
                `);
            }else{
                res.send(`
                    <p>Neuspjesna registracija.</p>
                    <form method="get" action="/">
                        <button type="submit">Back</button>
                    </form>
              `);
            }
        }
    }
    catch(e){
        console.error(e.message);
        res.status(500).send('Server Error');
    }
});

app.post('/login', async(req, res) => {
    try{
        const { username, password} = req.body;

        const result = await db_service.query('SELECT * FROM users WHERE username = $1', [username]);
        var isMatch = (password === result.rows[0].password);
        if(!result.rows[0].vulnerable){
            isMatch = await bcrypt.compare(password, result.rows[0].password);
        }

        if(isMatch){
            res.send(`
                <p>Prijavljen korisnik: ${username}</p>
                <form method="get" action="/">
                    <button type="submit">Back</button>
                </form>
                `);
        }else{
            res.send(`
                <p>Prijava neuspjesna. Netocno korisnicko ime ili lozinka</p>
                <form method="get" action="/">
                    <button type="submit">Back</button>
                </form>
                `);
        }
        
    }
    catch(e){
        console.error(e.message);
        res.status(500).send('Server Error');
    }
});

app.get('/users', async (req, res) => {
    try {
        const result = await db_service.query('SELECT * FROM users');
        
        res.render('users', { users: result.rows });
    } catch (e) {
        console.error(e.message);
        res.status(500).send('Server Error');
    }
});

