const express = require('express')
const helmet = require('helmet')
const app = express();
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');


/*
* ------------------------------------------------
* INSTRUCTIONS FOR USING THIS 10.2 IMPLEMENTATION:
* ------------------------------------------------
*
* I recommend using Postman when testing the features.
* 
* For the client (you) to receive the token, you must create a new
* user (POST request to /api/users with the required information).
*
* After the user has been created, the server sends the token to the
* client.
*
* Then, for the client to be able to access the player content, you
* have to set authorization headers and add the token to the header,
* before sending the request. After this, you can send the request.
*
* The server will check that the headers are correct, that the token 
* is valid, and that the username in the token can be found in the
* database.
*
* After completing authorization checking, the server will normally
* find the matching request handler, and will respond with the content
* that was requested.
*
*/


/*
* Mongoose connection
*/

const mongoose = require('mongoose');

const path = 'http://localhost:3000/';
mongoose.connect('mongodb://localhost/WWWProgramming', { useNewUrlParser: true, useUnifiedTopology: true, useFindAndModify: false, useCreateIndex: true });

const db = mongoose.connection;


/*
* Schemas, models
*/

const playerSchema = mongoose.Schema({
    name: {
        type: String,
        required: true
    },
    active: {
        type: Boolean,
        required: true,
        default: 0
    }
}, {
        collection: 'Players'
    });

playerSchema.virtual('links').get(function () {
    return [{
        'self': path + 'api/players/' + this._id
    }];
});
playerSchema.set('toJSON', {
    virtuals: true
})

const Player = mongoose.model('Player', playerSchema);


const userSchema = mongoose.Schema({
    name: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    }
});

userSchema.virtual('links').get(function () {
    return [{
        'self': path + 'api/users/' + this._id
    }];
});

//We don't return hashed password
userSchema.set('toJSON', {
    virtuals: true,
    transform: function (doc, ret) {
        delete ret.password;
    }
})

var User = mongoose.model('User', userSchema);


db.on('error', console.error.bind(console, 'MongoDB connection error:'));



/*
* Routing, authorization
*/

var api = express.Router()

const saltRounds = 12;

const secret = 'aVerySecretKey';

app.use(helmet())

app.use(bodyParser.json())


api.post('/users', function (req, res) {

    if (req.body && req.body.name && req.body.password) {
        console.log('adding user');

        bcrypt.hash(req.body.password, saltRounds, function (err, hash) {

            var newUser = new User({
                name: req.body.name,
                password: hash
            });
            newUser.save(function (err) {
                if (err) {
                    res.sendStatus(500);
                    return console.error(err);
                };
                console.log("Inserted 1 document into the collection");
                
                jwt.sign({ username: newUser.name }, secret, { algorithm: 'HS256' }, function (err, token) {
                    res.status(201);
                    res.set('Location', path + 'api/users/' + newUser._id);
                    res.json(token);
                });
            });


        });
    } else {
        res.sendStatus(400);
    }

});

//this will be executed for all calls specified after this
api.use(function (req, res, next) {

    if (req.headers.authorization) {
        if (req.headers.authorization.startsWith('Bearer ')) {
            let token = req.headers.authorization.slice(7, req.headers.authorization.length);
            jwt.verify(token, secret, function (err, decoded) {
                if (err) res.sendStatus(401);
                else {
                    let usrName = JSON.stringify(decoded.username).replace(/['"]+/g, '');
                    // Check that the user exists
                    User.findOne({
                        'name': usrName
                    }, function (err, user) {
                        if (err) return console.error(err);
                        if (user) {
                            console.log("Verified token. Granted access to user: " + usrName);
                            next();
                        } else {
                            res.sendStatus(401);
                        }
                    })
                }
            });
        }
        else {
            res.sendStatus(401);
        }
    }
    else {
        res.sendStatus(401);
    }
});



api.post('/players', function (req, res) {

    if (req.body && req.body.name) {
        console.log('adding player');

        let isActive = true;
        if (typeof req.body.active === 'undefined' || req.body.active === false) {
            isActive = false;
        }

        var newPlayer = new Player({
            name: req.body.name,
            active: isActive
        });
        newPlayer.save(function (err) {
            if (err) {
                res.sendStatus(500);
                return console.error(err);
            };

            console.log("Inserted 1 document into the collection");
            res.status(201);
            res.set('Location', path + 'api/players/' + newPlayer._id);
            res.json(newPlayer);
        });

    } else {
        res.sendStatus(400);
    }

});

api.get('/players', function (req, res) {
    Player.find(function (err, players) {
        if (err) {
            res.sendStatus(404);
            return console.error(err);
        };
        if (!players) {
            res.sendStatus(404)
        } else {
            res.set('Location', path + 'api/players/');
            res.status(200);
            res.json(players);
        }
    })
})

api.get('/players/:id', function (req, res) {
    Player.findOne({
        '_id': req.params.id
    }, function (err, player) {
        if (err) {
            res.sendStatus(404);
            return console.error(err);
        };
        if (!player) {
            res.sendStatus(404)
        } else {
            res.set('Location', path + 'api/players/' + player._id);
            res.status(200);
            res.json(player);
        }
    })
})

api.delete('/players/:id', function (req, res) {
    Player.findByIdAndDelete(req.params.id, function (err, player) {
        if (err) {
            res.sendStatus(404);
            return console.error(err);
        };
        if (!player) {
            res.sendStatus(404)
        } else {
            res.set('Location', path + 'api/players/' + player._id);
            res.status(204);
            res.json();
        }
    })
})

api.delete('/players/', function (req, res) {
    Player.deleteMany(function (err, players) {
        if (err) {
            res.sendStatus(404);
            return console.error(err);
        };
        if (!players) {
            res.sendStatus(404)
        } else {
            res.set('Location', path + 'api/players/');
            res.status(204);
            res.json();
        }
    })
})

api.put('/players/:id', function (req, res) {
    console.log(req.body);
    Player.findByIdAndUpdate(req.params.id, req.body, {
        'new': true
    }, function (err, player) {
        if (err) {
            res.sendStatus(400);
            return console.error(err);
        };
        if (!player) {
            res.sendStatus(404)
        } else {
            res.set('Location', path + 'api/players/' + player._id);
            res.status(200);
            res.json(player);
        }
    })
})


app.use('/api', api);
app.use('/', express.static('public'))
app.listen(3000, () => console.log('App listening on port 3000'))
