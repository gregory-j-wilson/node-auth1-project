const express = require("express");
const bcryptjs = require("bcryptjs");
const session = require("express-session");
// const KnexSessionStore = require("connect-session-knex")(session);
const usersRouter = require("./users/users-router.js");
// const authRouter = require("./auth/auth-router.js"); /// <<<<<
const connection = require("./connection.js");
const server = express();
const protected = require("./protected")

const Users = require("./users/users-model");


const sessionConfig = {
    name: "cookie",
    secret: process.env.SESSION_SECRET || "keep it secret, keep it safe!",
    resave: false,
    saveUninitialized: true, 
    cookie: {
        maxAge: 1000 * 60 * 60, 
        secure: process.env.USE_SECURE_COOKIES || false, 
        httpOnly: true,
    },
    // store: new KnexSessionStore({
    //     knex: connection, // knex connection to the database
    //     tablename: "sessions",
    //     sidfieldname: "sid",
    //     createtable: true,
    //     clearInterval: 1000 * 60 * 60, // remove expired sessions every hour
    // }),
};


server.use(express.json());
server.use(session(sessionConfig));
server.use("/api/users", protected, usersRouter);
// server.use("/api/auth", authRouter);


server.post('/api/register', (req, res) => {

    const userInfo = req.body
    const isValid = validateUser(userInfo)

    if (isValid) {

        const rounds = process.env.BCRYPT_ROUNDS
        const hash = bcryptjs.hashSync(userInfo.password, rounds)
        userInfo.password = hash

        Users.add(userInfo).then(inserted => {
            res.status(201).json({ data: inserted })
        })
    } else {
        res.status(400).json({message: 'Invalid information, please verify and try again.'})
    }


})

server.post('/api/login', (req, res) => {

    const creds = req.body

    const isValid = validateCredentials(creds)

    if(isValid) {

        Users.findBy({username: creds.username })
            .then(([user]) => {
                if (user && bcryptjs.compareSync(creds.password, user.password)) {
                    
                    req.session.user = user

                    req.session.username = user.username
                    // req.session.id = user.id
                    console.log(req.session.user)
                    res.status(200).json({
                        message: `Welcome ${creds.username}!!!`
                    })
                } else {
                    res.status(401).json({ message: 'You cannot pass!!' })
                }
            })
    } else {
        res.status(400).json({ message: 'Invalid information, please verify and try again.'})
    }
})


function validateUser(user) {
    // has username, password, and role
    return user.username && user.password ? true : false;
}

function validateCredentials(user) {
    // has username, password, and role
    return user.username && user.password ? true : false;
}



module.exports = server;