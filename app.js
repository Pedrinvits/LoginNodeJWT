require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const app = express()
// Config JSON response
app.use(express.json())

// Models
const User = require('./models/User')

// Public Route
app.get('/',(req,res) => {
    res.status(200).json({message : 'Bem vindo a nossa api'})
})

// Private Route
app.get('/user/:id', checkToken, async(req,res)=> {
    const id = req.params.id
    // check if user exits
    const user = await User.findById(id)
    // console.log(user)
    if(!user){
        return res.status(404).json({message : 'Usuário não encontrado !'})
    }
    res.status(200).json({user})
})

function checkToken(req,res,next){
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(" ")[1]
    if (!token){
        return res.status(401).json({message : 'Acesso Negado'})
    }
    try {
        const secret = process.env.SECRET
        jwt.verify(token, secret)
        next()
    }catch(err){
        res.status(400).json({message : "Token inválido!"})
    }
}

// Register User
app.post('/auth/register', async(req,res)=>{
    const {name,email,password, confirmpassword} = req.body
    if(!name) {
        return res.status(422).json({message : 'O nome é obrigatório !'})
    }
    if(!email) {
        return res.status(422).json({message : 'O email é obrigatório !'})
    }
    if(!password) {
        return res.status(422).json({message : 'A senha é obrigatória !'})
    }
    if(password !== confirmpassword){
        return res.status(422).json({message : 'As senhas não conferem !'})
    }
    // Check if user exists
    const userExists = await User.findOne({email : email})
    if(userExists){
        return res.status(422).json({message : 'Por favor insira outro email !'})
    }
    // Create password
    const salt = await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash(password , salt)

    // Create user
    const user = new User ({
        name,
        email,
        password : passwordHash,
    })

    try{
        await user.save()
        res.status(201).json({message : 'Usuario Criado com sucesso !'})
    }catch(err){
        console.log(err)
        res.status(500).json({message : err})
    }
})

// Login
app.post('/auth/login', async(req,res) => {

    const {email,password} = req.body
    // validations
    if(!email){
        return res.status(422).json({message : 'O email é obrigatório'})
    }
    if(!password){
        return res.status(422).json({message : 'A senha é obrigatória'})
    }
    // check if user exists
    const user = await User.findOne({email : email})
    if(!user){
        return res.status(404).json({message : 'Usuário não encontrado !'})
    }
    // check if password match
    // ver pq a funcao n funciona
    const checkPassword = await bcrypt.compare( password, user.password )

    if(!checkPassword){
        return res.status(422).json({message : 'Senha inválida'})
    }
    // if(password !==  user.password){
    //     return res.status(422).json({message : 'Senha inválida'})
    // }
    try{
        const secret = process.env.SECRET
        const token = jwt.sign(
            {
                id : user._id,
            },
            secret,
        )
        res.status(200).json({message : 'Login efetuado com sucesso !', token})
    }catch(err){
        console.log(err)
        res.status(500).json({message : err})
    }
} )

// Credentials
const dbUser = process.env.DB_USER
const dbPass = process.env.DB_PASS
mongoose.connect(`mongodb+srv://${dbUser}:${dbPass}@authjwt.8dr2xjs.mongodb.net/?retryWrites=true&w=majority`)
.then(()=>{
    app.listen(3000)
    console.log('Conectou ao banco !')
}).catch((err)=>console.log(err))
