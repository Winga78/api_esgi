const express = require('express')
const app = express()
const port = 3000
const saltRounds = 10;
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const bodyParser= require('body-parser');
app.use(bodyParser.json());

const dotenv = require('dotenv').config();


const extractBearerToken = headerValue => {
    if(typeof headerValue !== 'string'){
        return false; 
    }
    const matches = headerValue.match(/(bearer)\s+(\S+)/i);
    return matches && matches[2]
}


const checkTokenMiddleware = (req, res,next)=>{
    const token = req.headers.authorization && extractBearerToken(req.headers.authorization);
  
    if(!token)
    {
        // 401 authentification invalide
        return res.status(401).json({message : 'Error, Need a token'});
    }
  
    jwt.verify(token, process.env.SECRET, (err, decodedToken)=> {
        if(err) {
            res.status(401).json({message : 'Error, Bad token'});
        }else {
            return next();
        }
    })
  } 



app.post('/register', (req, res) => {
    const users = fetch(`http://localhost:3001/register?email=${req.body.email}`).then(user => user.json())
    users.then((value)=>{
       if(value.length != 0)
        {
             return res.status(200).json({message: `Le compte ${value[0].email} existe déjà !`});
        }
        const hash = bcrypt.hashSync(req.body.password, saltRounds);
        const user = {
            email:req.body.email,
            password: hash , 
        };
        const chargeUtile = JSON.stringify(user);
 
        fetch('http://localhost:3001/register', {
            method : "POST",
            headers : {"Content-Type": "application/json"},
            body : chargeUtile 
        })
 
        return res.status(201).json({message: `${req.body.email} a bien été crée !`});
    })
        
        
     
})

 app.post('/login', (req, res) => {
    const user= fetch(`http://localhost:3001/register?email=${req.body.email}`).then(user => user.json())


    user.then((value)=>{
      const ckeckpassword=  bcrypt.compareSync(req.body.password, value[0].password)

        if(value=== null || ckeckpassword === null){
          return res.status(400).json({message: 'Error. Wrong login or password'})
      }
     
         const token = jwt.sign({
                 id: value[0].id, 
                 password : value[0].password,
                 email: value[0].email,
         }, process.env.SECRET, {expiresIn: '3 hours'})
        
         return res.json(token);
       
          
    });

  })



  app.post('/products',checkTokenMiddleware, (req, res)=>{
    
    const token = req.headers.authorization && extractBearerToken(req.headers.authorization);
    const decoded = jwt.decode(token, {complete : false});
    const user= fetch(`http://localhost:3001/register?id=${decoded.id}`).then(user => user.json())
    user.then((value)=>{

        if(value.length == 0){
            return res.status(404).json({message: `Error , veuillez créer un compte pour rajouter un produit`});
        }

        const product ={
            name: req.body.name,
            price: req.body.price,
            UserID: decoded.id
        }
         
        const chargeUtile = JSON.stringify(product);
    
        fetch('http://localhost:3001/products', {
            method : "POST",
            headers : {"Content-Type": "application/json"},
            body : chargeUtile 
        })
    
        return res.status(201).json({message: `${decoded.email} a bien été crée le produit ${req.body.name}!`});
        
    })
    
})



app.get('/carts/:id', checkTokenMiddleware,(req, res)=>{
    const token = req.headers.authorization && extractBearerToken(req.headers.authorization);
    const decoded = jwt.decode(token, {complete : false});
    const product = fetch(`http://localhost:3001/products?id=${req.params.id}`).then(product => product.json())
   product.then((value,err)=>{

        if (err) {
             return res.status(401).json({message : 'le produit n\'a pas pu être ajouté'});
          }

        const panier = {
            name: value[0].name,
            price: value[0].price,
            UserID: decoded.id,
            ProductID :  req.params.id,
            quantity : 1
         }

        const chargeUtile = JSON.stringify(panier);
    
        fetch('http://localhost:3001/carts', {
            method : "POST",
            headers : {"Content-Type": "application/json"},
            body : chargeUtile 
        })

         return res.status(201).json({message: `${decoded.email} a bien ajouté au panier ${value[0].name}!`});

    })

})


app.get('/carts',checkTokenMiddleware, (req, res)=>{
    const token = req.headers.authorization && extractBearerToken(req.headers.authorization);
    const decoded = jwt.decode(token, {complete : false});
    const cart = fetch(`http://localhost:3001/carts?UserID=${decoded.id}`).then(cart => cart.json())

    cart.then((values, err)=>{ 
        if(values.length == 0)
         return res.status(404).json({message : 'pas de produits dans le panier'})
       return res.json({'client': decoded.email,'produit': values[0].name, 'prix': values[0].price, 'quantité': values[0].quantity});
    })
})


app.get('/users', (req, res)=>{
    const users = fetch(`http://localhost:3001/register`).then(users => users.json())

    users.then((values, err)=>{ 
       if (values == null)
         return res.status(404).json({message : "pas d'utilisateur inscript"})
         
       return res.json({'users': values});
    })
})


app.get('/user/:email', (req, res)=>{
    const user = fetch(`http://localhost:3001/register?email=${req.params.email}`).then(user => user.json())

    user.then((values, err)=>{ 
       if (values == null)
         return res.status(200).json({message : "pas d'utilisateur inscript"})
         
       return res.json({'user': values});
    })
})

app.put('/user',checkTokenMiddleware, (req, res)=>{
    const token = req.headers.authorization && extractBearerToken(req.headers.authorization);
    const decoded = jwt.decode(token, {complete : false});
    const hash = bcrypt.hashSync(req.body.password, saltRounds);
   const user = {
    id : decoded.id,
    email: req.body.email,
    password : hash,
  }

    const chargeUtile = JSON.stringify(user);

    fetch(` http://localhost:3001/register/${decoded.id}`,{
            method : "PUT",
            headers : {"Content-Type": "application/json"},
            body : chargeUtile 
     });
   
     res.status(200).json({ message: 'mot de passe modifié avec succès !'})
 })


 app.put('/product/:id',checkTokenMiddleware, (req, res)=>{
    const token = req.headers.authorization && extractBearerToken(req.headers.authorization);
    const decoded = jwt.decode(token, {complete : false});
    
    const product = fetch(`http://localhost:3001/products?id=${req.params.id}`).then(product => product.json())
    product.then((value,err)=>{
        if (value.length == 0)
           res.status(404).json({ message: 'produit introuvable !'})
        console.log(value[0])
        const product = {
            id : value[0].id,
            name: req.body.name || value[0].name,
            price : req.body.price || value[0].price,
            UserID : decoded.id
          }
        
            const chargeUtile = JSON.stringify(product);
        
            fetch(` http://localhost:3001/products/${value[0].id}`,{
                    method : "PUT",
                    headers : {"Content-Type": "application/json"},
                    body : chargeUtile 
             });
             res.status(200).json({ message: 'article modifié avec succès !'})
    })
 })


app.put('/cart/:id',checkTokenMiddleware, (req, res)=>{
    const token = req.headers.authorization && extractBearerToken(req.headers.authorization);
    const decoded = jwt.decode(token, {complete : false});
    const cart = fetch(`http://localhost:3001/carts?id=${req.params.id}`).then(cart => cart.json())

    cart.then((value)=>{
        const cart = {
            id : value[0].id,
            name: req.body.email,
            price : value[0].price,
            UserID : decoded.id,
            ProductID : value[0].ProductID,
            quantity : req.body.quantity
          }
            const chargeUtile = JSON.stringify(cart);
        
            fetch(` http://localhost:3001/carts/${value[0].id}`,{
                    method : "PUT",
                    headers : {"Content-Type": "application/json"},
                    body : chargeUtile 
             });
           
             res.status(200).json({ message: 'la quantité des produits a bien été modifié avec succès !'})
    })
 })


//suppression de l'utilisateur

 app.delete('/user/',checkTokenMiddleware, (req, res)=>{
    const token = req.headers.authorization && extractBearerToken(req.headers.authorization);
    const decoded = jwt.decode(token, {complete : false});
    const user = fetch(`http://localhost:3001/register?id=${decoded.id}`).then(user => user.json()) 
    user.then((value)=>{
        fetch(` http://localhost:3001/register/${value[0].id}`,{
            method : "DELETE",
            headers : {"Content-Type": "application/json"},
     });   

    })
    res.status(200).json({ message: 'utilisateur supprimé avec succès !'})
  })


//suppression du panier

app.delete('/cart/:id',checkTokenMiddleware, (req, res)=>{
    const token = req.headers.authorization && extractBearerToken(req.headers.authorization);
    const decoded = jwt.decode(token, {complete : false});
    const user = fetch(`http://localhost:3001/carts?id=${req.params.id}`).then(cart => cart.json()) 
    user.then((value)=>{
        fetch(` http://localhost:3001/carts/${value[0].id}`,{
            method : "DELETE",
            headers : {"Content-Type": "application/json"},
     });   

    })
    res.status(200).json({ message: 'panier supprimé avec succès !'})
})

// suppresion d'un produit 

app.delete('/product/:id',checkTokenMiddleware, (req, res)=>{
    const token = req.headers.authorization && extractBearerToken(req.headers.authorization);
    const decoded = jwt.decode(token, {complete : false});
    const user = fetch(`http://localhost:3001/products?id=${req.params.id}`).then(product => product.json()) 
    user.then((value)=>{
        fetch(` http://localhost:3001/products/${value[0].id}`,{
            method : "DELETE",
            headers : {"Content-Type": "application/json"},
     });   

    })
    res.status(200).json({ message: 'produit supprimé avec succès !'})
})




app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})