const express = require("express");
const mongodb = require("mongodb");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const cors = require("cors");
require("dotenv").config();
const app = express();
app.use(express.json());
const mongoClient = mongodb.MongoClient;
const port = process.env.PORT || 3100;
const objectId = mongodb.ObjectID;
app.use(cors());
const dbURL = process.env.DB_URL;
const key = process.env.A_KEY;

app.get("/",(req,res)=>{
    res.status(200).send("Hello This page works!");
});

app.put("/tokencheck/:token",async(req,res)=>{
    try{
        let client = await mongoClient.connect(dbURL);
        let db = client.db("hackathon");
        let data = await db.collection("users").findOne({token:req.params.token});
        if(data){
            await db.collection("users").update({_id:objectId(data._id)},{$unset:{token:1}});
            res.status(200).json({message:"Success",status:200});
        }
        else{
            res.status(404).json({message:"token not found",status:404});
        }
    }
    catch(error){
        console.log(error);
        res.status(500).json({message:"Internal Server Error!",status:500});
    }
});

app.post("/signup",async(req,res)=>{
    try{
        let client = await mongoClient.connect(dbURL);
        let db = client.db("hackathon");
        let data = await db.collection("users").findOne({email:req.body.email});
        if(data){
            res.status(405).json({message:"User already registered",status:405});
        }
        else{
            let salt = await bcrypt.genSalt(10);
            let hash = await bcrypt.hash(req.body.password,salt);
            req.body.password = hash;
            
            let token = await jwt.sign({user_name: req.body.firstname,user_email:req.body.email},process.env.A_KEY);
            req.body.token = token;
            await db.collection("users").insertOne(req.body);
            
            //let testAccount = await nodemailer.createTestAccount();
            let transporter = nodemailer.createTransport({
                host: "smtp.ethereal.email",
                service:"hotmail",
                port: 587,
                secure: false, // true for 465, false for other ports
                auth: {
                    user: process.env.USER, // generated ethereal user
                    pass: process.env.PASS, // generated ethereal password
                  },
              });
            let info = await transporter.sendMail({
                from: 'shwetha.iyer@hotmail.com', // sender address
                to: "kimjenni.91@gmail.com", // list of receivers
                subject: "Activation link", // Subject line
                text: "Hello, Please click on the link to activate your account ", // plain text body
                html: `<a>${token}</a>`, // html body
              });
              console.log("Message sent: %s", info.messageId);
              console.log("Preview URL: %s", nodemailer.getTestMessageUrl(info));
              res.status(200).json({message:"User has been registered successfully and email sent",status:200});
        }
        client.close();
    }
    catch(error){
        console.log(error);
        res.status(500).json({message:"Internal Server Error!",status:500});
    }
});

app.post("/login",async(req,res)=>{
    try{
        let client = await mongoClient.connect(dbURL);
        let db = client.db("hackathon");
        let data = await db.collection("users").findOne({email:req.body.email});
        if(data){
            let isValid = await bcrypt.compare(req.body.password,data.password);
            console.log(isValid);
            if(isValid){
                let token = await jwt.sign({user_id: data._id},key); 
                res.status(200).json({
                    message:"Login Successfull",
                    token_id:token,
                    status:200
                });
                
            }
            else{
                res.status(401).json({message:"Invalid credentials!",status:401});
            }
        }
        else{
            res.status(404).json({message:"User not registered!",status:404});
        }
    }
    catch(error){
        console.log(error);
        res.status(500).json({message:"Internal Server Error!",status:500});
    }
});

app.listen(port,()=> console.log("The App is running successfully on port:",port));
