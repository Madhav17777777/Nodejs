import express from "express";
import path from "path";
import mongoose from "mongoose";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
const mongoURI = 'mongodb://127.0.0.1:27017/backend2';
mongoose.connect(mongoURI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Connected to MongoDB'))
  .catch((err) => console.error('Error connecting to MongoDB', err));

const userSchema=new mongoose.Schema({
    name:String,
    email:String,
    password:String,
});
const User=mongoose.model("User",userSchema);

const app=express();
app.use(express.static(path.join(path.resolve(),"public")));
//this is for getting the data on the server...
app.use(express.urlencoded({extended: true}));
app.use(cookieParser());

app.set("view engine","ejs");
const isAuthenticated= async(req,res, next)=>{
    const {token}=req.cookies;
    if(token){
        const decoded=jwt.verify(token,"secret@gmail.com");
        req.user =await User.findById(decoded._id);
        next();
    }else{
        res.redirect("/login");
    }

}
app.get("/",isAuthenticated,(req,res)=>{
  res.render("logout",{name : req.user.name});
});
app.get("/register",(req,res)=>{
    res.render("register");
  });
app.get("/logout",(req,res)=>{
    res.cookie("token", null,{
        expires:new Date(Date.now()),
    });
    res.redirect("/");
});
app.get("/login",(req,res)=>{
    res.render("login");
}); 
app.post("/register",async(req,res)=>{
    const {name,email,password}=req.body;
    let user=await User.findOne({name,email,password});
    if(user){
        res.redirect("/login");
        console.log("already registered ... back to login page");
    }else{
        const hashedpassword = await bcrypt.hash(password,10);
        user= await User.create({
            name,
            email,
           password: hashedpassword,
        });
        const token =jwt.sign({_id: user._id },"secret@gmail.com",);
    
        res.cookie("token", token,{
            httpOnly:true,expires:new Date(Date.now()+60*1000),
        });
        res.redirect("/");
    }
   
})
app.post("/login",async(req,res)=>{
    const {name,email,password}=req.body;
    let user=await User.findOne({email});
    if(!user){
        console.log("Register first");
        res.redirect("/register");
    }
   else{
    const isMatch=user.password===password;
    if(!isMatch) return res.render("login",{name,email,message: "incorrect password"});
    const hashedpassword = await bcrypt.hash(password,10);
    user= await User.create({
        name,
        email,
        password: hashedpassword,
    });
    const token =jwt.sign({_id: user._id },"secret@gmail.com",);

    res.cookie("token", token,{
        httpOnly:true,expires:new Date(Date.now()+60*1000),
    });
    res.redirect("/");
    


   }
        
});
app.listen(5000,()=>{
    console.log("App is working...");
});