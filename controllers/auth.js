import jwt from 'jsonwebtoken'
import bcrypt from 'bcryptjs'
import Users from '../models/auth.js'

export const signup= async(req,res)=>{
    const {name,email,password}=req.body;
    try{
        const existinguser = await Users.findOne({email});
        if(existinguser){
            return res.status(404).json({message:"User already exist"})
        }
        const hashedPassword =await bcrypt.hash(password,12)
        const newUser= await Users.create({name,email,password:hashedPassword,})
        const token=jwt.sign({email:newUser.email,id:newUser._id},process.env.JWT_SECRET,{expiresIn:'1h'});
        res.status(200).json({result:newUser,token})

    }catch(error){
        console.log(error)
        res.status(500).json("Something went wrong...")
    }
} 

export const login= async(req,res)=>{
    const {email,password}=req.body;
    try{
        const existingser = await Users.findOne({email});
        if(!existingser){
            return res.status(404).json({message:"User don't exist"})
        }
        const isPasswordCrt=await bcrypt.compare(password,existingser.password)
        if(!isPasswordCrt){
            return res.status(400).json({message:"Invalid credential"})
        }
        const token=jwt.sign({email:existingser.email,id:existingser._id},process.env.JWT_SECRET,{expiresIn:'1h'});
        res.status(200).json({result:existingser,token})

    }catch(error){
        res.status(500).json("Something went wrong...")
    }
} 