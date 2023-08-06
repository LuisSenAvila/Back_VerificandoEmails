const catchError = require('../utils/catchError');
const User = require('../models/User');
const bcrypt = require('bcrypt');
const { verifyAccount } = require('../utils/VerifyAccount');
const EmailCode = require('../models/EmailCode');
const jwt = require('jsonwebtoken');
const { sendEmail } = require('../utils/sendEmail');

const getAll = catchError(async(req, res) => {
    const results = await User.findAll();
    return res.json(results);
});

const create = catchError(async(req, res) => {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const {email,firstName,lastName,country,image,isVerified}=req.body
    const body={email,firstName,lastName,country,image,isVerified}
    body.password=hashedPassword
    const result = await User.create(body);
    const code=require('crypto').randomBytes(64).toString('hex')
    const frontBaseUrl="https://autenticacionemails.netlify.app/#"
    verifyAccount({email,firstName,code,frontBaseUrl})
    await EmailCode.create({code,userId:result.id})
    
    return res.status(201).json(result);
});

const getOne = catchError(async(req, res) => {
    const { id } = req.params;
    const result = await User.findByPk(id);
    if(!result) return res.sendStatus(404);
    return res.json(result);
});

const remove = catchError(async(req, res) => {
    const { id } = req.params;
    const result = await User.destroy({ where: {id} });
    if(!result) return res.sendStatus(404);
    return res.sendStatus(204);
});

const update = catchError(async(req, res) => {
    const { id } = req.params;
    delete req.body.password
    delete req.body.email
    delete req.body.isVerified
    const result = await User.update(
        req.body,
        { where: {id}, returning: true }
    );
    if(result[0] === 0) return res.sendStatus(404);
    return res.json(result[1][0]);
});

const verified=(async(req,res)=>{
    const {code}=req.params
    const emailcodeUser= await EmailCode.findOne({where:{code}})
    if(!emailcodeUser) return res.sendStatus(401)
    const user= await User.update({
        isVerified:true },{where:{id:emailcodeUser.userId},returning:true}
    )
    await emailcodeUser.destroy()
    if(user[0] === 0) return res.sendStatus(404);
    return res.json(user[1][0])
})

const login=(async(req,res)=>{
    const {email,password}=req.body
    const user=await User.findOne({where:{email}})
    if(!user) return res.sendStatus(401)
    const isValid=await bcrypt.compare(password,user.password)
    if(isValid){
        if(!user.isVerified) res.sendStatus(401)
        const token = jwt.sign(
            { user },
            process.env.TOKEN_SECRET,
            { expiresIn: '1d' }
        );
        return res.json({user,token})

    }else{
        return res.sendStatus(401)
    }
   
})

const logget=(async(req,res)=>{
    const user=req.user
    return res.json(user)
})

const resetPassword=(async(req,res)=>{
    const {email}=req.body
    const user= await User.findOne({where:{email}})
    if(!user) return res.sendStatus(401)
    const code=require('crypto').randomBytes(64).toString('hex')
    const frontBaseUrl="https://autenticacionemails.netlify.app/#"
    sendEmail({
        to:email,
        subject:'Recuperación de contraseña',
        html:` 
        <div style="text-align: center;">
            <a href="${frontBaseUrl}/reset_password/${code}" style="display: inline-block; background-color: #007BFF; color: #ffffff; text-align: center; padding: 14px 28px; border-radius: 6px; text-decoration: none; font-weight: bold; font-size: 18px;">¡Recuperar su contraseña!</a>
        </div> `
    })
    await EmailCode.create({code,userId:user.id})
    return res.json(user)
})

const reset_passwordCode=(async(req,res)=>{
    const {code}= req.params
    const emailCode= await EmailCode.findOne({where:{code}})
    if(!emailCode) return res.sendStatus(401)
    const hashpassword=await bcrypt.hash(req.body.password,10)
    
    const user= await User.update({
        password:hashpassword },{where:{id:emailCode.userId},returning:true}
    )
    await emailCode.destroy()
    if(user[0] === 0) return res.sendStatus(404);
    return res.json(user[1][0])

})

User.prototype.toJSON = function () {
   const values = { ...this.get() };
   delete values.password ;
   return values;
};

module.exports = {
    getAll,
    create,
    getOne,
    remove,
    update,
    verified,
    login,
    logget,
    resetPassword,
    reset_passwordCode
}
