const express = require("express");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const {z} = require("zod");
require("dotenv").config();
const cookieParser = require('cookie-parser');
const path = require('path');

const {UserModel, TodoModel} = require('./db');

const app = express();
app.use(express.json());
app.use(cookieParser());

app.set("view engine", "ejs");
app.set('views', [path.join(__dirname, 'views'), path.join(__dirname, 'views/partials')]);

app.use(express.static("public")); 
app.use(express.urlencoded({ extended: true })); 

mongoose.connect(process.env.MONGO_URI);

const { auth, JWT_SECRET } = require("./auth");

const userSchema= z.object({
    email: z.string().min(3).max(100).email(),
    password: z.string().min(5, "Password must be at least 5 characters")
    .max(100, "Password cannot exceed 100 characters")
    .regex(/[a-z]/, "Password must contain at least one lowercase letter")
    .regex(/[A-Z]/, "Password must contain at least one uppercase letter")
    .regex(/\d/, "Password must contain at least one number")
    .regex(/[@$!%*?&]/, "Password must contain at least one special character (@$!%*?&)"),
    name: z.string().min(1)
})

const todoSchema = z.object({
    title: z.string().min(1),
    dueDate: z.string().transform((str)=>new Date(str)) //Converts string to date
})

app.get("/signup", function(req, res){
    res.render("signup");
});

app.get("/signin", function(req, res){
    res.render("signin");
});

app.post("/signup", async function(req, res){

    const parsedDataWithSuccess = userSchema.safeParse(req.body);
    if(!parsedDataWithSuccess.success){
        return res.json({
            message: "Incorrect Format",
            error: parsedDataWithSuccess.error
        })
    }
    const email = req.body.email;
    const password = req.body.password;
    const name = req.body.name;
    
    try{
    const hashedPassword = await bcrypt.hash(password, 10);
    //console.log(hashedPassword);

    await UserModel.create({
        email: email,
        password: hashedPassword,
        name: name
    })
    res.redirect("/signin");
    }
    catch(e){
        res.json({
            message: "User already exists"
        })
    }
});

app.post("/signin", async function(req, res){
    const parsedDataWithSuccess = userSchema.pick({email: true, password: true}).safeParse(req.body);
    if(!parsedDataWithSuccess.success){
        return res.status(400).json({
            message: "Invalid email or oassword format",
            error: parsedDataWithSuccess.error
        })
    }
    const email = req.body.email;
    const password = req.body.password;

    const user = await UserModel.findOne({
        email: email
    })

    if(!user){
        res.status(403).json({
            message: "User does not exist in our database"
        })
        return;
    }

    const passwordMatch = await bcrypt.compare(password, user.password);

    if(passwordMatch){
        const token = jwt.sign({
            id: user._id.toString()
        },
        JWT_SECRET);
        res.cookie("token", token, {httpOnly:true});
        res.redirect("/todos");
    }
    else{
        res.status(403).json({
            message: "Incorrect Credentials"
        })
    }
});

app.post("/todo", auth, async function(req, res){
    const parsedDataWithSuccess = todoSchema.safeParse(req.body);
    if(!parsedDataWithSuccess.success){
        return res.status(401).json({
            message: "  Invalid data entered",
            error: parsedDataWithSuccess.error
        })
    }
    const userId = req.userId;
    const title = req.body.title;
    const dueDate = req.body.dueDate;
    const dueTime = req.body.dueTime;
    try{
        await TodoModel.create({
            title,
            userId,
            dueDate,
            dueTime
        })
        res.redirect("/todos");
    }
    catch(e){
        res.status(401).json({
            message:"Error creating todo"
        })
    }
});

app.get("/todos", auth, async function(req, res){
    const userId = req.userId;

    const todos = await TodoModel.find({
        userId
    })

    res.render("todos",{todos})
});

//Mark todo as done
app.put("/todo/:id/done", auth, async function(req, res){
    const todoId = req.params.id;
    const userId = req.userId;

    try{
        const todo = await TodoModel.findOneAndUpdate(
            {_id: todoId, userId},
            {done: true},
            {new: true}
        )
        if(!todo){
            return req.status(404).json({
                message: "Todo not found"
            })
        }
        res.json({
            message: "todo marked as done"
        , todo})
    }
    catch(e){
        res.status(401).json({
            message: "Error updating todo"
        })
    }
})

app.delete("/todo/:id", auth, async function(req, res){
    const todoId = req.params.id;
    const userId = req.userId;
    try{
        const deleteTodo = await TodoModel.findOneAndDelete({
            _id: todoId,
            userId
        })
        if(!deleteTodo){
            res.status(404).json({
                message: "Todo not found"
            })
        }
        res.json({
            message: "Todo deleted"
        })
    }
    catch(e){
        res.status(401).json({
            message: "Error deleting todo"
        })
    }
})

app.post('/logout', (req, res) => {
    res.clearCookie('token');
    res.redirect('/signin');
});

app.listen(3000, ()=>console.log("Running on port 3000"));