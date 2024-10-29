const mongoose = require("mongoose");
const validator = require("validator");
const connection = mongoose.connect('mongodb://localhost:27017');
// 'mongodb+srv://harry:root@firstcluster.o6mci.mongodb.net/?retryWrites=true&w=majority&appName=FirstCluster'

connection.then(() =>{
    console.log("MongoDB connection Successfull");
    
}).catch((error => console.error("Error:",error)));

const loginSchema = new mongoose.Schema({
    name:{
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true,
        unique: true,
        validate: [validator.isEmail, 'Invalid email format'],
    },
    password:{
        type: String,
        required: true
    },
    role:{
        type: String
    }
});

const collection = new mongoose.model("users", loginSchema);

module.exports = collection;