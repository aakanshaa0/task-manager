const mongoose = require("mongoose");
const Schema = mongoose.Schema;
const ObjectId = mongoose.ObjectId;

const User = new Schema({
    email : {type: String, unique: true, required: true},
    password: {type: String,required: true},
    name: {type: String, required: true}
})

const Todo = new Schema({
    title: {type: String, required: true},
    done: {type: Boolean, default: false},
    userId: {type: ObjectId, ref: "users", required: true},
    createdAt: {type: Date, default: Date.now},
    dueDate: {type: Date, required: true},
    dueTime: {type: String, required: true}
})

const UserModel = mongoose.model('users', User);
const TodoModel = mongoose.model('todos', Todo);

module.exports = {
    UserModel: UserModel,
    TodoModel: TodoModel
}
