const mongoose = require('mongoose');

const taskSchema = new mongoose.Schema({
    name: { type: String, required: true },
    desc: { type: String, required: false },
    users: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    files: [{type: mongoose.Schema.Types.ObjectId, ref: 'File'}]
});

module.exports = mongoose.model('Task', taskSchema);