const mongoose = require('mongoose');

const fileSchema = new mongoose.Schema({
    name: { type: String},
    content: { type: Object, required: false },
    board: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Board', required: true }]
});

module.exports = mongoose.model('File', fileSchema);