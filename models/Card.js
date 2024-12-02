const mongoose = require('mongoose');

const cardSchema = new mongoose.Schema({
    name: { type: String, required: true },
    index: { type: Number, required: true },
    tasks: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Task' }]
});

module.exports = mongoose.model('Card', cardSchema);