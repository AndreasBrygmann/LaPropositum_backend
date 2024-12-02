const mongoose = require('mongoose');

const boardSchema = new mongoose.Schema({
    name: { type: String, required: true },
    cards: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Card' }],
    admins: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }]
});

module.exports = mongoose.model('Board', boardSchema);