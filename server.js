// Tilkolblings dependencies til MongoDB (Database)
const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const Document = require("./document");
const nodemailer = require('nodemailer');
const crypto = require('crypto');

// JWT Token dependencies
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require("cors");

const app = express(); // Velger at det er en express applikasjon
const PORT = process.env.PORT || 5000; // Velger port applikasjonen kjører på

// Middleware (enabler cors)
app.use(cors(), bodyParser.json());

// MongoDB tilkoblingslenke
mongoose.connect('mongodb+srv://123abc:abc123!@bop3000.jed1b22.mongodb.net/?retryWrites=true&w=majority', {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
// Respons handlinger etter tilkobling
.then(() => console.log('MongoDB connected'))
.catch(err => console.error('MongoDB connection error:', err));

// Socket.io
const server = require('http').createServer(app);
const io = require("socket.io")(server, {
    cors: {
        //bytt localhost til hva enn lenken til siden vår kommer til å være til slutt
        origin: ["https://bop3000-backend.onrender.com", "http://localhost:5173", "https://lapropositum.netlify.app"],
        methods: ["GET", "POST"],
    },
});

io.on('connection', (socket) => {
    console.log('a user connected');
});

// Modeller for hver cluster
const User = require('./models/User');
const Board = require('./models/Board');
const Card = require('./models/Card');
const Task = require('./models/Task');
const File = require('./models/File');
const defaultvalue = ""; // Default tom dokument streng

//------------------------------------------------------------------------------------------------

//                                              ROUTES

//------------------------------------------------------------------------------------------------
//                                      Middleware AuthToken:

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    if (!authHeader) {
        return res.status(401).json({ message: 'Token mangler' });
    }

    const token = authHeader.split(' ')[1]; // Skiller ut Token fra Bearer med mellomrom
    
    // Verifiserer Token med hemmelig nøkkel
    jwt.verify(token, 'ThisIsMy_SeCrEt_KeY', async (err, decoded) => {
        if (err) {
            console.error('Feil i å verifisere JWT:', err);
            return res.status(403).json({ message: 'Ugyldig token' });
        }
        
        try {
            const user = await User.findById(decoded.userId); // Henter ut bruker fra database
            if (!user) {
                return res.status(404).json({ message: 'Bruker ikke funnet' });
            }
            req.user = { userId: user._id }; // Definerer brukerid
            next();
        } catch (err) { // Feilhåndtering
            console.error('Fikk ikke hentet bruker:', err);
            res.status(500).json({ message: 'Intern server feil' });
        }
    });
}

//------------------------------------------------------------------------------------------------
//                                          Login Route:
app.post('/login', async (req, res) => {
    const { email, password } = req.body; // Henter epost og passord fra body i json fra REACT
    const user = await User.findOne({ email }); // Finner bruker ved hjelp av mail

    // Feilmelding hvis bruker ikke eksisterer
    if (!user) { return res.status(401).json({ message: 'Feil mail' }); }

    try {
        // Bruker B-crypt for å sjekke om passord matcher i databasen
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) { return res.status(401).json({ message: 'Feil passord' }); } // Feilmelding

        // Hvis epost og passord er korrekt genereres det en token som er gyldig i 4t
        const token = jwt.sign({ userId: user._id }, 'ThisIsMy_SeCrEt_KeY', { expiresIn: '4h' });
        console.log('Generert token:', token);
        res.json({ token });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Intern server feil' });
    }
});

//------------------------------------------------------------------------------------------------
//                                          User Routes:

// Get all users (for å få opp brukere når man skal invite noen)
app.get('/users', authenticateToken, async (req, res) => {
    try {
        // Find and retrieve all users, selecting only the email field
        const users = await User.find({}, 'email');
        res.json(users); // Return only the email addresses to the frontend
    } catch (err) { // Error handling
        res.status(500).json({ message: err.message });
    }
});

// Get all uisers for a board
app.get('/users/:boardId', authenticateToken, async (req, res) => {
    const { boardId } = req.params; // Extract boardId from the request parameters

    try {
        // Find users who are associated with the specified board
        const users = await User.find({ boards: boardId }, '_id email');

        res.json(users); // Return the user IDs and email addresses of users associated with the board to the frontend
    } catch (err) {
        // Error handling
        res.status(500).json({ message: err.message });
    }
});

//                                          Create User
app.post('/users', async (req, res) => {
    const { sanitizedEmail, sanitizedPassword } = req.body; // Henter epost og passord fra json body fra REACT
    const email = sanitizedEmail;
    const password = sanitizedPassword;
    try {
        // Hasher passordet før det lagres til databasen med bcrypt (Bruker salt slik at alle passord er unike)
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ email, password: hashedPassword, boards: [] }); // Oppretter brukeren med modell
        const newUser = await user.save(); // Lagrer brukeren i MongoDB
        res.status(201).json(newUser);
    } catch (err) {
        res.status(400).json({ message: err.message }); // Feilmelding
    }
});

//                                 Update User Password and Email
app.patch('/users', authenticateToken, async (req, res) => {
    const userId = req.user.userId; // Henter id fra token
    const { email, password } = req.body; // Henter mail og passord fra body fra REACT

    try {
        // Hasher passordet før det lagres til databasen med bcrypt
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = await User.findByIdAndUpdate(userId, { email, password: hashedPassword }, { new: true });// Lager bruker

        // Sjekker om brukeren eksisterer i database (Er dette nødvendig?!?)!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        res.json(user); // Respons til Frontend
    } catch (err) { // Feilmelding
        res.status(400).json({ message: err.message });
    }
});

//                              Get all files associated with a user
app.get('/user/files', authenticateToken, async (req, res) => {
    const userId = req.user.userId;

    try {
        // Find the user and their boards
        const user = await User.findById(userId).populate('boards');
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Get the user's board IDs
        const boardIds = user.boards.map(board => board._id);

        // Find files associated with those boards
        const files = await File.find({ board: { $in: boardIds } }).populate('board');

        // Construct the response
        const result = await Promise.all(files.map(async file => {
            const board = await Board.findById(file.board);
            return {
                id: file._id,
                name: file.name,
                boardName: board.name
            };
        }));

        res.json(result);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

//                                          Delete User
app.delete('/users/', authenticateToken, async (req, res) => {
    //const { id } = req.params; // Henter id parameter fra api-link sendt fra REACT
    const id = req.user.userId; // Henter id fra token
    try {
        await User.findByIdAndDelete(id); // Finner og sletter bruker med ID
        res.json({ message: 'Bruker Slettet' }); // Respons til Frontend
    } catch (err) { // Feilmelding
        res.status(400).json({ message: err.message });
    }
});

/*app.delete('/users/:email', authenticateToken, async (req, res) => {
    const { email } = req.params; // Henter e-post parameter fra api-link sendt fra REACT
    try {
        var query = { email: email };
        //dbo.collection("User").deleteOne(query);
        await User.deleteOne(query);
        res.json({ message: 'Bruker Slettet' }); // Respons til Frontend
    } catch (err) { // Feilmelding
        res.status(400).json({ message: err.message });
    }
});*/

//------------------------------------------------------------------------------------------------
//                                          Board Routes:

//                                         GET all boards
app.get('/boards', authenticateToken, async (req, res) => {
    console.log("Entered /boards route handler");
    try {
        const userId = req.user.userId; // Henter id for bruker fra token
        console.log("User ID extracted from token:", userId);

        const user = await User.findById(userId).populate('boards'); // Finner brukeren og fyller inn boards til bruker
        console.log("User found:", user);

        const boards = user.boards; // Henter ut boardsa fra bruker-objektet
        console.log("Boards extracted from user:", boards);

        res.json(boards); // Gir tilbake boards for brukeren
    } catch (err) { // Feilmeldinger
        console.error("Error:", err);
        res.status(500).json({ message: err.message });
    }
});

//                                          Create Board
app.post('/boards', authenticateToken, async (req, res) => {
    const { name } = req.body; // Henter ut navn for board fra REACT
    const userId = req.user.userId; // Henter ut bruker id fra token

    try {
        const board = new Board({ name, cards: [], admins: [userId] }); // Oppretter board med bruker som admin
        const newBoard = await board.save(); // Lagrer board i MongoDB

        await User.findByIdAndUpdate(userId, { $push: { boards: newBoard._id } }); // Legger til board i brukerens array

        res.status(201).json(newBoard); // Returnerer board til Frontend
    } catch (err) { // Feilmelding
        res.status(400).json({ message: err.message });
    }
});

//                                        Update Board Name
app.patch('/boards/:id', authenticateToken, async (req, res) => {
    const { id } = req.params; // Henter ut id fra link
    const { name } = req.body; // Henter ut navn fra Json fra REACT
    const userId = req.user.userId; // Henter brukerid fra token

    try {
        const board = await Board.findById(id); // Søker etter board i boards
        if (!board) { return res.status(404).json({ message: 'Finner ikke board' }); } // Sjekker om board finnes

        if (!board.admins.includes(userId)) { // Sjekker om brukeren er admin for det boardet
            return res.status(403).json({ message: 'Bruker er ikke admin for boardet' });
        }
        const updatedBoard = await Board.findByIdAndUpdate(id, { name }, { new: true }); // Oppdaterer boardnavn
        res.json(updatedBoard); // Returnerer oppdatert board
    } catch (err) { // Feilmelding
        res.status(400).json({ message: err.message });
    }
});

//                                       Add user to Board
app.patch('/boards/:email/boards/:boardId/invite', authenticateToken, async (req, res) => {
    const { boardId, email } = req.params; // Henter ut boardid og mail fra link
    // Gjør det på denne måten siden det er tre "patch" for board. Dette gjør at dem ikke er like.

    try { // Henter ut brukeren's id som inviterer og sjekker om han eksisterer
        const invitingUser = await User.findById(req.user.userId);
        if (!invitingUser) {
            return res.status(404).json({ message: 'Inviterende bruker ikke funnet' }); // !!!!!!!!!!!!!!!!!!!!!!!!!!!
        }

        if (!invitingUser.boards.includes(boardId)) { // Sjekker om den inviterende brukeren er medlem av boardet
            return res.status(403).json({ message: 'Brukeren har ikke tilgang til boardet' }); // !!!!!!!!!!!!!!!!!!!!
        }

        // Sjekker om brukeren som blir invitert eksisterer
        const invitedUser = await User.findOne({ email });
        if (!invitedUser) { return res.status(404).json({ message: 'Bruker som blir invitert ikke funnet' }); }
        
        // Legger til boardet til brukeren som ble invitert
        if (!invitedUser.boards.includes(boardId)) {
            invitedUser.boards.push(boardId);
            await invitedUser.save();
        }
        
        res.json({ message: 'Bruker invitert til board!' }); // Respons til Frontend
    } catch (err) { // Feilmelding
        res.status(500).json({ message: err.message });
    }
});


//                                Add user as admin to the board
app.patch('/boards/:boardId/admins/:email', authenticateToken, async (req, res) => {
    const { boardId, email } = req.params; // Extract boardId and email from the request parameters

    try {
        // Find the inviting user by ID
        const invitingUser = await User.findById(req.user.userId);
        if (!invitingUser) {
            return res.status(404).json({ message: 'Inviting user not found' });
        }

        // Find the board by ID
        const board = await Board.findById(boardId);
        if (!board) {
            return res.status(404).json({ message: 'Board not found' });
        }

        // Check if the inviting user is an admin of the board
        const isAdmin = board.admins.includes(invitingUser._id);
        if (!isAdmin) {
            return res.status(403).json({ message: 'User is not an admin of the board' });
        }

        // Find the user to be added as admin
        const userToAddAsAdmin = await User.findOne({ email });
        if (!userToAddAsAdmin) {
            return res.status(404).json({ message: 'User to be added as admin not found' });
        }

        // Check if the user to be added as admin is a member of the board
        const isMember = userToAddAsAdmin.boards.includes(boardId);
        if (!isMember) {
            return res.status(403).json({ message: 'User is not a member of the board' });
        }

        // Add the user as admin to the board if they are not already an admin
        if (!board.admins.includes(userToAddAsAdmin._id)) {
            board.admins.push(userToAddAsAdmin._id);
            await board.save();
        }

        res.json({ message: 'User added as admin to the board' });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});


//                                          REMOVE ADMIN ROLE
app.post('/boards/remove-admin', authenticateToken, async (req, res) => {
    const { boardId, email } = req.body;
    const userId = req.user.userId; // User ID of the requester

    // Log request body and userId for debugging
    console.log('Request body:', req.body);
    console.log('Authenticated User ID:', userId);

    if (!boardId || !email) {
        return res.status(400).json({ message: 'Board ID and email are required' });
    }

    try {
        // Find the board by its ID
        const board = await Board.findById(boardId);
        if (!board) {
            console.log('Board not found:', boardId);
            return res.status(404).json({ message: 'Board not found' });
        }

        // Check if the requesting user is an admin of the board
        if (!board.admins.includes(userId)) {
            console.log('User is not an admin of this board:', userId);
            return res.status(403).json({ message: 'User is not an admin of this board' });
        }

        // Find the user to be removed by email
        const userToRemove = await User.findOne({ email: email });
        if (!userToRemove) {
            console.log('User to be removed not found:', email);
            return res.status(404).json({ message: 'User to be removed not found' });
        }

        const userIdToRemove = userToRemove._id;

        // Check if the user to be removed is an admin of the board
        if (!board.admins.includes(userIdToRemove)) {
            console.log('User to be removed is not an admin of this board:', userIdToRemove);
            return res.status(404).json({ message: 'User to be removed is not an admin of this board' });
        }

        // Remove the user from the admin array
        board.admins.pull(userIdToRemove);
        await board.save();

        res.json({ message: 'Admin removed successfully' });
    } catch (err) {
        console.error('Error:', err);
        res.status(500).json({ message: err.message });
    }
});



//                           Get all admins for board (EDIT DENNE!!!)
app.get('/boards/admins/:boardId', authenticateToken, async (req, res) => {
    const { boardId } = req.params; // Extract boardId from the request parameters

    try {
        // Find the board by ID
        const board = await Board.findById(boardId);

        if (!board) {
            return res.status(404).json({ message: 'Board not found' });
        }

        // Extract admin IDs from the board
        const adminIds = board.admins;

        // Find users with admin IDs and select only their _id and name fields
        const admins = await User.find({ _id: { $in: adminIds } }, '_id email');

        res.json(admins); // Return the IDs and names of admins for the board to the frontend
    } catch (err) {
        // Error handling
        res.status(500).json({ message: err.message });
    }
});

//                                   DELETE USER FROM BOARD (100%)
app.delete('/boards/remove-user', authenticateToken, async (req, res) => {
    const { boardId, email } = req.body;
    const adminId = req.user.userId;

    try {
        // Check if the board exists
        const board = await Board.findById(boardId);
        if (!board) {
            return res.status(404).json({ message: 'Board not found' });
        }

        // Check if the requester is an admin of the board
        if (!board.admins.includes(adminId)) {
            return res.status(403).json({ message: 'User is not an admin of this board' });
        }

        // Find the user by email
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        const userId = user._id;

        // Remove user from the board's admins array
        board.admins = board.admins.filter(admin => !admin.equals(userId));
        await board.save();

        // Remove the board from the user's boards array
        user.boards = user.boards.filter(board => !board.equals(boardId));
        await user.save();

        // Find all cards associated with the board
        const cards = await Card.find({ _id: { $in: board.cards } });

        // Find all tasks associated with the cards
        const taskIds = cards.reduce((acc, card) => acc.concat(card.tasks), []);
        const tasks = await Task.find({ _id: { $in: taskIds } });

        // Remove user from tasks' users arrays
        await Promise.all(tasks.map(async task => {
            task.users = task.users.filter(taskUser => !taskUser.equals(userId));
            await task.save();
        }));

        res.status(200).json({ message: 'User removed from board successfully' });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});


//                                          Delete Board
app.delete('/boards/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const userId = req.user.userId; // Extract user ID from the token payload
    
    try {
        // Find the board
        const board = await Board.findById(id);
        if (!board) {
            return res.status(404).json({ message: 'Board not found' });
        }
        
        // Check if the user is an admin of the board
        if (!board.admins.includes(userId)) {
            return res.status(403).json({ message: 'Only admins of the board can delete it' });
        }

        // Find all cards on the board
        const cards = await Card.find({ _id: { $in: board.cards } });

        // Log the cards and associated tasks for debugging
        console.log('Cards on the board:', cards);
        for (const card of cards) {
            console.log(`Tasks on card ${card._id}:`, card.tasks);
        }

        // Delete all tasks associated with cards on this board
        for (const card of cards) {
            await Task.deleteMany({ _id: { $in: card.tasks } });
            // Clear tasks array in the card document
            card.tasks = [];
            await card.save();
        }

        // Delete all cards on the board
        await Card.deleteMany({ _id: { $in: board.cards } });

        // Delete the board itself
        await Board.findByIdAndDelete(id);

        res.json({ message: 'Board deleted' });
    } catch (err) {
        res.status(400).json({ message: err.message });
    }
});

//------------------------------------------------------------------------------------------------
//                                          Card Routes:

//                                           GET CARDS
app.get('/cards/:boardId', authenticateToken, async (req, res) => {
    const { boardId } = req.params; // Hnenter boardIDen fra link
    
    try { // Finner board med boardID og legger til cards i cards-arrayet i board clusteret
        const board = await Board.findById(boardId).populate({
            path: 'cards',
            populate: {
                path: 'tasks',
                select: 'name _id desc' // Include both name and _id of tasks
            }
        });

        if (!board) { // Sjekker om den fant boardet
            return res.status(404).json({ message: 'Finner ikke board' });
        }
        
        const cardsWithTasksAndIndex = board.cards.map(card => {
            return {
                _id: card._id,
                name: card.name,
                index: card.index,
                tasks: card.tasks.map(task => ({ name: task.name, _id: task._id, desc: task.desc })) // Include task _id
            };
        });

        res.json(cardsWithTasksAndIndex); // Gir tilbake kortene med tasks og index til Frontend
    } catch (err) { // Feilmelding
        res.status(500).json({ message: err.message });
    }
});

//                                          Create Card
app.post('/cards/:boardId', authenticateToken, async (req, res) => { // !!!!!!!!!! INDEX MÅ VÆRE UNIK !!!!!!!!!!!!!
    const { boardId } = req.params; // Henter boardID fra link
    const { name, index } = req.body; // Henter navn og index på kort
    const userId = req.user.userId; // brukerid hentet fra token

    try {
        const board = await Board.findById(boardId); // Finner brukeren
        if (!board) { return res.status(404).json({ message: 'Finner ikke board' }); }
        
        if (!board.admins.includes(userId)) { // Sjekker om brukeren er admin for boardet
            return res.status(403).json({ message: 'Bruker er ikke admin for boardet' });
        }

        // Lager det nye kortet
        const card = new Card({ name, index, tasks: [] }); // Lager objektet
        const newCard = await card.save(); // Lagrer objektet i MongoDB
        
        // Legger til kortet i kort-array i boards cluster
        board.cards.push(newCard._id);
        await board.save();

        res.status(201).json(newCard);
    } catch (err) { // Feilmelding
        res.status(400).json({ message: err.message });
    }
});

//                                          UPDATE CARD
app.patch('/cards/:id', authenticateToken, async (req, res) => {
    const { id } = req.params; // Henter id for kort fra link
    const { name, index } = req.body; // Henter navn og index fra JSON body fra REACT
    const userId = req.user.userId; // Henter brukerID fra token

    try { // Sjekker om kort eksisterer
        const card = await Card.findById(id);
        if (!card) { return res.status(404).json({ message: 'Kort ikke funnet' }); }

        // Sjekker om brukeren er admin på boardet kortet eksisterer på
        const board = await Board.findOne({ cards: id, admins: userId });
        if (!board) { return res.status(403).json({ message: 'Bruker ikke admin på board' }); }

        // Oppdaterer kortets navn og index
        const updatedCard = await Card.findByIdAndUpdate(id, { name, index }, { new: true });
        res.json(updatedCard);
    } catch (err) { // Feilmelding
        res.status(400).json({ message: err.message });
    }
});


//                                          UPDATE CARD ORDER
app.post('/boards/update-card-order', authenticateToken, async (req, res) => {
    const { boardId, cardIds } = req.body;
    const userId = req.user.userId;

    // Log request body for debugging
    console.log('Request body:', req.body);

    if (!boardId) {
        return res.status(400).json({ message: 'Board ID is required' });
    }

    if (!Array.isArray(cardIds)) {
        return res.status(400).json({ message: 'Card IDs must be an array' });
    }

    try {
        // Find the board by its ID
        const board = await Board.findById(boardId);
        if (!board) {
            console.log('Board not found:', boardId);
            return res.status(404).json({ message: 'Board not found' });
        }

        // Check if the requesting user is an admin of the board
        if (!board.admins.includes(userId)) {
            console.log('User is not an admin of this board:', userId);
            return res.status(403).json({ message: 'User is not an admin of this board' });
        }

        // Replace the cards array with the new order
        board.cards = cardIds.map(id => new mongoose.Types.ObjectId(id));
        await board.save();

        res.json({ message: 'Card order updated successfully' });
    } catch (err) {
        console.error('Error:', err);
        res.status(500).json({ message: err.message });
    }
});


//                                          Delete Card
app.delete('/cards/:id', authenticateToken, async (req, res) => {
    const { id } = req.params; // Get card ID from the request parameters
    const userId = req.user.userId; // Get user ID from the authenticated user

    try {
        // Find the card by its ID
        const card = await Card.findById(id);
        if (!card) return res.status(404).json({ message: 'Card not found' });

        // Find the board that contains this card
        const board = await Board.findOne({ cards: card._id });
        if (!board) return res.status(404).json({ message: 'Board not found' });

        // Check if the user is an admin of the board
        if (!board.admins.includes(userId)) {
            return res.status(403).json({ message: 'User is not an admin of this board' });
        }

        // Find all tasks associated with the card
        const tasks = await Task.find({ _id: { $in: card.tasks } });

        // Delete each task associated with the card
        await Promise.all(tasks.map(async (task) => {
            await Task.findByIdAndDelete(task._id);
        }));

        // Remove card reference from the corresponding board
        await Board.updateOne({ cards: card._id }, { $pull: { cards: card._id } });

        // Delete the card
        await Card.findByIdAndDelete(id);

        res.json({ message: 'Card and associated tasks deleted successfully' });
    } catch (err) {
        res.status(400).json({ message: err.message });
    }
});


//------------------------------------------------------------------------------------------------
//                                          Task Routes:


//                                           GET TASKS (MÅ TESTES)
app.get('/tasks/:taskId', authenticateToken, async (req, res) => {
    const { taskId } = req.params;
    const userId = req.user.userId; // Assuming the authenticateToken middleware sets req.user

    try {
        // Find the task with the specified ID and populate only email and _id of users, and populate files
        const task = await Task.findById(taskId)
            .populate({
                path: 'users',
                select: 'email _id' // Ensure only email and _id fields are selected
            })
            .populate('files');

        if (!task) {
            return res.status(404).json({ message: 'Task not found' });
        }

        // Check if the user is associated with the task
        const isUserAssociated = task.users.some(user => user._id.equals(userId));

        // If the user is associated, include the related files
        if (isUserAssociated) {
            return res.json(task);
        }

        // If the user is not associated, exclude the files
        const taskWithoutFiles = task.toObject();
        delete taskWithoutFiles.files;

        res.json(taskWithoutFiles);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

//                                          Create Task
app.post('/tasks/:boardId/:cardId', authenticateToken, async (req, res) => {
    const { boardId, cardId } = req.params;
    const { name, desc } = req.body;

    try {
        // Check if the board exists
        const board = await Board.findById(boardId);
        if (!board) {
            return res.status(404).json({ message: 'Board not found' });
        }

        // Check if the card exists on the board
        const cardExistsOnBoard = board.cards.includes(cardId);
        if (!cardExistsOnBoard) {
            return res.status(404).json({ message: 'Card not found on this board' });
        }

        const userId = req.user.userId; // Extract user ID from token

        if (!board.admins.includes(userId)) { // Check if the user is an admin for the board
            return res.status(403).json({ message: 'User is not an admin for this board' });
        }

        // Create the task
        const task = new Task({ name, desc });

        // Add the user who is creating the task to the users array
        task.users.push(userId);

        const newTask = await task.save();

        // Add the task to the card's array of tasks
        await Card.findByIdAndUpdate(cardId, { $push: { tasks: newTask._id } });

        res.status(201).json(newTask);
    } catch (err) {
        res.status(400).json({ message: err.message });
    }
});


//                              Update Task Name, Description, and Users!!!!!!!!!!!!!!!!! TEST DENNE !!!!!!
app.patch('/tasks/:taskId', authenticateToken, async (req, res) => {
    const {taskId} = req.params;
    const {name, desc } = req.body;
    const userId = req.user.userId;

    try {
        // Fetch the task
        const task = await Task.findById(taskId);

        if (!task) {
            return res.status(404).json({ message: 'Task not found' });
        }

        // Fetch the card containing the task to determine the board
        const card = await Card.findOne({ tasks: taskId });

        if (!card) {
            return res.status(404).json({ message: 'Card not found for task' });
        }

        // Fetch the board containing the card
        const board = await Board.findOne({ cards: card._id });

        if (!board) {
            return res.status(404).json({ message: 'Board not found for card' });
        }

        // Check if the inviting user is an admin of the board
        if (!board.admins.includes(userId)) {
            // Check if the inviting user is already in the users array of the task
            if (!task.users.includes(userId)) {
                return res.status(403).json({ message: 'Not authorized to invite users to this task' });
            }
        }

        // Update the task with the provided data
        task.name = name;
        task.desc = desc;

        // Save the updated task
        await task.save();

        return res.json({task});
    } catch (err) {
        return res.status(500).json({ message: err.message });
    }
});


//                                       Invite user to task
app.patch('/tasks/:taskId/:email/invite', authenticateToken, async (req, res) => {
    const { taskId, email } = req.params;
    const userId = req.user.userId;

    try {
        // Fetch the task
        const task = await Task.findById(taskId);

        if (!task) {
            return res.status(404).json({ message: 'Task not found' });
        }

        // Fetch the card containing the task to determine the board
        const card = await Card.findOne({ tasks: taskId });

        if (!card) {
            return res.status(404).json({ message: 'Card not found for task' });
        }

        // Fetch the board containing the card
        const board = await Board.findOne({ cards: card._id });

        if (!board) {
            return res.status(404).json({ message: 'Board not found for card' });
        }

        // Check if the inviting user is an admin of the board
        if (!board.admins.includes(userId)) {
            // Check if the inviting user is already in the users array of the task
            if (!task.users.includes(userId)) {
                return res.status(403).json({ message: 'Not authorized to invite users to this task' });
            }
        }

        // Fetch the user to invite
        const userToInvite = await User.findOne({ email });

        if (!userToInvite) {
            return res.status(404).json({ message: 'User to invite not found' });
        }

        // If the user to invite is not already in the task's users array, add them
        if (!task.users.includes(userToInvite._id)) {
            task.users.push(userToInvite._id);
            await task.save();
        }

        return res.json({ message: 'User invited to the task' });
    } catch (err) {
        return res.status(500).json({ message: err.message });
    }
});


//                                     MOVES TASK BETWEEN CARDS
app.post('/tasks/move', authenticateToken, async (req, res) => {
    const { oldCardId, newCardId, taskId, taskIds } = req.body;
    const userId = req.user.userId;

    try {
        // Verify the user is an admin on the board associated with the cards
        const oldCard = await Card.findById(oldCardId);
        const newCard = await Card.findById(newCardId);

        if (!oldCard || !newCard) {
            return res.status(404).json({ message: 'One or both of the cards were not found' });
        }

        // Get the board containing the cards
        const board = await Board.findOne({ cards: { $in: [oldCardId, newCardId] } });
        if (!board) {
            return res.status(404).json({ message: 'Board not found' });
        }

        // Check if the user is an admin of the board
        if (!board.admins.includes(userId)) {
            return res.status(403).json({ message: 'User is not an admin of this board' });
        }

        if (oldCardId != newCardId) {
            // Remove task from old card's task array if it exists there
            if (oldCard.tasks.includes(taskId)) {
                oldCard.tasks.pull(taskId);
                await oldCard.save();
            }
        }

        // Update new card's task array with the new array of taskIds
        newCard.tasks = taskIds;
        await newCard.save();

        res.status(200).json({ message: 'Tasks moved successfully' });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});


//                                          Delete Task 100% ferdig
app.delete('/tasks/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const userId = req.user.userId;

    try {
        const task = await Task.findById(id);
        if (!task) return res.status(404).json({ message: 'Task not found' });

        // Find the card that contains this task
        const card = await Card.findOne({ tasks: task._id });
        if (!card) return res.status(404).json({ message: 'Card not found' });

        // Find the board that contains this card
        const board = await Board.findOne({ cards: card._id });
        if (!board) return res.status(404).json({ message: 'Board not found' });

        // Check if the user is an admin of the board
        if (!board.admins.includes(userId)) {
            return res.status(403).json({ message: 'User is not an admin of this board' });
        }

        // Remove the task reference from the task array in the card document
        await Card.updateOne({ tasks: task._id }, { $pull: { tasks: task._id } });

        // Delete the task
        await Task.findByIdAndDelete(id);

        res.json({ message: 'Task deleted successfully' });
    } catch (err) {
        res.status(400).json({ message: err.message });
    }
});


//----------------------------------------------------------------------------------------------------------------------------------------------------------------------
//                                                      Reset password
//Kun til testing
app.get('/checkEmail', async (req, res) => {
    const { email } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) {
            res.json({ message: 'e-post ikke funnet' });
        }
        else {res.json({ message: 'e-post eksisterer' });}

    } catch (err) { // Feilmelding
        res.status(500).json({ message: err.message });
    }
});
//Generer en e-post med token i url
app.post('/generateMail', async (req, res) => {
    const { email } = req.body;
    //if (!email) return res.status(404).json({ message: 'no e-mail found' });
    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: 'E-mail doesnt exist' });
        }
        const token = jwt.sign({ userId: user._id }, 'ThisIsMy_SeCrEt_KeY', { expiresIn: '15m' });
        const url = "https://lapropositum.netlify.app/ResetPassword?Token=" + token;
        //Generer en e-post med nodemailer
        const nodemailer = require("nodemailer");

        const transporter = nodemailer.createTransport({
        host: "smtp.zoho.eu",
        port: 465,
        secure: true, //ssl
        auth: {
            user: "lapropositum@zohomail.eu",
            pass: "telemarkVann100",
        },
        });

        // async..await is not allowed in global scope, must use a wrapper
        async function main() {
        // send mail with defined transport object
        const info = await transporter.sendMail({
            from: '"La Propositum" <lapropositum@zohomail.eu>', // sender address
            to: email, // list of receivers
            subject: "Reset Password", // Subject line
            text: "Click on the link under to reset your password. If you did not reset your password you can safely ignore this e-mail", // plain text body
            html: "<b>Click on the link under to reset your password. <br><br> If you did not reset your password you can safely ignore this e-mail. <br><br><br> <a href=" + url + ">Click here to reset your password</a><br><br></b>", // html body
        });

        console.log("Message sent: %s", info.messageId);
        // Message sent: <d786aa62-4e0a-070a-47ed-0b0666549519@ethereal.email>
        }

        main().catch(console.error);

        res.json("password reset link sendt to e-mail");
    } catch (err) { // Feilmelding
        res.status(500).json({ message: err.message });
    }
});
//Reseter passord med token
app.patch('/resetPassword', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    const { password } = req.body;
    try {
        //User.password = password;
        const hashedPassword = await bcrypt.hash(password, 10);
        await User.findByIdAndUpdate(userId, {password: hashedPassword }, { new: true });
        res.json("Password updated");
    } catch (err) { // Feilmelding
        res.status(500).json({ message: err.message });
    }
});

//------------------------------------------------------------------------------------------------

//             (100% ferdig) HENTER ALLE FILER ASSOSIERT MED BOARDID MEN KUN DE SOM IKKE ER KNYTTET TIL TASKS
app.get('/file/:boardId', authenticateToken, async (req, res) => {
    try {
        const { boardId } = req.params;

        const files = await File.find({ board: boardId, tasks: { $size: 0 } });

        res.status(200).json(files);
    } catch (err) {
        res.status(400).json({ message: err.message });
    }
});

//                      HER KAN KUN ADMIN LEGGE TIL FIL PÅ TASK (100%)
app.post('/file/assign-task', authenticateToken, async (req, res) => {
    const { fileId, taskId } = req.body;

    if (!fileId || !taskId) {
        return res.status(400).json({ message: 'File ID and Task ID are required' });
    }

    try {
        // Fetch the file
        const file = await File.findById(fileId).populate('board');
        if (!file) {
            return res.status(404).json({ message: 'File not found' });
        }

        // Fetch the board containing the file
        const board = await Board.findOne({ _id: { $in: file.board } });
        if (!board) {
            return res.status(404).json({ message: 'Board not found' });
        }

        const userId = req.user.userId; // Use userId from authenticateToken middleware
        console.log(userId);

        // Check if the user is an admin of the board
        if (!board.admins.includes(userId)) {
            return res.status(403).json({ message: 'User is not an admin on this board' });
        }

        // Fetch the task
        const task = await Task.findById(taskId);
        if (!task) {
            return res.status(404).json({ message: 'Task not found' });
        }

        // Assign the file to the task
        task.files.push(fileId);
        await task.save();

        res.status(200).json({ message: 'File assigned to task successfully', task });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});


//                  HER KAN ADMIN FJERNE FIL FRA TASK (100%)
app.post('/file/remove-task', authenticateToken, async (req, res) => {
    const { fileId, taskId } = req.body;

    if (!fileId || !taskId) {
        return res.status(400).json({ message: 'File ID and Task ID are required' });
    }

    try {
        const file = await File.findById(fileId).populate('board');
        if (!file) {
            return res.status(404).json({ message: 'File not found' });
        }

        const board = await Board.findById(file.board[0]);
        if (!board) {
            return res.status(404).json({ message: 'Board not found' });
        }

        const userId = req.user.userId;

        if (!board.admins.includes(userId)) {
            return res.status(403).json({ message: 'User is not an admin on this board' });
        }

        const taskIndex = file.tasks.indexOf(taskId);
        if (taskIndex > -1) {
            file.tasks.splice(taskIndex, 1);
            await file.save();
            return res.status(200).json({ message: 'Task removed successfully', file });
        } else {
            return res.status(404).json({ message: 'Task not found in file' });
        }

    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});


app.get('/link', authenticateToken, async (req, res) => {
    try {
        const files = await File.find();
        res.json(files);
    } catch (err) { // Feilmelding
        res.status(500).json({ message: err.message });
    }
});

//                                  OPPRETTER FIL (100% ferdig, returnerer id)
app.post('/link', authenticateToken, async (req, res) => {
    try {
        const { boardId } = req.body; // Extract boardId from the request body
        let { name } = req.body; // Extract name from the request body

        if (!boardId) {
            return res.status(400).json({ message: 'Board ID is required' });
        }
        if (!name) {
            name = "";
        }

        const newFile = await File.create({ name: name, content: "", board: [boardId] }); // Create a new document with empty content and the board ID

        res.status(201).json({ id: newFile._id }); // Respond with the ID of the created entry
    } catch (err) {
        res.status(400).json({ message: err.message }); // If there's an error, respond with a 400 status and an error message
    }
});


/*app.delete('/link', authenticateToken, async (req, res) => {
    try {
        // Delete all documents in the File collection
        await File.deleteMany({});
        res.status(200).json({ message: 'All entries deleted successfully' });
    } catch (err) {
        // Handle any errors
        res.status(500).json({ message: 'Failed to delete entries', error: err.message });
    }
});*/

app.delete('/link/:id', authenticateToken, async (req, res) => {
    const fileId = req.params.id; // Extract file id parameter from request
    
    try {
        const file = await File.findById(fileId);
        if (!file) {
            return res.status(404).json({ message: 'File not found' });
        }

        // Find all tasks that reference the file
        const tasks = await Task.find({ files: file._id });

        // Delete each task reference to the file
        await Promise.all(tasks.map(async (task) => {
            task.files.pull(file._id);
            await task.save();
        }));

        // Delete the file itself
        await File.findByIdAndDelete(fileId);

        res.status(200).json({ message: 'File and associated references deleted successfully' });
    } catch (err) {
        res.status(500).json({ message: 'Failed to delete entry', error: err.message });
    }
});


//Socket.IO 
io.on("connection", socket => {
    socket.on("get-document", async documentId => {
        const document = await findorcreateDoc(documentId)
        socket.join(documentId)
        socket.emit("load-document", document.data)

        socket.on("send-changes", delta => {
            socket.broadcast.to(documentId).emit("receive-changes", delta)
        })

        socket.on("save-document", async data => {
            await Document.findByIdAndUpdate(documentId, {data})
        })
    })
})

async function findorcreateDoc(id){
    if (id == null) return

    const document = await Document.findById(id)
    if (document) return document
    return await Document.create({_id: id, data: defaultvalue })
}

// ____________________________________________DELETE ALL SPØRRINGER___________________________________________

// Route to delete all files
app.delete('/files', authenticateToken, async (req, res) => {
    try {
        // Delete all files from the database
        await File.deleteMany({});

        res.status(200).json({ message: 'All files have been deleted successfully' });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

//_____________________________________________________________________________________________________________


// Start the server
server.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});