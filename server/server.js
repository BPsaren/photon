import express from 'express';
import dotenv from 'dotenv';
import usersRouter from './routes/usersRouter.js';
import authRoute from './routes/authRoute.js';
import { initializeDefaultConnection } from './utils/db.js';

dotenv.config();





const          app = express();

// Middleware to parse JSON
app.use(express.json());

// Routes
app.use('/api', usersRouter);
app.use('/', authRoute);
// Set EJS as the default view engine
app.set('view engine', 'ejs');
app.set('views', './views'); // Ensure this matches the directory where your EJS files are located
// Home route
app.get('/', (req, res) => {
    res.send('ami home page');
});

// Initialize database connection when starting the app
await initializeDefaultConnection();

// Define port
const PORT = process.env.MyPort || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
