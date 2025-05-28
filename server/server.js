import dotenv from 'dotenv';
import app from './app.js';

dotenv.config();

// Define port
const PORT = process.env.MyPort || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port: ${PORT}`);
});
