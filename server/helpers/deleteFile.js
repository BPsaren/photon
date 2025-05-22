import fs from 'fs/promises';
//import path from 'path';

const deleteFile = async (filePath) => {
    try {
        await fs.unlink(filePath); // Attempt to delete the file
        console.log(`File deleted successfully: ${filePath}`);
    } catch (error) {
        if (error.code === 'ENOENT') {
            console.warn(`File not found, skipping: ${filePath}`);
        } else {
            console.error(`Error deleting file: ${error.message}`);
        }
    }
};

export default deleteFile;
