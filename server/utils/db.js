import mongoose from 'mongoose'
import dotenv from 'dotenv'

dotenv.config()

const connections = {}
let defaultConnection = null

const baseURL = process.env.MONGODB_URI
if (!baseURL) {
    throw new Error('MONGODB_URI is not defined in the .env file')
}

// Initialize default connection
export const initializeDefaultConnection = async () => {
    if (!defaultConnection) {
        const mainDBName = process.env.MAIN_DB_NAME || 'main'
        await mongoose.connect(`${baseURL}${mainDBName}`, {})
        defaultConnection = mongoose.connection
        console.log(`Connected to default database: ${mainDBName}`)
    }
    return defaultConnection
}

// For user-specific databases
export const getDatabaseConnection = async (dbName) => {
    if (connections[dbName]) {
        return connections[dbName]
    }

    const dbURI = `${baseURL}${dbName}`
    const connection = await mongoose.createConnection(dbURI).asPromise()
    connections[dbName] = connection
    console.log(`Connected to database: ${dbName}`)
    return connection
}
