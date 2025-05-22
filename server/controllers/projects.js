import mongoose from 'mongoose'
import { getDatabaseConnection } from '../utils/db.js'
import projectSchema from '../models/projectsModel.js' // Import schema only

const addProjects = async (req, res) => {
    try {
        const { title, description, mediaURL } = req.body
        const userId = req.user._id
        const userRole = req.user.role

        // Validation
        if (!title || !description || !mediaURL) {
            return res.status(400).json({
                success: false,
                msg: 'All fields are required.',
            })
        }

        // Get tenant-specific DB connection
        const userDBName = `${userRole}_${userId}`
        const userDB = await getDatabaseConnection(userDBName)

        // Create model for this connection
        const Project = userDB.model('Project', projectSchema) // Reuse schema

        // Save project
        const project = new Project({ title, description, mediaURL, userId })
        await project.save()

        res.status(201).json({
            success: true,
            msg: 'Project added successfully.',
            project: {
                id: project._id,
                title: project.title,
                description: project.description,
                mediaURL: project.mediaURL,
                createdAt: project.createdAt,
            },
        })
    } catch (error) {
        console.error('Project addition error:', error)
        res.status(500).json({
            success: false,
            msg: 'Failed to add project.',
            ...(process.env.NODE_ENV === 'development' && {
                error: error.message,
            }),
        })
    }
}

export default { addProjects }
