/**
 * Settings Routes
 * Handles settings-related API endpoints
 */

const express = require('express');
const router = express.Router();
const configService = require('../services/config');

/**
 * GET /api/settings/can-delete-all
 * Check if the current user is allowed to see the delete all button
 * Returns true if the user's email is in the CAN_SEE_DELETE_ALL_BUTTON env variable
 */
router.get('/can-delete-all', async (req, res) => {
    try {
        // Check if user is authenticated
        if (!req.user) {
            return res.status(401).json({
                success: false,
                error: 'Not authenticated',
                canDeleteAll: false
            });
        }

        // Get user's email
        const userEmail = req.user.email;
        if (!userEmail) {
            return res.json({
                success: true,
                canDeleteAll: false
            });
        }

        // Get allowed emails from config
        const allowedEmails = configService.getAllowedDeleteButtonEmails();
        
        // Check if user's email is in the allowed list
        const canDeleteAll = allowedEmails.includes(userEmail);

        res.json({
            success: true,
            canDeleteAll: canDeleteAll
        });

    } catch (error) {
        console.error('Error checking delete all permission:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to check delete all permission',
            canDeleteAll: false
        });
    }
});

module.exports = router;


