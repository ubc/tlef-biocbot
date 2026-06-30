/**
 * Shibboleth SSO Routes
 *
 * These routes are specifically designed to match the paths expected by the
 * Shibboleth Identity Provider (IdP) as defined in the metadata.xml file.
 * This router should be mounted at the root of the Express application.
 */
const express = require('express');
const passport = require('passport');
const router = express.Router();

// Middleware to parse urlencoded bodies, which is common for SAML POST callbacks
router.use(express.urlencoded({ extended: false }));

/**
 * GET /Shibboleth.sso/Login
 *
 * Initiates the Shibboleth authentication flow.
 * This is the endpoint the application should redirect users to for login.
 * It corresponds to the RequestInitiator Location in the metadata.
 */
router.get('/Shibboleth.sso/Login', (req, res, next) => {
    console.log('[SHIBBOLETH DEBUG] Initiating Shibboleth login at /Shibboleth.sso/Login');

    // Check for Shibboleth strategy before attempting to use it
    try {
        passport.authenticate('ubcshib', {
            failureRedirect: '/login?error=ubcshib_failed'
        })(req, res, next);
    } catch (error) {
        console.error('❌ UBC Shibboleth strategy not registered:', error.message);
        return res.status(503).json({
            success: false,
            error: 'UBC Shibboleth authentication is not available or misconfigured.'
        });
    }
});

/**
 * POST /Shibboleth.sso/SAML2/POST
 *
 * This is the SAML Assertion Consumer Service (ACS) endpoint.
 * The IdP will redirect the user's browser to this URL with a POST request
 * containing the SAML assertion after a successful login.
 */
const samlCallbackHandlers = [
    (req, res, next) => {
        console.log(`[SHIBBOLETH DEBUG] Received SAML callback at ${req.path}`);
        console.log('[SHIBBOLETH DEBUG] Request body:', req.body);
        next();
    },
    passport.authenticate('ubcshib', {
        failureRedirect: '/login?error=ubcshib_failed',
        session: true
    }),
    (req, res) => {
        // This is the success callback after passport processes the assertion.
        console.log('[SHIBBOLETH DEBUG] SAML authentication successful. User:', req.user.userId);

        // Save user details to the session for compatibility with the rest of the app.
        if (req.user) {
            req.session.userId = req.user.userId;
            req.session.userRole = req.user.role;
            req.session.userDisplayName = req.user.displayName;
        }

        // Determine the redirect path based on the user's role.
        let redirectPath = '/';
        if (req.user && req.user.role) {
            if (req.user.role === 'instructor') {
                redirectPath = '/instructor/home';
            } else if (req.user.role === 'student') {
                redirectPath = '/student';
            } else if (req.user.role === 'ta') {
                redirectPath = '/ta';
            }
        }

        console.log(`[SHIBBOLETH DEBUG] Redirecting user to ${redirectPath}`);
        res.redirect(redirectPath);
    }
];

router.post('/Shibboleth.sso/SAML2/POST', ...samlCallbackHandlers);

const localSamlAliasesEnabled = process.env.ENABLE_LOCAL_SAML_ALIASES === 'true';
if (localSamlAliasesEnabled) {
    router.post('/auth/saml/callback', ...samlCallbackHandlers);
}

/**
 * Single Logout Service (SLO) placeholders.
 * These are required by the metadata but may not be used in the current flow.
 * We'll log any requests to see if the IdP attempts to use them.
 */
const logSLORequest = (req, res) => {
    console.log(`[SHIBBOLETH DEBUG] Received Single Logout (SLO) request at ${req.path}`);
    console.log('[SHIBBOLETH DEBUG] This endpoint is not fully implemented.');
    // In a real implementation, you would clear the user's session here.
    res.redirect('/login?logout=slo_success');
};

router.get('/Shibboleth.sso/SLO/Redirect', logSLORequest);
router.post('/Shibboleth.sso/SLO/POST', logSLORequest);
router.post('/Shibboleth.sso/SLO/Artifact', logSLORequest);

if (localSamlAliasesEnabled) {
    router.get('/auth/logout', logSLORequest);
    router.post('/auth/logout', logSLORequest);
}

module.exports = router;
