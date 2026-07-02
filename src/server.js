require('dotenv').config();
const express = require('express');
const path = require('path');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const cors = require('cors');

const { MongoClient } = require('mongodb');
const { ensureCourseCodes } = require('./models/Course');
const { ensureSuperchatsFromLegacy } = require('./models/Superchat');
const { ensureIndexes: ensureMessageFeedbackIndexes } = require('./models/MessageFeedback');
const { ensureIndexes: ensureChatSurveyResponseIndexes } = require('./models/ChatSurveyResponse');
const coursesRoutes = require('./routes/courses');
const flagsRoutes = require('./routes/flags');
const lecturesRoutes = require('./routes/lectures');

const chatRoutes = require('./routes/chat');
const instructorChatRoutes = require('./routes/instructorChat');
const studentSuperCourseRoutes = require('./routes/studentSuperCourse');
const authRoutes = require('./routes/auth');
const shibbolethRoutes = require('./routes/shibboleth');

const learningObjectivesRoutes = require('./routes/learning-objectives');
const documentsRoutes = require('./routes/documents');
const questionsRoutes = require('./routes/questions');
const onboardingRoutes = require('./routes/onboarding');
const qdrantRoutes = require('./routes/qdrant');
const studentsRoutes = require('./routes/students');
const userAgreementRoutes = require('./routes/user-agreement');
const settingsRoutes = require('./routes/settings');
const quizRoutes = require('./routes/quiz');
const studentTrackerRoutes = require('./routes/student-tracker');
const struggleActivityRoutes = require('./routes/struggle-activity');
const mentalHealthFlagsRoutes = require('./routes/mentalHealthFlags');
const superChatNotesRoutes = require('./routes/superChatNotes');
const superchatsRoutes = require('./routes/superchats');
const academicSyncRoutes = require('./routes/academicSync');
const LLMService = require('./services/llm');
const LlmRegistry = require('./services/llmRegistry');
const AuthService = require('./services/authService');
const { isAcademicApiEnabled } = require('./services/academicApi');
const createAuthMiddleware = require('./middleware/auth');
const initializePassport = require('./config/passport');

const app = express();
const port = process.env.TLEF_BIOCBOT_PORT || 8080;

// Configure CORS to allow requests from localhost:3002 (browser-sync proxy)
app.use(cors({
    origin: ['http://localhost:3000', 'http://localhost:3002', 'http://localhost:8050'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Cookie']
}));

// Serve shared static files publicly
app.use('/assets', express.static(path.join(__dirname, '../public/assets')));
app.use('/styles', express.static(path.join(__dirname, '../public/styles')));
app.use('/common', express.static(path.join(__dirname, '../public/common')));


// Shibboleth routes will be mounted after session and Passport are configured
// This ensures session support is available for Passport authentication

// Service connections
let db;
let mongoClient; // Store MongoDB client for session store
let llmService;
let llmRegistry;
let authService;
let authMiddleware;
let passport;

/**
 * Initialize the LLM service
 * @returns {Promise<void>}
 */
async function initializeLLM() {
    try {
        console.log('🤖 Starting LLM service initialization...');
        llmRegistry = new LlmRegistry();
        app.locals.llmRegistry = llmRegistry;

        const provider = (process.env.LLM_PROVIDER || '').toLowerCase();
        const canUseGlobalOpenAiKey = provider === 'openai' && !!process.env.OPENAI_API_KEY;
        const shouldInitGlobalLlm =
            process.env.BIOCBOT_TEST_LLM_STUB === '1' ||
            provider === 'ollama' ||
            provider === 'ubc-llm-sandbox' ||
            canUseGlobalOpenAiKey;

        if (shouldInitGlobalLlm) {
            llmService = await LLMService.create();
            // Allow the LLM service to look up the active model/reasoning settings
            // from the global settings collection on demand.
            if (typeof llmService.setDbAccessor === 'function') {
                llmService.setDbAccessor(() => app.locals.db);
            }
            app.locals.llm = llmService;
        } else {
            console.log('ℹ️ Global LLM service skipped; scoped per-surface OpenAI keys will be used.');
            app.locals.llm = null;
        }
    } catch (error) {
        console.error('❌ Failed to initialize LLM service:', error.message);
        throw error;
    }
}

/**
 * Verify session middleware configuration
 * Session middleware is already configured early with MongoDB store using clientPromise
 * This function just confirms MongoDB connection is ready
 * @returns {void}
 */
function configureSession() {
    console.log('🔐 Verifying session middleware configuration...');
    console.log('✅ Session middleware is configured with MongoDB store');
    console.log('   MongoDB client promise will resolve when connection is established');
}

/**
 * Initialize Passport authentication
 * Must be called after session middleware is configured
 * @returns {Promise<void>}
 */
async function initializePassportAuth() {
    try {
        console.log('🔐 Starting Passport initialization...');

        // Initialize Passport with database connection
        passport = initializePassport(db);

        // Initialize Passport middleware (must be after session middleware)
        app.use(passport.initialize());
        app.use(passport.session());

        // Make passport available to routes
        app.locals.passport = passport;

        console.log('✅ Passport initialized successfully');

    } catch (error) {
        console.error('❌ Failed to initialize Passport:', error.message);
        throw error;
    }
}

/**
 * Initialize the authentication service
 * @returns {Promise<void>}
 */
async function initializeAuth() {
    try {
        console.log('🔐 Starting authentication service initialization...');
        authService = new AuthService(db);
        authMiddleware = createAuthMiddleware(db);

        // Make auth service available to routes
        app.locals.authService = authService;

        // Initialize default users for development
        const initResult = await authService.initializeDefaultUsers();
        if (initResult.success) {
            console.log('✅ Default users initialized');
        } else {
            console.log('ℹ️ Default users already exist or failed to initialize');
        }

    } catch (error) {
        console.error('❌ Failed to initialize authentication service:', error.message);
        throw error;
    }
}

/**
 * Connect to MongoDB using the connection string from environment variables
 * @returns {Promise<void>}
 */
async function connectToMongoDB() {
    try {
        const mongoUri = process.env.MONGO_URI;
        if (!mongoUri) {
            throw new Error('MONGO_URI environment variable is not set');
        }

        const client = new MongoClient(mongoUri);
        await client.connect();

        // Store the client for session store
        mongoClient = client;

        // Resolve the MongoDB client promise for session store
        if (global._resolveMongoClient) {
            global._resolveMongoClient(client);
            delete global._resolveMongoClient;
        }

        // Get the database instance
        db = client.db();

        console.log('✅ Successfully connected to MongoDB');

        // Make the database available to routes
        app.locals.db = db;

        // Test the connection by listing collections
        const collections = await db.listCollections().toArray();
        console.log(`📚 Available collections: ${collections.map(c => c.name).join(', ') || 'None'}`);

    } catch (error) {
        console.error('❌ Failed to connect to MongoDB:', error.message);
        process.exit(1);
    }
}



// Middleware for parsing request bodies
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Create a promise that will resolve to the MongoDB client
// This allows us to configure session middleware early with MongoDB store
let mongoClientPromise = new Promise((resolve) => {
    // This will be resolved when MongoDB connects
    global._resolveMongoClient = resolve;
});

// Configure session middleware early (before MongoDB connection)
// Using clientPromise allows MongoDB store to work once client is connected
app.use(session({
    secret: process.env.SESSION_SECRET || 'biocbot-session-secret-change-in-production',
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
        clientPromise: mongoClientPromise, // Will resolve when MongoDB connects
        dbName: process.env.MONGO_DB_NAME, // Optional: specify database name
        collectionName: 'sessions',
        ttl: 24 * 60 * 60, // 24 hours
        touchAfter: 24 * 3600
    }),
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    },
    name: 'biocbot.sid'
}));



// Home page route - redirect to login
app.get('/', (req, res) => {
    res.redirect('/login');
});

// Login page
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, '../public/index.html'));
});

// Quick Qdrant test endpoint
app.get('/test-qdrant', async (req, res) => {
    try {
        const QdrantService = require('./services/qdrantService');
        const qdrantService = new QdrantService({ skipEmbeddings: true });

        console.log('🧪 Testing Qdrant connection...');
        await qdrantService.initialize();

        const stats = await qdrantService.getCollectionStats();

        res.json({
            success: true,
            message: 'Qdrant connection successful!',
            collection: stats
        });

    } catch (error) {
        console.error('❌ Qdrant test failed:', error);
        res.status(500).json({
            success: false,
            message: 'Qdrant test failed',
            error: error.message
        });
    }
});

/**
 * Set up protected routes after authentication middleware is initialized
 */
function setupProtectedRoutes() {
    const redirectTATo = (targetPath) => (req, res, next) => {
        if (req.user && req.user.role === 'ta') {
            return res.redirect(targetPath);
        }
        next();
    };

    app.get('/instructor/downloads.html', authMiddleware.requireInstructorOrTA, redirectTATo('/ta'), authMiddleware.requireSystemAdmin, (req, res) => {
        res.sendFile(path.join(__dirname, '../public/instructor/downloads.html'));
    });

    // Must be declared before the /instructor static mount, which would
    // otherwise serve student-hub.html to TAs (the mount only requires
    // instructor OR TA, not instructor exclusively).
    app.get('/instructor/student-hub.html', authMiddleware.requireInstructor, (req, res) => {
        res.sendFile(path.join(__dirname, '../public/instructor/student-hub.html'));
    });

    app.get('/instructor/chat.html', authMiddleware.requireInstructor, (req, res) => {
        res.sendFile(path.join(__dirname, '../public/instructor/chat.html'));
    });

    // Protected static files
    app.use('/student', authMiddleware.requireStudent, express.static(path.join(__dirname, '../public/student')));
    app.use('/instructor', authMiddleware.requireInstructorOrTA, express.static(path.join(__dirname, '../public/instructor')));
    app.use('/ta', authMiddleware.requireTA, express.static(path.join(__dirname, '../public/ta')));

    // Qdrant test page (protected)
    app.get('/qdrant-test', authMiddleware.requireAuth, (req, res) => {
        res.sendFile(path.join(__dirname, '../public/qdrant-test.html'));
    });

    // Student routes (protected)
    app.get('/student', authMiddleware.requireStudent, (req, res) => {
        res.sendFile(path.join(__dirname, '../public/student/index.html'));
    });

    app.get('/student/history', authMiddleware.requireStudent, (req, res) => {
        res.sendFile(path.join(__dirname, '../public/student/history.html'));
    });

    // Student flagged content page
    app.get('/student/flagged', authMiddleware.requireStudent, (req, res) => {
        res.sendFile(path.join(__dirname, '../public/student/flagged.html'));
    });

    // Student quiz practice page
    app.get('/student/quiz', authMiddleware.requireStudent, (req, res) => {
        res.sendFile(path.join(__dirname, '../public/student/quiz.html'));
    });

    // Student Super Course chat page
    app.get('/student/super-course', authMiddleware.requireStudent, (req, res) => {
        res.sendFile(path.join(__dirname, '../public/student/super-course.html'));
    });

    // TA routes (protected)
    app.get('/ta', authMiddleware.requireTA, (req, res) => {
        res.sendFile(path.join(__dirname, '../public/ta/home.html'));
    });

    app.get('/ta/onboarding', authMiddleware.requireTA, (req, res) => {
        res.sendFile(path.join(__dirname, '../public/ta/onboarding.html'));
    });

    // TA course management - redirect to instructor course page
    app.get('/ta/courses', authMiddleware.requireTA, (req, res) => {
        res.redirect('/instructor/documents');
    });

    // TA student support - redirect to instructor flags page
    app.get('/ta/students', authMiddleware.requireTA, (req, res) => {
        res.redirect('/instructor/flagged');
    });

    // TA settings - serve dedicated TA settings page
    app.get('/ta/settings', authMiddleware.requireTA, (req, res) => {
        res.sendFile(path.join(__dirname, '../public/ta/settings.html'));
    });

    // Instructor routes (protected - instructors and TAs can access)
    app.get('/instructor', authMiddleware.requireInstructorOrTA, (req, res) => {
        // Serve the documents page directly
        res.sendFile(path.join(__dirname, '../public/instructor/index.html'));
    });

    // Also handle /instructor/ (with trailing slash)
    app.get('/instructor/', authMiddleware.requireInstructorOrTA, (req, res) => {
        // Serve the documents page directly
        res.sendFile(path.join(__dirname, '../public/instructor/index.html'));
    });

    // Check if user can access onboarding (not completed)
    app.get('/instructor/onboarding', authMiddleware.requireInstructor, async (req, res) => {
        try {
            const instructorId = req.user.userId; // Get from authenticated user

            // Check if instructor has completed onboarding
            const db = req.app.locals.db;

            // "Set up another section" deliberately re-enters onboarding to create
            // a new course, so skip the completed-course redirect in that case —
            // but only when the academic API is on. With it off (the default),
            // restore the pre-feature behavior: a completed instructor is always
            // redirected away and can't re-enter onboarding to add a course.
            const addingCourse = req.query.addCourse && await isAcademicApiEnabled(db);
            if (db && !addingCourse) {
                const collection = db.collection('courses');
                const existingCourse = await collection.findOne({
                    instructorId,
                    isOnboardingComplete: true
                });

                if (existingCourse) {
                    // Redirect to course upload page if onboarding is complete
                    return res.redirect(`/instructor/documents?courseId=${existingCourse.courseId}`);
                }
            }

            // If no completed course (or explicitly adding another), show onboarding
            res.sendFile(path.join(__dirname, '../public/instructor/onboarding.html'));

        } catch (error) {
            console.error('Error checking onboarding status:', error);
            // If there's an error, show onboarding
            res.sendFile(path.join(__dirname, '../public/instructor/onboarding.html'));
        }
    });

    app.get('/instructor/settings', authMiddleware.requireInstructorOrTA, redirectTATo('/ta/settings'), (req, res) => {
        res.sendFile(path.join(__dirname, '../public/instructor/settings.html'));
    });

    app.get('/instructor/home', authMiddleware.requireInstructorOrTA, redirectTATo('/ta'), (req, res) => {
        res.sendFile(path.join(__dirname, '../public/instructor/home.html'));
    });

    app.get('/instructor/chat', authMiddleware.requireInstructor, (req, res) => {
        res.sendFile(path.join(__dirname, '../public/instructor/chat.html'));
    });

    // Super Chat Notes — shared instructor knowledge layer
    app.get('/instructor/notes', authMiddleware.requireInstructor, (req, res) => {
        res.sendFile(path.join(__dirname, '../public/instructor/notes.html'));
    });

    app.get('/instructor/documents', authMiddleware.requireInstructorOrTA, authMiddleware.requireTAPermission('courses'), (req, res) => {
        res.sendFile(path.join(__dirname, '../public/instructor/index.html'));
    });

    app.get('/instructor/flagged', authMiddleware.requireInstructorOrTA, authMiddleware.requireTAPermission('flags'), (req, res) => {
        res.sendFile(path.join(__dirname, '../public/instructor/flagged.html'));
    });

    app.get('/instructor/downloads', authMiddleware.requireInstructorOrTA, redirectTATo('/ta'), authMiddleware.requireSystemAdmin, (req, res) => {
        res.sendFile(path.join(__dirname, '../public/instructor/downloads.html'));
    });

    app.get('/instructor/ta-hub', authMiddleware.requireInstructorOrTA, (req, res) => {
        res.sendFile(path.join(__dirname, '../public/instructor/ta-hub.html'));
    });

    app.get('/instructor/student-hub', authMiddleware.requireInstructor, (req, res) => {
        res.sendFile(path.join(__dirname, '../public/instructor/student-hub.html'));
    });
}

// Legacy routes (redirect to new structure)
app.get('/settings', (req, res) => {
    res.redirect('/student');
});

// Health check endpoint to verify all services
app.get('/api/health', async (req, res) => {
    const healthStatus = {
        status: 'checking',
        timestamp: new Date().toISOString(),
        services: {},
        environment: {
            NODE_ENV: process.env.NODE_ENV,
            LLM_PROVIDER: process.env.LLM_PROVIDER,
            QDRANT_URL: process.env.QDRANT_URL ? 'SET' : 'NOT SET',
            OLLAMA_ENDPOINT: process.env.OLLAMA_ENDPOINT ? 'SET' : 'NOT SET'
        }
    };

    try {
        // Test MongoDB connection
        if (!db) {
            healthStatus.services.mongodb = { status: 'error', message: 'Database not connected' };
        } else {
            try {
                await db.admin().ping();
                healthStatus.services.mongodb = { status: 'healthy', message: 'Connected' };
            } catch (error) {
                healthStatus.services.mongodb = { status: 'error', message: error.message };
            }
        }

        // Test configuration loading
        try {
            const config = require('./services/config');
            const llmConfig = config.getLLMConfig();
            const vectorConfig = config.getVectorDBConfig();
            healthStatus.services.config = {
                status: 'healthy',
                message: 'Configuration loaded successfully',
                llmProvider: llmConfig.provider,
                vectorHost: vectorConfig.host,
                vectorPort: vectorConfig.port
            };
        } catch (error) {
            healthStatus.services.config = { status: 'error', message: error.message };
        }

        // Test Qdrant connection
        try {
            const QdrantService = require('./services/qdrantService');
            const qdrantService = new QdrantService({ skipEmbeddings: true });
            await qdrantService.initialize();
            healthStatus.services.qdrant = { status: 'healthy', message: 'Connected' };
        } catch (error) {
            healthStatus.services.qdrant = { status: 'error', message: error.message };
        }

        // Test LLM connection
        try {
            if (app.locals.llm) {
                const isConnected = await app.locals.llm.testConnection();
                healthStatus.services.llm = {
                    status: isConnected ? 'healthy' : 'error',
                    message: isConnected ? 'Connected' : 'Connection failed',
                    provider: app.locals.llm.getProviderName()
                };
            } else if (app.locals.llmRegistry) {
                healthStatus.services.llm = {
                    status: 'healthy',
                    message: 'Scoped per-surface LLM registry is initialized',
                    provider: process.env.LLM_PROVIDER || 'unknown'
                };
            } else {
                healthStatus.services.llm = { status: 'error', message: 'LLM registry is not initialized' };
            }
        } catch (error) {
            healthStatus.services.llm = { status: 'error', message: error.message };
        }

        // Determine overall status
        const allHealthy = Object.values(healthStatus.services).every(service => service.status === 'healthy');
        healthStatus.status = allHealthy ? 'healthy' : 'degraded';
        healthStatus.message = allHealthy ? 'All services are running' : 'Some services are not available';

        const statusCode = allHealthy ? 200 : 503;
        res.status(statusCode).json(healthStatus);

    } catch (error) {
        healthStatus.status = 'error';
        healthStatus.message = 'Health check failed';
        healthStatus.error = error.message;
        res.status(503).json(healthStatus);
    }
});

/**
 * Set up API routes after authentication middleware is initialized
 */
function setupAPIRoutes() {
    // Authentication routes (no auth required for most, but some need user population)
    app.use('/api/auth', authMiddleware.populateUser, authRoutes);

    // API endpoints (protected)
    app.use('/api/courses', authMiddleware.requireAuth, authMiddleware.requireActiveCourseForNonInstructors, coursesRoutes);
    app.use('/api/flags', authMiddleware.requireAuth, authMiddleware.populateUser, authMiddleware.requireActiveCourseForNonInstructors, flagsRoutes);
    app.use('/api/lectures', authMiddleware.requireAuth, authMiddleware.requireActiveCourseForNonInstructors, lecturesRoutes);

    app.use('/api/learning-objectives', authMiddleware.requireAuth, authMiddleware.requireActiveCourseForNonInstructors, learningObjectivesRoutes);
    app.use('/api/documents', authMiddleware.requireAuth, authMiddleware.requireActiveCourseForNonInstructors, documentsRoutes);
    app.use('/api/questions', authMiddleware.requireAuth, authMiddleware.requireActiveCourseForNonInstructors, questionsRoutes);
    app.use('/api/onboarding', authMiddleware.requireAuth, onboardingRoutes);
    app.use('/api/qdrant', authMiddleware.requireAuth, qdrantRoutes);
    app.use('/api/chat', authMiddleware.requireAuth, authMiddleware.populateUser, authMiddleware.requireActiveCourseForNonInstructors, authMiddleware.requireStudentEnrolled, chatRoutes);
    app.use('/api/instructor/chat', authMiddleware.requireAuth, authMiddleware.populateUser, authMiddleware.requireInstructor, instructorChatRoutes);
    app.use('/api/superchat-notes', authMiddleware.requireAuth, authMiddleware.populateUser, authMiddleware.requireInstructor, superChatNotesRoutes);
    app.use('/api/superchats', authMiddleware.requireAuth, authMiddleware.populateUser, superchatsRoutes);
    app.use('/api/academic-sync', authMiddleware.requireAuth, authMiddleware.populateUser, authMiddleware.requireInstructor, academicSyncRoutes);
    app.use('/api/student/super-course', authMiddleware.requireAuth, authMiddleware.populateUser, studentSuperCourseRoutes);
    app.use('/api/students', authMiddleware.requireAuth, authMiddleware.populateUser, authMiddleware.requireActiveCourseForNonInstructors, authMiddleware.requireStudentEnrolled, studentsRoutes);
    app.use('/api/user-agreement', authMiddleware.requireAuth, userAgreementRoutes);
    app.use('/api/settings', authMiddleware.requireAuth, authMiddleware.populateUser, authMiddleware.requireActiveCourseForNonInstructors, settingsRoutes);
    app.use('/api/student/struggle', authMiddleware.requireAuth, authMiddleware.populateUser, studentTrackerRoutes);
    app.use('/api/struggle-activity', authMiddleware.requireAuth, authMiddleware.requireActiveCourseForNonInstructors, struggleActivityRoutes);
    app.use('/api/quiz', authMiddleware.requireAuth, authMiddleware.populateUser, authMiddleware.requireActiveCourseForNonInstructors, authMiddleware.requireStudentEnrolled, quizRoutes);
    app.use('/api/mental-health-flags', authMiddleware.requireAuth, authMiddleware.populateUser, authMiddleware.requireActiveCourseForNonInstructors, mentalHealthFlagsRoutes);

    // Test-only routes for scripting the LLM stub. Gated by BIOCBOT_TEST_LLM_STUB
    // so they are unreachable in production runs (no flag = no router mounted).
    if (process.env.BIOCBOT_TEST_LLM_STUB === '1') {
        const testLlmStubRoutes = require('./routes/testLlmStub');
        app.use('/api/test/llm-stub', testLlmStubRoutes);
        console.log('🧪 Test LLM stub routes mounted at /api/test/llm-stub');
    }
}

// Initialize the application
async function startServer() {
    try {
        console.log('🚀 Starting BiocBot server...');

        // Session middleware is already configured early (before MongoDB connection)
        // It uses clientPromise which will resolve when MongoDB connects
        
        // Initialize core services in correct order
        await connectToMongoDB(); // Resolves the MongoDB client promise for session store
        
        // Verify session configuration
        configureSession();
        
        // Initialize Passport (requires session middleware - already configured)
        await initializePassportAuth();
        
        // Mount Shibboleth routes AFTER session and Passport are configured
        // These routes use Passport authentication and require session support
        app.use('/', shibbolethRoutes);
        
        // Initialize other services
        await initializeLLM();
        await initializeAuth();

        // Run migrations
        await ensureCourseCodes(db);
        await ensureSuperchatsFromLegacy(db);
        await ensureMessageFeedbackIndexes(db);
        await ensureChatSurveyResponseIndexes(db);

        // Set up routes after authentication is initialized
        setupProtectedRoutes();
        setupAPIRoutes();

        // Start the Express server
        app.listen(port, () => {
            console.log('\n✨ All services initialized successfully!');
            console.log(`🌐 Server is running on http://localhost:${port}`);
            console.log(`👨‍🎓 Student interface: http://localhost:${port}/student`);
            console.log(`👨‍🏫 Instructor interface: http://localhost:${port}/instructor`);
            console.log(`🔍 Health check: http://localhost:${port}/api/health`);
        });

    } catch (error) {
        console.error('❌ Failed to start server:', error.message);
        process.exit(1);
    }
}

// Start the server
startServer();
