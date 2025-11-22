require('dotenv').config();
const express = require('express');
const path = require('path');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const cors = require('cors');

const { MongoClient } = require('mongodb');
const coursesRoutes = require('./routes/courses');
const flagsRoutes = require('./routes/flags');
const lecturesRoutes = require('./routes/lectures');
const modeQuestionsRoutes = require('./routes/mode-questions');
const chatRoutes = require('./routes/chat');
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
const LLMService = require('./services/llm');
const AuthService = require('./services/authService');
const createAuthMiddleware = require('./middleware/auth');
const initializePassport = require('./config/passport');

const app = express();
const port = process.env.TLEF_BIOCBOT_PORT || 8080;

// Configure CORS to allow requests from localhost:3002 (browser-sync proxy)
app.use(cors({
    origin: ['http://localhost:3000', 'http://localhost:3002', 'http://localhost:8085'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Cookie']
}));

// Serve static files from the public directory
app.use(express.static(path.join(__dirname, '../public')));

// Shibboleth routes will be mounted after session and Passport are configured
// This ensures session support is available for Passport authentication

// Service connections
let db;
let mongoClient; // Store MongoDB client for session store
let llmService;
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
        llmService = await LLMService.create();
        app.locals.llm = llmService;
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
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

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

// Serve static files from the 'public' directory
app.use(express.static(path.join(__dirname, '../public')));

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
        const qdrantService = new QdrantService();

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
            if (db) {
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

            // If no completed course, show onboarding
            res.sendFile(path.join(__dirname, '../public/instructor/onboarding.html'));

        } catch (error) {
            console.error('Error checking onboarding status:', error);
            // If there's an error, show onboarding
            res.sendFile(path.join(__dirname, '../public/instructor/onboarding.html'));
        }
    });

    app.get('/instructor/settings', authMiddleware.requireInstructorOrTA, (req, res) => {
        res.sendFile(path.join(__dirname, '../public/instructor/settings.html'));
    });

    app.get('/instructor/home', authMiddleware.requireInstructorOrTA, (req, res) => {
        res.sendFile(path.join(__dirname, '../public/instructor/home.html'));
    });

    app.get('/instructor/documents', authMiddleware.requireInstructorOrTA, authMiddleware.requireTAPermission('courses'), (req, res) => {
        res.sendFile(path.join(__dirname, '../public/instructor/index.html'));
    });

    app.get('/instructor/flagged', authMiddleware.requireInstructorOrTA, authMiddleware.requireTAPermission('flags'), (req, res) => {
        res.sendFile(path.join(__dirname, '../public/instructor/flagged.html'));
    });

    app.get('/instructor/downloads', authMiddleware.requireInstructorOrTA, (req, res) => {
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
            const qdrantService = new QdrantService();
            await qdrantService.initialize();
            healthStatus.services.qdrant = { status: 'healthy', message: 'Connected' };
        } catch (error) {
            healthStatus.services.qdrant = { status: 'error', message: error.message };
        }

        // Test LLM connection
        try {
            const llmService = require('./services/llm');
            const isConnected = await llmService.testConnection();
            healthStatus.services.llm = {
                status: isConnected ? 'healthy' : 'error',
                message: isConnected ? 'Connected' : 'Connection failed',
                provider: llmService.getProviderName()
            };
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

    // Public course endpoints (no auth required)
    app.get('/api/courses/available/all', async (req, res) => {
        try {
            // Get database instance from app.locals
            const db = req.app.locals.db;
            if (!db) {
                return res.status(503).json({
                    success: false,
                    message: 'Database connection not available'
                });
            }

            // Query database for all active courses
            const collection = db.collection('courses');
            const courses = await collection.find({ status: { $ne: 'deleted' } }).toArray();

            // Transform the data to match expected format for both sides
            const transformedCourses = courses.map(course => ({
                courseId: course.courseId,
                courseName: course.courseName || course.courseId,
                instructorId: course.instructorId,
                status: course.status || 'active',
                createdAt: course.createdAt?.toISOString() || new Date().toISOString()
            }));

            console.log(`Retrieved ${transformedCourses.length} available courses`);

            res.json({
                success: true,
                data: transformedCourses
            });

        } catch (error) {
            console.error('Error fetching available courses:', error);
            res.status(500).json({
                success: false,
                message: 'Internal server error while fetching available courses'
            });
        }
    });

    // API endpoints (protected)
    app.use('/api/courses', authMiddleware.requireAuth, coursesRoutes);
    app.use('/api/flags', authMiddleware.requireAuth, authMiddleware.populateUser, authMiddleware.requireStudentEnrolled, flagsRoutes);
    app.use('/api/lectures', authMiddleware.requireAuth, lecturesRoutes);
    app.use('/api/mode-questions', authMiddleware.requireAuth, modeQuestionsRoutes);
    app.use('/api/learning-objectives', authMiddleware.requireAuth, learningObjectivesRoutes);
    app.use('/api/documents', authMiddleware.requireAuth, documentsRoutes);
    app.use('/api/questions', authMiddleware.requireAuth, questionsRoutes);
    app.use('/api/onboarding', authMiddleware.requireAuth, onboardingRoutes);
    app.use('/api/qdrant', authMiddleware.requireAuth, qdrantRoutes);
    app.use('/api/chat', authMiddleware.requireAuth, authMiddleware.populateUser, authMiddleware.requireStudentEnrolled, chatRoutes);
    app.use('/api/students', authMiddleware.requireAuth, authMiddleware.populateUser, authMiddleware.requireStudentEnrolled, studentsRoutes);
    app.use('/api/user-agreement', authMiddleware.requireAuth, userAgreementRoutes);
    app.use('/api/settings', authMiddleware.requireAuth, authMiddleware.populateUser, settingsRoutes);
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
