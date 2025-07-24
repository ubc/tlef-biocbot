require('dotenv').config();
const express = require('express');
const path = require('path');
const exampleRoutes = require('./routes/example/hello');
const coursesRoutes = require('./routes/courses');

const app = express();
const port = process.env.TLEF_BIOCBOT_PORT || 8080;

// Serve static files from the 'public' directory
app.use(express.static(path.join(__dirname, '../public')));

// Home page route now shows role selection
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../public/index.html'));
});

// Student routes
app.get('/student', (req, res) => {
    res.sendFile(path.join(__dirname, '../public/student/index.html'));
});

app.get('/student/history', (req, res) => {
    res.sendFile(path.join(__dirname, '../public/student/history.html'));
});

app.get('/student/settings', (req, res) => {
    res.sendFile(path.join(__dirname, '../public/student/settings.html'));
});

// Instructor routes
app.get('/instructor', (req, res) => {
    res.sendFile(path.join(__dirname, '../public/instructor/index.html'));
});

app.get('/instructor/settings', (req, res) => {
    res.sendFile(path.join(__dirname, '../public/instructor/settings.html'));
});

app.get('/instructor/onboarding', (req, res) => {
    res.sendFile(path.join(__dirname, '../public/instructor/onboarding.html'));
});

app.get('/instructor/home', (req, res) => {
    res.sendFile(path.join(__dirname, '../public/instructor/home.html'));
});

// Legacy routes (redirect to new structure)
app.get('/settings', (req, res) => {
    res.redirect('/student/settings');
});

app.get('/documents', (req, res) => {
    res.redirect('/instructor');
});

// API endpoints
app.use('/api/example', exampleRoutes);
app.use('/api/courses', coursesRoutes);

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
  console.log(`Student interface: http://localhost:${port}/student`);
  console.log(`Instructor interface: http://localhost:${port}/instructor`);
});
