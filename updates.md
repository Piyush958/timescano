# TimeScano Web Dashboard

## Overview

TimeScano is a time tracking and productivity application with a web dashboard that serves as a frontend/reporting portal for a desktop time tracking app. The system consists of a Flask web application that provides user authentication, session management, and data visualization features for tracking productivity metrics, breaks, activities, and screenshots.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend Architecture
- **Flask + Jinja2 Templates**: Server-side rendering with dynamic template generation
- **Bootstrap 5**: Responsive UI framework with dark theme support
- **Font Awesome**: Icon library for enhanced user interface
- **Custom CSS**: Additional styling for screenshots, cards, and responsive design

### Backend Architecture
- **Flask Web Framework**: Python-based web application framework
- **Session-based Authentication**: Server-side session management with role-based access control
- **MongoDB Integration**: NoSQL database for storing user data, sessions, and productivity metrics
- **PyMongo**: MongoDB driver for Python database operations

### Data Storage Solutions
- **MongoDB Atlas**: Cloud-hosted MongoDB instance
- **Database**: `timescano`
- **Collections Structure**:
  - `users`: User accounts with credentials
  - `sessions`: Time tracking sessions with duration metrics
  - `breaks`: Break periods within sessions
  - `activities`: User activity logs during sessions
  - `screenshots`: Base64-encoded screenshots with timestamps

## Key Components

### Authentication System
- **Hash-based Password Storage**: SHA256 password hashing (matching desktop app)
- **Role-based Access Control**: Admin and regular user roles
- **Session Management**: Flask session-based authentication with proper logout

### Dashboard Components
- **Admin Dashboard**: System-wide user management and session overview
- **User Dashboard**: Personal session history and productivity metrics
- **Session Detail View**: Comprehensive view of individual sessions with activities, breaks, and screenshots

### Data Management
- **CRUD Operations**: Create, read, update, delete for sessions and screenshots
- **CSV Export**: Data export functionality for reporting
- **Image Handling**: Base64 screenshot decoding and display

## Data Flow

### User Authentication Flow
1. User submits credentials via login form
2. Password is hashed using SHA256
3. Credentials are validated against MongoDB users collection
4. Session is created with user ID and role information
5. User is redirected to appropriate dashboard based on role

### Session Management Flow
1. Desktop app creates session records in MongoDB
2. Web dashboard queries sessions collection
3. Related data (breaks, activities, screenshots) is fetched via session ID
4. Data is formatted and displayed in responsive tables and cards

### Data Export Flow
1. User requests CSV export
2. System queries user's sessions from MongoDB
3. Data is formatted into CSV structure
4. CSV file is generated and served for download

## External Dependencies

### Database Connection
- **MongoDB Atlas**: `mongodb+srv://timescano_user:timescano_pass_2025@timescano.noernme.mongodb.net/`
- **Database Name**: `timescano`
- **Connection Library**: PyMongo

### Frontend Dependencies
- **Bootstrap 5**: Via CDN for responsive design
- **Font Awesome 6**: Via CDN for icons
- **Custom CSS**: Local stylesheet for additional styling

### Python Dependencies
- **Flask**: Web framework
- **PyMongo**: MongoDB driver
- **Hashlib**: Password hashing
- **CSV**: Data export functionality
- **BSON**: MongoDB ObjectId handling

## Deployment Strategy

### Environment Configuration
- **Session Secret**: Environment variable `SESSION_SECRET` with fallback
- **MongoDB URI**: Environment variable `MONGO_URI` with hardcoded fallback
- **Debug Logging**: Configured for development environment

### File Structure
```
/
├── app.py                 # Main Flask application
├── utils/
│   └── db.py             # Database utilities and connection
├── templates/
│   ├── base.html         # Base template with navigation
│   ├── login.html        # Login page
│   ├── register.html     # User creation page
│   ├── session_detail.html # Session details view
│   ├── admin/
│   │   └── dashboard.html # Admin dashboard
│   └── user/
│       └── dashboard.html # User dashboard
└── static/
    └── style.css         # Custom CSS styles
```

### Security Considerations
- **Password Hashing**: SHA256 for compatibility with desktop app
- **Role-based Access**: Admin/user role separation
- **Session Protection**: Route protection based on authentication status
- **Input Validation**: Form validation and CSRF protection via Flask sessions

### Scalability Approach
- **Database Indexing**: MongoDB collections should be indexed on frequently queried fields
- **Session Management**: Server-side sessions for better security
- **Responsive Design**: Mobile-friendly interface for accessibility
- **Error Handling**: Comprehensive error handling and logging system