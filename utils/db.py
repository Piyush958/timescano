import os
from pymongo import MongoClient
from datetime import datetime, timezone
from bson import ObjectId
import hashlib
import logging

# MongoDB connection
MONGO_URI = "mongodb+srv://timescano_user:timescano_pass_2025@timescano.noernme.mongodb.net/?retryWrites=true&w=majority&appName=timescano"
DB_NAME = "timescano"

# Suppress pymongo DEBUG logs
logging.getLogger('pymongo').setLevel(logging.WARNING)
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

client = MongoClient(MONGO_URI)
db = client[DB_NAME]

# Collections
organizations_col = db["organizations"]
users_col = db["users"]
sessions_col = db["sessions"]
breaks_col = db["breaks"]
activities_col = db["activities"]
screenshots_col = db["screenshots"]
recordings_col = db["recordings"]

# Drop existing indexes if they exist to avoid conflicts
try:
    users_col.drop_index("organization_id_1_email_1")
except:
    pass
try:
    users_col.drop_index("organization_id_1_username_1")
except:
    pass

# Create indexes for performance
organizations_col.create_index([("name", 1)])
users_col.create_index([("organization_id", 1), ("email", 1)], unique=True, sparse=True)
users_col.create_index([("organization_id", 1), ("username", 1)], unique=True, sparse=True)
sessions_col.create_index([("user_id", 1), ("start_time", 1), ("organization_id", 1)])
breaks_col.create_index([("session_id", 1), ("organization_id", 1)])
activities_col.create_index([("session_id", 1), ("organization_id", 1)])
screenshots_col.create_index([("session_id", 1), ("timestamp", 1), ("organization_id", 1)])
recordings_col.create_index([("session_id", 1), ("timestamp", 1), ("organization_id", 1)])

# Hash password using SHA256
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Authenticate user credentials
def authenticate_user(email, password):
    try:
        user = users_col.find_one({
            "email": email,
            "password": hash_password(password)
        })
        return str(user["_id"]) if user else None
    except Exception as e:
        logger.error(f"Error authenticating user {email}: {str(e)}")
        return None

# Register new user with role and optional organization_id
def register_user(email, username, password, role="user", organization_id=None):
    try:
        if users_col.find_one({"email": email, "organization_id": organization_id}):
            return False
        if users_col.find_one({"username": username, "organization_id": organization_id}):
            return False
        doc = {
            "email": email,
            "username": username,
            "password": hash_password(password),
            "role": role
        }
        if organization_id:
            doc["organization_id"] = organization_id
        result = users_col.insert_one(doc)
        return str(result.inserted_id)
    except Exception as e:
        logger.error(f"Error registering user {email}: {str(e)}")
        return False

def get_all_users(organization_id):
    """Get all users for an organization (excludes superusers) - for admin/user views"""
    try:
        users = list(users_col.find({
            "organization_id": organization_id,
            "role": {"$ne": "superuser"}  # Exclude superusers completely
        }))
        return users
    except Exception as e:
        logger.error(f"Error getting users for organization {organization_id}: {str(e)}")
        return []

def get_users_by_role(organization_id, requester_role):
    """Get users based on requester's role in hierarchy - NEVER shows superusers"""
    try:
        if requester_role.lower() == "superuser":
            # Superuser sees admins and regular users, but NEVER other superusers
            users = list(users_col.find({
                "organization_id": organization_id,
                "role": {"$in": ["admin", "user"], "$ne": {"$regex": "^superuser$", "$options": "i"}}
            }))
        elif requester_role.lower() == "admin":
            # Admin sees only regular users, NEVER superusers
            users = list(users_col.find({
                "organization_id": organization_id,
                "role": "user"
            }))
        else:
            # Regular users see nobody
            users = []
        return users
    except Exception as e:
        logger.error(f"Error getting users by role for organization {organization_id}: {str(e)}")
        return []

def get_all_users_including_superusers(organization_id):
    """Get all users for an organization (includes superusers for internal use)"""
    try:
        users = list(users_col.find({
            "organization_id": organization_id
        }))
        return users
    except Exception as e:
        logger.error(f"Error getting all users for organization {organization_id}: {str(e)}")
        return []

def get_sessions_by_user(user_id, organization_id):
    """Get sessions for a specific user in an organization"""
    try:
        return list(sessions_col.find({"user_id": user_id, "organization_id": organization_id}).sort("start_time", -1))
    except Exception as e:
        logger.error(f"Error fetching sessions for user {user_id} in organization {organization_id}: {str(e)}")
        return []

def get_all_sessions(organization_id, user_filter=None, date_filter=None, requester_role="admin"):
    """Get sessions based on requester's role in hierarchy"""
    query = {"organization_id": organization_id}

    if user_filter:
        query["user_id"] = user_filter

    if date_filter:
        try:
            date_obj = datetime.fromisoformat(date_filter)
            start_of_day = date_obj.replace(hour=0, minute=0, second=0, microsecond=0)
            end_of_day = date_obj.replace(hour=23, minute=59, second=59, microsecond=999999)
            query["start_time"] = {
                "$gte": start_of_day.isoformat(),
                "$lte": end_of_day.isoformat()
            }
        except Exception as e:
            logger.error(f"Error parsing date filter {date_filter}: {str(e)}")

    try:
        sessions = list(sessions_col.find(query).sort("start_time", -1))
        
        # Filter sessions based on requester's role
        filtered_sessions = []
        for session in sessions:
            user_id = session.get('user_id')
            if user_id:
                try:
                    user = users_col.find_one({"_id": ObjectId(user_id)})
                    if user:
                        user_role = user.get('role')
                        if requester_role == "superuser":
                            if user_role in ["admin", "user"]:
                                filtered_sessions.append(session)
                        elif requester_role == "admin":
                            if user_role == "user":
                                filtered_sessions.append(session)
                except:
                    pass
        return filtered_sessions
    except Exception as e:
        logger.error(f"Error fetching sessions for organization {organization_id}: {str(e)}")
        return []

def get_session_by_id(session_id, organization_id):
    """Get session by ID in an organization"""
    try:
        return sessions_col.find_one({"_id": ObjectId(session_id), "organization_id": organization_id})
    except Exception as e:
        logger.error(f"Error fetching session {session_id} in organization {organization_id}: {str(e)}")
        return None

def get_breaks_by_session(session_id, organization_id):
    """Get breaks for a specific session in an organization"""
    try:
        return list(breaks_col.find({"session_id": session_id, "organization_id": organization_id}).sort("start", 1))
    except Exception as e:
        logger.error(f"Error fetching breaks for session {session_id} in organization {organization_id}: {str(e)}")
        return []

def get_activities_by_session(session_id, organization_id):
    """Get activities for a specific session in an organization"""
    try:
        return list(activities_col.find({"session_id": session_id, "organization_id": organization_id}).sort("time", 1))
    except Exception as e:
        logger.error(f"Error fetching activities for session {session_id} in organization {organization_id}: {str(e)}")
        return []

def get_screenshots_by_session(session_id, organization_id, limit=10, skip=0):
    """Get screenshots for a specific session with pagination in an organization"""
    try:
        return list(screenshots_col.find({"session_id": session_id, "organization_id": organization_id}).sort("timestamp", -1).skip(skip).limit(limit))
    except Exception as e:
        logger.error(f"Error fetching screenshots for session {session_id} in organization {organization_id}: {str(e)}")
        return []

def get_recordings_by_session(session_id, organization_id, limit=10, skip=0):
    """Get recordings for a specific session with pagination in an organization"""
    try:
        return list(recordings_col.find({"session_id": session_id, "organization_id": organization_id}).sort("timestamp", -1).skip(skip).limit(limit))
    except Exception as e:
        logger.error(f"Error fetching recordings for session {session_id} in organization {organization_id}: {str(e)}")
        return []

def delete_session(session_id, organization_id):
    """Delete a session and all related data in an organization"""
    try:
        result = sessions_col.delete_one({"_id": ObjectId(session_id), "organization_id": organization_id})
        if result.deleted_count > 0:
            breaks_col.delete_many({"session_id": session_id, "organization_id": organization_id})
            activities_col.delete_many({"session_id": session_id, "organization_id": organization_id})
            screenshots_col.delete_many({"session_id": session_id, "organization_id": organization_id})
            recordings_col.delete_many({"session_id": session_id, "organization_id": organization_id})
            return True
        return False
    except Exception as e:
        logger.error(f"Error deleting session {session_id} in organization {organization_id}: {str(e)}")
        return False

def delete_screenshot(screenshot_id, organization_id):
    """Delete a screenshot in an organization"""
    try:
        result = screenshots_col.delete_one({"_id": ObjectId(screenshot_id), "organization_id": organization_id})
        return result.deleted_count > 0
    except Exception as e:
        logger.error(f"Error deleting screenshot {screenshot_id} in organization {organization_id}: {str(e)}")
        return False

def save_session(user_id, start_time, organization_id):
    """Save a new session in an organization"""
    try:
        result = sessions_col.insert_one({
            "user_id": user_id,
            "start_time": start_time,
            "end_time": None,
            "elapsed_time": 0,
            "idle_time": 0,
            "organization_id": organization_id
        })
        return str(result.inserted_id)
    except Exception as e:
        logger.error(f"Error saving session for user {user_id} in organization {organization_id}: {str(e)}")
        return None

def end_session(session_id, end_time, elapsed_time, idle_time, organization_id):
    """End a session in an organization"""
    try:
        result = sessions_col.update_one(
            {"_id": ObjectId(session_id), "organization_id": organization_id},
            {"$set": {
                "end_time": end_time,
                "elapsed_time": elapsed_time,
                "idle_time": idle_time
            }}
        )
        return result.modified_count > 0
    except Exception as e:
        logger.error(f"Error ending session {session_id} in organization {organization_id}: {str(e)}")
        return False

def log_break(session_id, start, end, duration, organization_id):
    """Log a break in an organization"""
    try:
        result = breaks_col.insert_one({
            "session_id": session_id,
            "start": start,
            "end": end,
            "duration": duration,
            "organization_id": organization_id
        })
        return str(result.inserted_id)
    except Exception as e:
        logger.error(f"Error logging break for session {session_id} in organization {organization_id}: {str(e)}")
        return None

def log_activity(session_id, time, activity, organization_id):
    """Log an activity in an organization"""
    try:
        result = activities_col.insert_one({
            "session_id": session_id,
            "time": time,
            "activity": activity,
            "organization_id": organization_id
        })
        return str(result.inserted_id)
    except Exception as e:
        logger.error(f"Error logging activity for session {session_id} in organization {organization_id}: {str(e)}")
        return None

def store_screenshot(user_id, session_id, image_base64, organization_id):
    """Store a screenshot in an organization"""
    try:
        result = screenshots_col.insert_one({
            "user_id": user_id,
            "session_id": session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "image_base64": image_base64,
            "organization_id": organization_id
        })
        return str(result.inserted_id)
    except Exception as e:
        logger.error(f"Error storing screenshot: {str(e)}")
        return None

def store_recording_frame(user_id, session_id, base64_frame, organization_id):
    """Store a recording frame in an organization"""
    try:
        result = recordings_col.insert_one({
            "user_id": user_id,
            "session_id": session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "frame_base64": base64_frame,
            "organization_id": organization_id
        })
        return str(result.inserted_id)
    except Exception as e:
        logger.error(f"Error storing recording frame: {str(e)}")
        return None

def get_visible_users_only(organization_id):
    """Get only visible users (admins and regular users) - NEVER includes superusers"""
    try:
        users = list(users_col.find({
            "organization_id": organization_id,
            "role": {"$ne": "superuser"}  # Explicitly exclude superusers
        }))
        return users
    except Exception as e:
        logger.error(f"Error getting visible users for organization {organization_id}: {str(e)}")
        return []

def get_organization_hierarchy(organization_id):
    """Get complete organization hierarchy tree"""
    try:
        # Get organization info
        organization = organizations_col.find_one({"_id": organization_id})
        if not organization:
            return None
        
        # Get all users grouped by role
        superusers = list(users_col.find({"organization_id": organization_id, "role": "superuser"}))
        admins = list(users_col.find({"organization_id": organization_id, "role": "admin"}))
        regular_users = list(users_col.find({"organization_id": organization_id, "role": "user"}))
        
        hierarchy = {
            "organization": {
                "name": organization.get("name"),
                "id": organization_id
            },
            "superusers": [
                {
                    "id": str(user["_id"]),
                    "username": user["username"],
                    "email": user["email"]
                } for user in superusers
            ],
            "admins": [
                {
                    "id": str(user["_id"]),
                    "username": user["username"],
                    "email": user["email"]
                } for user in admins
            ],
            "users": [
                {
                    "id": str(user["_id"]),
                    "username": user["username"],
                    "email": user["email"]
                } for user in regular_users
            ]
        }
        return hierarchy
    except Exception as e:
        logger.error(f"Error getting organization hierarchy for {organization_id}: {str(e)}")
        return None

def get_user_by_credentials(username, password_hash):
    """Get user by username and password hash for desktop app authentication"""
    try:
        user = users_col.find_one({
            "username": username,
            "password": password_hash
        })
        return user
    except Exception as e:
        logger.error(f"Error getting user by credentials: {str(e)}")
        return None

def is_session_active(session_id, organization_id):
    """Check if a session is currently active"""
    try:
        session = sessions_col.find_one({
            "_id": ObjectId(session_id),
            "organization_id": organization_id,
            "end_time": None
        })
        return session is not None
    except Exception as e:
        logger.error(f"Error checking session active status: {str(e)}")
        return False

def update_session_activity(session_id, organization_id, last_activity_time=None):
    """Update session with last activity time"""
    try:
        if not last_activity_time:
            last_activity_time = datetime.now(timezone.utc).isoformat()
        
        result = sessions_col.update_one(
            {"_id": ObjectId(session_id), "organization_id": organization_id},
            {"$set": {"last_activity": last_activity_time}}
        )
        return result.modified_count > 0
    except Exception as e:
        logger.error(f"Error updating session activity: {str(e)}")
        return False