import os
import logging
from datetime import datetime, timezone
from flask import Flask, render_template, request, redirect, url_for, session, flash, make_response, send_from_directory, Response
from io import StringIO
import hashlib
import csv
from bson import ObjectId
from flask_socketio import SocketIO, emit, join_room, rooms
from utils.db import (organizations_col, users_col, sessions_col, breaks_col,
                      activities_col, screenshots_col, recordings_col,
                      authenticate_user, register_user, get_all_users,
                      get_all_users_including_superusers, get_sessions_by_user,
                      get_all_sessions, get_session_by_id,
                      get_breaks_by_session, get_activities_by_session,
                      get_screenshots_by_session, get_recordings_by_session,
                      delete_session, delete_screenshot, get_users_by_role,
                      save_session)
import cv2
import numpy as np
import base64
import subprocess
from collections import defaultdict
import redis
from celery import Celery
import uuid

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "timescano_secret_key_2025")
socketio = SocketIO(
    app,
    cors_allowed_origins="https://timescano.onrender.com",
    logger=True,
    engineio_logger=True,
    ping_timeout=30,
    ping_interval=10,
    async_mode='gevent',
    transports=['websocket', 'polling'],
    max_http_buffer_size=25 * 1024 * 1024
)

# Redis client with retry logic
def connect_redis():
    try:
        client = redis.Redis(
            host=os.environ.get('REDIS_HOST', 'redis'),
            port=6379,
            db=0,
            decode_responses=True,
            socket_timeout=5,
            socket_connect_timeout=5
        )
        client.ping()
        logger.info("Connected to Redis successfully")
        return client
    except redis.ConnectionError as e:
        logger.warning(
            f"Redis connection failed: {str(e)}. Falling back to synchronous video processing."
        )
        return None

redis_client = connect_redis()

# Celery configuration
app.config['CELERY_BROKER_URL'] = f"redis://{os.environ.get('REDIS_HOST', 'redis')}:6379/0"
app.config['CELERY_RESULT_BACKEND'] = f"redis://{os.environ.get('REDIS_HOST', 'redis')}:6379/0"

def make_celery(app):
    celery = Celery(app.import_name,
                    broker=app.config['CELERY_BROKER_URL'],
                    backend=app.config['CELERY_RESULT_BACKEND'])
    celery.conf.update(app.config)
    return celery

celery = make_celery(app)

# Dictionary to store frame queues per session
frame_queues = defaultdict(list)
MAX_FRAME_QUEUE_SIZE = 50  # Reduced to save memory

def format_duration(seconds):
    if not seconds or isinstance(seconds, str):
        return "00:00:00"
    try:
        h, rem = divmod(int(seconds), 3600)
        m, s = divmod(rem, 60)
        return f"{h:02}:{m:02}:{s:02}"
    except (ValueError, TypeError):
        return "00:00:00"

def format_datetime(dt_string):
    if not dt_string:
        return "N/A"
    try:
        dt = datetime.fromisoformat(dt_string.replace('Z', '+00:00'))
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except:
        return dt_string

def end_session(session_id, end_time, elapsed_time, idle_time, organization_id):
    """End a session by updating end_time and metrics"""
    try:
        sessions_col.update_one(
            {
                "_id": ObjectId(session_id),
                "organization_id": organization_id
            }, {
                "$set": {
                    "end_time": end_time,
                    "elapsed_time": elapsed_time,
                    "idle_time": idle_time
                }
            })
        logger.info(f"Session {session_id} ended successfully")
        return True
    except Exception as e:
        logger.error(f"Error ending session {session_id}: {str(e)}")
        return False

@app.route('/')
def index():
    if 'user_id' in session:
        if session.get('is_superuser', False):
            return redirect(url_for('superuser_dashboard'))
        elif session.get('is_admin', False):
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('user_dashboard'))
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user_id = authenticate_user(email, password)
        if user_id:
            user = users_col.find_one({"_id": ObjectId(user_id)})
            session['user_id'] = user_id
            session['email'] = email
            session['username'] = user.get('username')
            session['role'] = user.get('role', 'user')
            session['is_admin'] = session['role'] == 'admin'
            session['is_superuser'] = session['role'] == 'superuser'
            session['organization_id'] = user.get('organization_id')
            flash('Login successful', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid email or password', 'error')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        organization = request.form.get('organization')
        if 'user_id' in session:
            organization_id = session['organization_id']
            if session['is_superuser']:
                role = request.form.get('role', 'user')
                if role not in ['admin', 'user']:
                    flash('Invalid role selected', 'error')
                    return render_template('register.html',
                                           is_superuser=True,
                                           is_logged_in=True)
            elif session['is_admin']:
                role = 'user'
            else:
                flash('Access denied. You cannot create users.', 'error')
                return redirect(url_for('login'))
        else:
            role = 'superuser'
            organization_id = str(uuid.uuid4())
            organization_name = organization
            organization_doc = {
                "_id": organization_id,
                "name": organization_name,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "subscription_active": False,
                "plan": "free"
            }
            organizations_col.insert_one(organization_doc)
        result = register_user(email, username, password, role,
                               organization_id)
        if result:
            if 'user_id' not in session:
                users_col.update_one({"_id": ObjectId(result)},
                                     {"$set": {
                                         "subscription_active": False
                                     }})
            flash(
                f'User with email "{email}" created successfully with role "{role}"',
                'success')
            if 'user_id' not in session:
                user_id = result
                user = users_col.find_one({"_id": ObjectId(user_id)})
                session['user_id'] = user_id
                session['email'] = email
                session['username'] = username
                session['role'] = 'superuser'
                session['is_admin'] = False
                session['is_superuser'] = True
                session['organization_id'] = organization_id
                return redirect(url_for('superuser_dashboard'))
            return redirect(
                url_for('superuser_dashboard'
                        if session['is_superuser'] else 'admin_dashboard'))
        flash('Error creating user', 'error')
    if 'user_id' in session:
        if not (session.get('is_superuser', False)
                or session.get('is_admin', False)):
            flash('Access denied', 'error')
            return redirect(url_for('login'))
        return render_template('register.html',
                               is_superuser=session.get('is_superuser', False),
                               is_logged_in=True)
    return render_template('register.html',
                           is_superuser=False,
                           is_logged_in=False)

@app.route('/plans')
def plans():
    if 'user_id' not in session or not session['is_superuser']:
        flash('Access denied. Only superusers can manage subscriptions.',
              'error')
        return redirect(url_for('login'))
    organization_id = session['organization_id']
    organization = organizations_col.find_one({"_id": organization_id})
    subscription_active = organization.get('subscription_active',
                                           False) if organization else False
    return render_template('plans.html',
                           subscription_active=subscription_active)

@app.route('/checkout', methods=['GET', 'POST'])
def checkout():
    if 'user_id' not in session or not session['is_superuser']:
        flash('Access denied. Only superusers can manage subscriptions.',
              'error')
        return redirect(url_for('login'))
    plan = request.args.get('plan')
    if plan != 'pro':
        flash('Invalid plan selected', 'error')
        return redirect(url_for('plans'))
    if request.method == 'POST':
        coupon = request.form.get('coupon', '').strip()
        if coupon == 'byb123':
            organization_id = session['organization_id']
            organizations_col.update_one(
                {"_id": organization_id},
                {"$set": {
                    "subscription_active": True,
                    "plan": "pro"
                }})
            users_col.update_one({"_id": ObjectId(session['user_id'])},
                                 {"$set": {
                                     "subscription_active": True
                                 }})
            flash(
                'Subscription activated successfully with coupon! Video tracking enabled for your entire organization.',
                'success')
            return redirect(url_for('plans'))
        flash('Invalid coupon. Payment not processed.', 'error')
    return render_template('checkout.html')

@app.route('/superuser/dashboard')
def superuser_dashboard():
    if 'user_id' not in session or not session['is_superuser']:
        flash('Access denied', 'error')
        return redirect(url_for('login'))
    organization_id = session['organization_id']
    user_filter = request.args.get('user_filter', '')
    date_filter = request.args.get('date_filter', '')
    users = get_users_by_role(organization_id, "superuser")
    all_users = get_all_users_including_superusers(organization_id)
    sessions = get_all_sessions(organization_id, user_filter, date_filter,
                                "superuser")
    formatted_sessions = []
    for session_item in sessions:
        user_id = session_item.get('user_id')
        username = all_users[[u['_id'] for u in all_users].index(
            ObjectId(user_id))]['username'] if user_id and ObjectId(
                user_id) in [u['_id'] for u in all_users] else 'Unknown'
        formatted_session = {
            '_id': str(session_item['_id']),
            'user_id': user_id or 'Unknown',
            'username': username,
            'start_time': format_datetime(session_item.get('start_time', '')),
            'end_time': format_datetime(session_item.get('end_time', '')),
            'elapsed_time':
            format_duration(session_item.get('elapsed_time', 0)),
            'idle_time': format_duration(session_item.get('idle_time', 0)),
            'video_path': session_item.get('video_path', '')
        }
        formatted_sessions.append(formatted_session)
    active_users = {
        str(user['_id']):
        bool(
            sessions_col.find_one({
                "user_id": str(user['_id']),
                "organization_id": organization_id,
                "end_time": None
            }))
        for user in users
    }
    return render_template('superuser_dashboard.html',
                           users=users,
                           sessions=formatted_sessions,
                           user_filter=user_filter,
                           date_filter=date_filter,
                           active_users=active_users)

@app.route('/superuser/user/<user_id>')
def superuser_user_detail(user_id):
    if 'user_id' not in session or not session['is_superuser']:
        flash('Access denied', 'error')
        return redirect(url_for('login'))
    organization_id = session['organization_id']
    user = users_col.find_one({
        "_id": ObjectId(user_id),
        "organization_id": organization_id
    })
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('superuser_dashboard'))
    date_filter = request.args.get('date_filter', '')
    sessions = get_sessions_by_user(user_id, organization_id)
    if date_filter:
        try:
            date_obj = datetime.fromisoformat(date_filter)
            start_of_day = date_obj.replace(hour=0,
                                            minute=0,
                                            second=0,
                                            microsecond=0).isoformat()
            end_of_day = date_obj.replace(hour=23,
                                          minute=59,
                                          second=59,
                                          microsecond=999999).isoformat()
            sessions = [
                s for s in sessions
                if start_of_day <= s.get('start_time', '') <= end_of_day
            ]
        except:
            pass
    formatted_sessions = []
    for session_item in sessions:
        formatted_session = {
            '_id': str(session_item['_id']),
            'start_time': format_datetime(session_item.get('start_time', '')),
            'end_time': format_datetime(session_item.get('end_time', '')),
            'elapsed_time':
            format_duration(session_item.get('elapsed_time', 0)),
            'idle_time': format_duration(session_item.get('idle_time', 0)),
            'video_path': session_item.get('video_path', '')
        }
        formatted_sessions.append(formatted_session)
    user_info = {
        'username': user['username'],
        'email': user['email'],
        'role': user['role'],
        '_id': str(user['_id']),
        'organization_id': user.get('organization_id', 'N/A'),
        'total_sessions': len(formatted_sessions)
    }
    return render_template('superuser_user_detail.html',
                           user=user_info,
                           sessions=formatted_sessions,
                           date_filter=date_filter)

@app.route('/admin/dashboard')
def admin_dashboard():
    if 'user_id' not in session or not session.get('is_admin', False):
        flash('Access denied', 'error')
        return redirect(url_for('login'))
    organization_id = session.get('organization_id')
    user_filter = request.args.get('user_filter', '')
    date_filter = request.args.get('date_filter', '')
    users = get_users_by_role(organization_id, "admin")
    sessions = get_all_sessions(organization_id, user_filter, date_filter,
                                "admin")
    formatted_sessions = []
    for session_item in sessions:
        user_id = session_item.get('user_id')
        if user_id:
            user = users_col.find_one({
                "_id": ObjectId(user_id),
                "organization_id": organization_id
            })
            username = user['username'] if user else 'Unknown'
            formatted_session = {
                '_id':
                str(session_item['_id']),
                'user_id':
                user_id or 'Unknown',
                'username':
                username,
                'start_time':
                format_datetime(session_item.get('start_time', '')),
                'end_time':
                format_datetime(session_item.get('end_time', '')),
                'elapsed_time':
                format_duration(session_item.get('elapsed_time', 0)),
                'idle_time':
                format_duration(session_item.get('idle_time', 0)),
                'video_path':
                session_item.get('video_path', '')
            }
            formatted_sessions.append(formatted_session)
    return render_template('admin/dashboard.html',
                           users=users,
                           sessions=formatted_sessions,
                           user_filter=user_filter,
                           date_filter=date_filter)

@app.route('/user/dashboard')
def user_dashboard():
    if 'user_id' not in session:
        flash('Please login first', 'error')
        return redirect(url_for('login'))
    organization_id = session.get('organization_id')
    sessions = get_sessions_by_user(session['user_id'], organization_id)
    formatted_sessions = []
    for session_item in sessions:
        formatted_session = {
            '_id': str(session_item['_id']),
            'start_time': format_datetime(session_item.get('start_time', '')),
            'end_time': format_datetime(session_item.get('end_time', '')),
            'elapsed_time':
            format_duration(session_item.get('elapsed_time', 0)),
            'idle_time': format_duration(session_item.get('idle_time', 0)),
            'video_path': session_item.get('video_path', '')
        }
        formatted_sessions.append(formatted_session)
    return render_template('user/dashboard.html', sessions=formatted_sessions)

@app.route('/admin/session/<session_id>')
def admin_session_detail(session_id):
    if 'user_id' not in session or not (session.get('is_admin', False)
                                        or session.get('is_superuser', False)):
        flash(
            'Access denied. Only admins or superusers can view this session.',
            'error')
        return redirect(url_for('login'))
    organization_id = session.get('organization_id')
    logger.info(f"Admin session detail for session {session_id}, organization_id: {organization_id}")
    session_data = get_session_by_id(session_id, organization_id)
    if not session_data:
        flash('Session not found', 'error')
        return redirect(url_for('admin_dashboard'))
    page = int(request.args.get('page', 1))
    limit = 10
    skip = (page - 1) * limit
    breaks = get_breaks_by_session(session_id, organization_id)
    activities = get_activities_by_session(session_id, organization_id)
    screenshots = get_screenshots_by_session(session_id,
                                             organization_id,
                                             limit=limit,
                                             skip=skip)
    total_screenshots = screenshots_col.count_documents({
        "session_id":
        session_id,
        "organization_id":
        organization_id
    })
    formatted_session = {
        '_id': str(session_data['_id']),
        'user_id': session_data['user_id'],
        'start_time': format_datetime(session_data.get('start_time', '')),
        'end_time': format_datetime(session_data.get('end_time', '')),
        'elapsed_time': format_duration(session_data.get('elapsed_time', 0)),
        'idle_time': format_duration(session_data.get('idle_time', 0)),
        'video_path': session_data.get('video_path', '')
    }
    has_video = False
    video_path = formatted_session['video_path']
    cache_key = f"video_exists:{session_id}"
    if redis_client:
        has_video = redis_client.get(cache_key) == "true"
    if not has_video and video_path and os.path.exists(video_path):
        has_video = True
        if redis_client:
            redis_client.setex(cache_key, 3600, "true")
    return render_template('admin_session_detail.html',
                           session=formatted_session,
                           breaks=breaks,
                           activities=activities,
                           screenshots=screenshots,
                           total_screenshots=total_screenshots,
                           page=page,
                           has_video=has_video,
                           is_admin=session.get('is_admin', False),
                           organization_id=organization_id)

@app.route('/download/<path:filename>')
def download_file(filename):
    try:
        return send_from_directory('videos', filename, as_attachment=True)
    except Exception as e:
        logger.error(f"Error downloading file {filename}: {str(e)}")
        flash('File not found', 'error')
        return redirect(url_for('admin_dashboard'))

@app.route('/delete/session/<session_id>')
def delete_session_route(session_id):
    if 'user_id' not in session or not (session.get('is_admin', False) or session.get('is_superuser', False)):
        flash('Access denied', 'error')
        return redirect(url_for('login'))
    organization_id = session.get('organization_id')
    if delete_session(session_id, organization_id):
        flash('Session deleted successfully', 'success')
    else:
        flash('Error deleting session', 'error')
    return redirect(url_for('admin_dashboard' if session.get('is_admin', False) else 'superuser_dashboard'))

@app.route('/delete/screenshot/<screenshot_id>')
def delete_screenshot_route(screenshot_id):
    if 'user_id' not in session or not (session.get('is_admin', False) or session.get('is_superuser', False)):
        flash('Access denied', 'error')
        return redirect(url_for('login'))
    organization_id = session.get('organization_id')
    screenshot = screenshots_col.find_one({"_id": ObjectId(screenshot_id), "organization_id": organization_id})
    if not screenshot:
        flash('Screenshot not found', 'error')
        return redirect(url_for('admin_dashboard'))
    session_id = screenshot.get('session_id')
    if delete_screenshot(screenshot_id, organization_id):
        flash('Screenshot deleted successfully', 'success')
    else:
        flash('Error deleting screenshot', 'error')
    return redirect(url_for('admin_session_detail', session_id=session_id))

@app.route('/export/<session_id>')
def export_session(session_id):
    if 'user_id' not in session or not (session.get('is_admin', False) or session.get('is_superuser', False)):
        flash('Access denied', 'error')
        return redirect(url_for('login'))
    organization_id = session.get('organization_id')
    session_data = get_session_by_id(session_id, organization_id)
    if not session_data:
        flash('Session not found', 'error')
        return redirect(url_for('admin_dashboard'))
    breaks = get_breaks_by_session(session_id, organization_id)
    activities = get_activities_by_session(session_id, organization_id)
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(['Session ID', 'User ID', 'Start Time', 'End Time', 'Elapsed Time', 'Idle Time'])
    writer.writerow([
        str(session_data['_id']),
        session_data.get('user_id', 'Unknown'),
        format_datetime(session_data.get('start_time', '')),
        format_datetime(session_data.get('end_time', '')),
        format_duration(session_data.get('elapsed_time', 0)),
        format_duration(session_data.get('idle_time', 0))
    ])
    writer.writerow([])
    writer.writerow(['Breaks'])
    writer.writerow(['Start', 'End', 'Duration'])
    for break_item in breaks:
        writer.writerow([
            break_item.get('start', 'N/A'),
            break_item.get('end', 'N/A'),
            format_duration(break_item.get('duration', 0))
        ])
    writer.writerow([])
    writer.writerow(['Activities'])
    writer.writerow(['Time', 'Activity'])
    for activity in activities:
        writer.writerow([
            activity.get('time', 'N/A'),
            activity.get('activity', 'N/A')
        ])
    response = make_response(output.getvalue())
    response.headers['Content-Disposition'] = f'attachment; filename=session_{session_id}.csv'
    response.headers['Content-type'] = 'text/csv'
    return response

@app.route('/export_csv/<session_id>')
def export_csv(session_id):
    """Alias for export_session for backward compatibility"""
    return export_session(session_id)

@celery.task
def process_video(session_id, frames, organization_id):
    try:
        session_data = sessions_col.find_one({
            "_id": ObjectId(session_id),
            "organization_id": organization_id
        })
        if not session_data:
            logger.warning(
                f"Session {session_id} not found for video processing in organization {organization_id}"
            )
            return
        organization = organizations_col.find_one({"_id": organization_id})
        if not organization or not organization.get('subscription_active', False):
            logger.info(
                f"Skipping video processing for non-subscribed organization {organization_id} in session {session_id}"
            )
            return
        video_dir = os.path.join(os.getcwd(), "videos")
        os.makedirs(video_dir, exist_ok=True)
        temp_video_path = os.path.join(video_dir, f"temp_{session_id}.avi")
        video_path_mp4 = os.path.join(video_dir, f"{session_id}.mp4")
        if not frames:
            logger.warning(
                f"No frames to process for session {session_id} in organization {organization_id}"
            )
            return
        logger.info(
            f"Processing video for session {session_id} with {len(frames)} frames in organization {organization_id}"
        )
        elapsed_seconds = session_data.get('elapsed_time', len(frames) * (1 / 15))
        frame_count = len(frames)
        if frame_count == 0:
            logger.error(f"No frames available for session {session_id}")
            return
        calculated_fps = max(0.2, min(frame_count / elapsed_seconds, 15.0)) if elapsed_seconds > 0 else 1.0
        fourcc = cv2.VideoWriter_fourcc(*'DIVX')
        out = cv2.VideoWriter(temp_video_path, fourcc, calculated_fps, (640, 360))
        if not out.isOpened():
            logger.error(
                f"Failed to initialize VideoWriter for session {session_id} in organization {organization_id}"
            )
            return
        for frame in frames:
            resized_frame = cv2.resize(frame, (640, 360), interpolation=cv2.INTER_LINEAR)
            out.write(resized_frame)
        out.release()
        cmd = [
            'ffmpeg', '-i', temp_video_path, '-c:v', 'libx264', '-c:a', 'aac',
            '-r', str(calculated_fps), '-y', video_path_mp4
        ]
        result = subprocess.run(cmd,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                text=True,
                                check=False)
        if result.returncode == 0 and os.path.exists(video_path_mp4) and os.path.getsize(video_path_mp4) > 0:
            sessions_col.update_one(
                {
                    "_id": ObjectId(session_id),
                    "organization_id": organization_id
                }, {"$set": {
                    "video_path": video_path_mp4
                }})
            if redis_client:
                redis_client.setex(f"video_exists:{session_id}", 3600, "true")
            logger.info(
                f"Converted and updated video path for session {session_id} in organization {organization_id}"
            )
            os.remove(temp_video_path)
        else:
            logger.error(
                f"FFmpeg conversion failed for session {session_id} in organization {organization_id}: {result.stderr}"
            )
            if os.path.exists(temp_video_path) and os.path.getsize(temp_video_path) > 0:
                sessions_col.update_one(
                    {
                        "_id": ObjectId(session_id),
                        "organization_id": organization_id
                    }, {"$set": {
                        "video_path": temp_video_path
                    }})
                if redis_client:
                    redis_client.setex(f"video_exists:{session_id}", 3600, "true")
                logger.info(
                    f"Retained temp AVI as video_path for session {session_id} in organization {organization_id}"
                )
    except Exception as e:
        logger.error(
            f"Error processing video for session {session_id} in organization {organization_id}: {str(e)}"
        )

def process_video_fallback(session_id, frames, organization_id):
    try:
        session_data = sessions_col.find_one({
            "_id": ObjectId(session_id),
            "organization_id": organization_id
        })
        if not session_data:
            logger.warning(
                f"Session {session_id} not found for video processing in fallback for organization {organization_id}"
            )
            return
        organization = organizations_col.find_one({"_id": organization_id})
        if not organization or not organization.get('subscription_active', False):
            logger.info(
                f"Skipping video processing for non-subscribed organization {organization_id} in session {session_id} (fallback)"
            )
            return
        video_dir = os.path.join(os.getcwd(), "videos")
        os.makedirs(video_dir, exist_ok=True)
        temp_video_path = os.path.join(video_dir, f"temp_{session_id}.avi")
        video_path_mp4 = os.path.join(video_dir, f"{session_id}.mp4")
        if not frames:
            logger.warning(
                f"No frames to process for session {session_id} in fallback for organization {organization_id}"
            )
            return
        logger.info(
            f"Processing video for session {session_id} with {len(frames)} frames in fallback for organization {organization_id}"
        )
        elapsed_seconds = session_data.get('elapsed_time', len(frames) * (1 / 15))
        frame_count = len(frames)
        if frame_count == 0:
            logger.error(f"No frames available for session {session_id}")
            return
        calculated_fps = max(0.2, min(frame_count / elapsed_seconds, 15.0)) if elapsed_seconds > 0 else 1.0
        fourcc = cv2.VideoWriter_fourcc(*'DIVX')
        out = cv2.VideoWriter(temp_video_path, fourcc, calculated_fps, (640, 360))
        if not out.isOpened():
            logger.error(
                f"Failed to initialize VideoWriter for session {session_id} in fallback for organization {organization_id}"
            )
            return
        for frame in frames:
            resized_frame = cv2.resize(frame, (640, 360), interpolation=cv2.INTER_LINEAR)
            out.write(resized_frame)
        out.release()
        cmd = [
            'ffmpeg', '-i', temp_video_path, '-c:v', 'libx264', '-c:a', 'aac',
            '-r', str(calculated_fps), '-y', video_path_mp4
        ]
        result = subprocess.run(cmd,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                text=True,
                                check=False)
        if result.returncode == 0 and os.path.exists(video_path_mp4) and os.path.getsize(video_path_mp4) > 0:
            sessions_col.update_one(
                {
                    "_id": ObjectId(session_id),
                    "organization_id": organization_id
                }, {"$set": {
                    "video_path": video_path_mp4
                }})
            if redis_client:
                redis_client.setex(f"video_exists:{session_id}", 3600, "true")
            logger.info(
                f"Converted and updated video path for session {session_id} in fallback for organization {organization_id}"
            )
            os.remove(temp_video_path)
        else:
            logger.error(
                f"FFmpeg conversion failed for session {session_id} in fallback for organization {organization_id}: {result.stderr}"
            )
            if os.path.exists(temp_video_path) and os.path.getsize(temp_video_path) > 0:
                sessions_col.update_one(
                    {
                        "_id": ObjectId(session_id),
                        "organization_id": organization_id
                    }, {"$set": {
                        "video_path": temp_video_path
                    }})
                if redis_client:
                    redis_client.setex(f"video_exists:{session_id}", 3600, "true")
                logger.info(
                    f"Retained temp AVI as video_path for session {session_id} in fallback for organization {organization_id}"
                )
    except Exception as e:
        logger.error(
            f"Error in fallback video processing for session {session_id} in organization {organization_id}: {str(e)}"
        )

@socketio.on('connect')
def handle_connect():
    logger.info(
        f"Client connected: {request.sid} at {datetime.now().isoformat()}")
    emit('connect_ack', {'status': 'connected', 'sid': request.sid})

@socketio.on('disconnect')
def handle_disconnect():
    logger.info(
        f"Client disconnected: {request.sid} at {datetime.now().isoformat()}")
    organization_id = session.get(
        'organization_id') if 'user_id' in session else None
    if 'user_id' in session:
        for session_id in list(frame_queues.keys()):
            session_data = sessions_col.find_one({
                "_id":
                ObjectId(session_id),
                "organization_id":
                organization_id
            })
            if session_data and session_data.get(
                    'end_time') is None and frame_queues[session_id]:
                logger.debug(
                    f"Queuing video processing for session {session_id}, frame count: {len(frame_queues[session_id])}"
                )
                emit('session_ended', {
                    'session_id': session_id,
                    'message': 'Live Session Ended'
                },
                     room=session_id)
                if redis_client:
                    try:
                        process_video.delay(session_id,
                                            frame_queues[session_id],
                                            organization_id)
                    except Exception as e:
                        logger.warning(
                            f"Celery task failed for session {session_id}: {str(e)}. Using fallback processing."
                        )
                        process_video_fallback(session_id,
                                               frame_queues[session_id],
                                               organization_id)
                else:
                    logger.warning(
                        f"Redis unavailable, using fallback processing for session {session_id}"
                    )
                    process_video_fallback(session_id,
                                           frame_queues[session_id],
                                           organization_id)
                del frame_queues[session_id]
                end_session(session_id,
                            datetime.now(timezone.utc).isoformat(), 0, 0,
                            organization_id)
    else:
        logger.warning(
            "No user session found during disconnect, skipping session end.")

@socketio.on('join_session')
def on_join(data):
    logger.info(f"Join session request: {data}, client SID: {request.sid}, current rooms: {rooms()}")
    session_id = data.get('session_id')
    user_id = data.get('user_id')
    organization_id = data.get('organization_id') or session.get('organization_id')
    
    if not all([session_id, user_id, organization_id]):
        logger.error(f"Invalid join_session data: {data}")
        emit('joined_session', {
            'status': 'error',
            'message': 'Missing session_id, user_id, or organization_id'
        })
        return

    logger.info(f"User {user_id} attempting to join session {session_id} (SID: {request.sid}) in organization {organization_id}")
    
    # Join the room first
    join_room(session_id)
    logger.info(f"Client {request.sid} joined room {session_id}, current rooms: {rooms()}")
    
    # Verify session exists
    session_data = sessions_col.find_one({"_id": ObjectId(session_id), "organization_id": organization_id})
    if not session_data:
        emit('joined_session', {
            'status': 'error',
            'message': 'Session not found'
        })
        logger.warning(f"Session {session_id} not found for organization {organization_id}")
        return

    # Check if session is active
    if session_data.get('end_time'):
        emit('joined_session', {
            'status': 'error',
            'message': 'Session has ended'
        })
        logger.info(f"Rejected join for ended session {session_id}")
        return

    # Success response
    emit('joined_session', {
        'status': 'success',
        'session_id': session_id,
        'message': 'Successfully joined session',
        'rooms': list(rooms())
    })
    
    logger.info(f"User {user_id} successfully joined session {session_id}, SID: {request.sid}, rooms: {rooms()}")
    
    # Send test frame immediately to verify connection
    emit('live_frame', {
        'session_id': session_id,
        'frame': '/9j/4AAQSkZJRgABAQEAAAAAAAD/2wBDAAYEBQYFBAYGBQYHBwYIChAKCgkJChQODwwQFxQYGBcUFhYaHSUfGhsjHBYWICwgIyYnKSopGR8tMC0oMCUoKSj/2wBDAQcHBwoIChMKChMoGhYaKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCj/wAARCAABAAEDASIAAhEBAxEB/8QAFQABAQAAAAAAAAAAAAAAAAAAAAv/xAAUEAEAAAAAAAAAAAAAAAAAAAAA/8QAFQEBAQAAAAAAAAAAAAAAAAAAAAX/xAAUEQEAAAAAAAAAAAAAAAAAAAAA/9oADAMBAAIRAxEAPwCdABmX/9k=',
        'timestamp': datetime.now().isoformat(),
        'user_id': user_id
    }, room=session_id)
    logger.info(f"Sent test frame to room {session_id}")

@socketio.on('live_frame')
def handle_live_frame(data):
    try:
        user_id = data.get('user_id')
        session_id = data.get('session_id')
        frame = data.get('frame')
        timestamp = data.get('timestamp')
        organization_id = data.get('organization_id') or session.get('organization_id')
        
        logger.info(f"Received live_frame request: user_id={user_id}, session_id={session_id}, frame_size={len(frame) if frame else 0}, timestamp={timestamp}, organization_id={organization_id}")
        
        if not all([user_id, session_id, frame, timestamp, organization_id]):
            logger.error(f"Invalid live_frame data - missing required fields: user_id={bool(user_id)}, session_id={bool(session_id)}, frame={bool(frame)}, timestamp={bool(timestamp)}, organization_id={bool(organization_id)}")
            return

        # Verify session exists and is active
        session_data = sessions_col.find_one({"_id": ObjectId(session_id), "organization_id": organization_id})
        if not session_data:
            logger.warning(f"Rejected frame for unknown session: {session_id} in organization {organization_id}")
            return
        if session_data.get('end_time'):
            logger.warning(f"Rejected frame for ended session: {session_id} in organization {organization_id}")
            return

        # Process frame for video storage
        try:
            frame_data = base64.b64decode(frame)
            np_arr = np.frombuffer(frame_data, np.uint8)
            frame_decoded = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)
            if frame_decoded is not None:
                frame_decoded = cv2.resize(frame_decoded, (640, 360), interpolation=cv2.INTER_LINEAR)
                if len(frame_queues[session_id]) < MAX_FRAME_QUEUE_SIZE:
                    frame_queues[session_id].append(frame_decoded)
                    logger.debug(f"Processed and stored frame for session {session_id}, shape: {frame_decoded.shape}")
                else:
                    logger.warning(f"Frame queue for session {session_id} is full, dropping frame")
            else:
                logger.error(f"Failed to decode frame for session {session_id}")
        except Exception as decode_error:
            logger.error(f"Error decoding frame: {str(decode_error)}")

        # Check who's in the room
        room_clients = socketio.server.manager.rooms.get('/', {}).get(session_id, set())
        logger.info(f"Broadcasting frame to session {session_id}, room has {len(room_clients)} clients: {list(room_clients)}")

        # Broadcast frame to all clients in the session room
        emit('live_frame', {
            'user_id': user_id,
            'session_id': session_id,
            'frame': frame,
            'timestamp': timestamp
        }, room=session_id)
        
        logger.info(f"Successfully broadcasted frame for session {session_id} to {len(room_clients)} clients")
        
    except Exception as e:
        logger.error(f"Error handling live frame: {str(e)}")

@socketio.on('ping')
def on_pong(data):
    logger.debug(f"Received ping with data: {data}")
    emit('pong', {'status': 'alive', 'time': datetime.now().isoformat()})

@socketio.on('punch_in')
def handle_punch_in(data):
    try:
        user_id = data.get('user_id')
        organization_id = data.get('organization_id')
        if not all([user_id, organization_id]):
            emit('punch_in_response', {
                'status': 'error',
                'message': 'Missing user_id or organization_id'
            })
            return
        existing_session = sessions_col.find_one({
            "user_id": user_id,
            "organization_id": organization_id,
            "end_time": None
        })
        if existing_session:
            emit(
                'punch_in_response', {
                    'status': 'success',
                    'message': 'Already punched in',
                    'session_id': str(existing_session['_id'])
                })
        else:
            session_id = save_session(user_id,
                                      datetime.now(timezone.utc).isoformat(),
                                      organization_id)
            if session_id:
                emit(
                    'punch_in_response', {
                        'status': 'success',
                        'message': 'Punch-in successful',
                        'session_id': session_id
                    })
                logger.info(f"User {user_id} punched in, session {session_id}")
            else:
                emit('punch_in_response', {
                    'status': 'error',
                    'message': 'Failed to create session'
                })
    except Exception as e:
        logger.error(f"Error handling punch_in: {str(e)}")
        emit('punch_in_response', {
            'status': 'error',
            'message': 'Internal server error'
        })

@socketio.on('session_ended')
def handle_session_ended(data):
    try:
        session_id = data.get('session_id')
        organization_id = data.get('organization_id')
        if session_id and organization_id:
            emit('session_ended', {
                'session_id': session_id,
                'message': 'Live Session Ended',
                'timestamp': datetime.now(timezone.utc).isoformat()
            },
                 room=session_id)
            logger.info(f"Session {session_id} ended, broadcasted to room")
    except Exception as e:
        logger.error(f"Error handling session_ended: {str(e)}")

@app.route('/api/organization/hierarchy')
def organization_hierarchy():
    if 'user_id' not in session or not session.get('is_superuser', False):
        return {
            'error':
            'Access denied. Only superusers can view organization hierarchy.'
        }, 403
    organization_id = session.get('organization_id')
    from utils.db import get_organization_hierarchy
    hierarchy = get_organization_hierarchy(organization_id)
    if hierarchy:
        return hierarchy
    return {'error': 'Organization not found'}, 404

@app.route('/api/auth/desktop', methods=['POST'])
def desktop_auth():
    try:
        data = request.get_json()
        username = data.get('username')
        password_hash = data.get('password_hash')
        if not username or not password_hash:
            return {'error': 'Username and password_hash required'}, 400
        from utils.db import get_user_by_credentials
        user = get_user_by_credentials(username, password_hash)
        if user:
            return {
                'success': True,
                'user_id': str(user['_id']),
                'username': user['username'],
                'organization_id': user.get('organization_id'),
                'role': user.get('role', 'user')
            }
        else:
            return {'error': 'Invalid credentials'}, 401
    except Exception as e:
        logger.error(f"Error in desktop auth: {str(e)}")
        return {'error': 'Internal server error'}, 500

@app.route('/api/session/<session_id>/activity', methods=['POST'])
def update_session_activity_api(session_id):
    try:
        data = request.get_json() or {}
        organization_id = data.get('organization_id')
        if not organization_id:
            return {'error': 'organization_id required'}, 400
        from utils.db import update_session_activity
        success = update_session_activity(session_id, organization_id)
        if success:
            return {'success': True}
        else:
            return {'error': 'Failed to update session activity'}, 400
    except Exception as e:
        logger.error(f"Error updating session activity: {str(e)}")
        return {'error': 'Internal server error'}, 500

@app.route('/debug/socketio')
def debug_socketio():
    if 'user_id' not in session or not (session.get('is_admin', False) or session.get('is_superuser', False)):
        return {'error': 'Access denied'}, 403
    
    try:
        rooms_info = {}
        if hasattr(socketio.server, 'manager') and hasattr(socketio.server.manager, 'rooms'):
            namespace_rooms = socketio.server.manager.rooms.get('/', {})
            for room_id, clients in namespace_rooms.items():
                rooms_info[room_id] = list(clients)
        
        return {
            'rooms': rooms_info,
            'total_rooms': len(rooms_info),
            'frame_queues': {k: len(v) for k, v in frame_queues.items()}
        }
    except Exception as e:
        logger.error(f"Error getting Socket.IO debug info: {str(e)}")
        return {'error': str(e)}, 500

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

if __name__ == '__main__':
    socketio.run(app,
                 host='0.0.0.0',
                 port=5000,
                 debug=True,
                 allow_unsafe_werkzeug=True)
