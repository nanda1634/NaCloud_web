import os
import hmac
import hashlib
import base64
import boto3
import mimetypes
import io
import zipfile
import random
import string
import smtplib
from jose import jwt
import requests
# import razorpay  # Uncomment if you re-enable payments later
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from dotenv import load_dotenv
from fastapi import FastAPI, Request, Form, Body, UploadFile, File, Depends, HTTPException
from fastapi.responses import RedirectResponse, HTMLResponse, JSONResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from fastapi.security import OAuth2PasswordBearer
from starlette.middleware.sessions import SessionMiddleware
from botocore.exceptions import ClientError
from typing import List, Optional, Union, Dict
from PIL import Image
import pillow_heif
from pydantic import BaseModel

# 1. LOAD ENVIRONMENT VARIABLES
load_dotenv()

# Register HEIC opener for Pillow (Crucial for HEIC thumbnails)
pillow_heif.register_heif_opener()

app = FastAPI()

# ==========================================
# CONFIGURATION
# ==========================================
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
COGNITO_USER_POOL_ID = os.getenv("COGNITO_USER_POOL_ID")
COGNITO_CLIENT_ID = os.getenv("COGNITO_CLIENT_ID")
COGNITO_CLIENT_SECRET = os.getenv("COGNITO_CLIENT_SECRET")
S3_BUCKET_NAME = os.getenv("S3_BUCKET_NAME")
SESSION_SECRET = os.getenv("SESSION_SECRET", "dev_secret_key")

# --- EMAIL CONFIGURATION (ZOHO MAIL) ---
SMTP_EMAIL = "support@nacloud.space"
SMTP_PASSWORD = os.getenv("MAIL_KEY")
ADMIN_EMAIL = os.getenv("MAIL_ID")

# Limits & Storage
MAX_UPLOAD_SIZE_BYTES = 1024 * 1024 * 1024 * 5 # 5GB
STORAGE_CLASS = 'INTELLIGENT_TIERING'

# File Categories
FILE_CATEGORIES = {
    'pictures': ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.webp', '.heic', '.heif'],
    'documents': ['.pdf', '.doc', '.docx', '.txt', '.xls', '.xlsx', '.ppt', '.pptx', '.csv'],
    'videos': ['.mp4', '.mov', '.avi', '.mkv', '.webm'],
    'music': ['.mp3', '.wav', '.aac', '.flac']
}

# Session Config
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET)

templates = Jinja2Templates(directory="templates")

# Initialize Clients
cognito_client = boto3.client('cognito-idp', region_name=AWS_REGION)
s3_client = boto3.client('s3', region_name=AWS_REGION)

dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION)
billing_table = dynamodb.Table('NaCloud_Billing')

# ==========================================
# HELPER FUNCTIONS
# ==========================================

async def initialize_user_billing(email: str):
    """Call this during signup/verify to set the 1-month grace period."""
    billing_table.put_item(Item={
        'email': email,
        'account_created': datetime.utcnow().isoformat(),
        'free_tier_limit': 5 * 1024 * 1024 * 1024, # 5GB
        'is_grace_period': True,
        'balance_owed': 0
    })


def get_secret_hash(username):
    msg = username + COGNITO_CLIENT_ID
    dig = hmac.new(
        str(COGNITO_CLIENT_SECRET).encode('utf-8'),
        msg=str(msg).encode('utf-8'),
        digestmod=hashlib.sha256
    ).digest()
    return base64.b64encode(dig).decode()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
# Helper to verify Cognito Access Token
def verify_token(token: str = Depends(oauth2_scheme)):
    """Verifies the JWT token from the Authorization Header."""
    try:
        # FastAPI Depends(oauth2_scheme) automatically finds the header "Authorization: Bearer <token>"
        # Now we use that token to get the user
        response = cognito_client.get_user(AccessToken=token)
        user_email = next(attr['Value'] for attr in response['UserAttributes'] if attr['Name'] == 'email')
        return user_email
    except Exception as e:
        print(f"Auth Error: {e}")
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    

def get_user_folder(username):
    return f"user_data/{username}/"

def get_recycle_bin_folder(username):
    return f"recycle_bin/{username}/"

def flash(request: Request, message: str, category: str = "primary"):
    if "_messages" not in request.session:
        request.session["_messages"] = []
    request.session["_messages"].append({"message": message, "category": category})

def get_flashed_messages(request: Request):
    return request.session.pop("_messages", [])

def invalidate_storage_cache(request: Request):
    if 'storage_bytes' in request.session:
        del request.session['storage_bytes']

def send_email(to_email, subject, body):
    """Sends an email using Zoho SMTP with SSL/TLS fallback"""
    if not SMTP_PASSWORD or "YOUR_ZOHO" in SMTP_PASSWORD:
        print("❌ EMAIL FAILED: SMTP_PASSWORD not set in main.py")
        return False
    try:
        msg = MIMEMultipart()
        msg['From'] = SMTP_EMAIL
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))
        
        try:
            # Try SSL (Port 465) first - preferred for Zoho
            server = smtplib.SMTP_SSL('smtp.zoho.in', 465, timeout=15)
        except:
            # Fallback to TLS (Port 587)
            server = smtplib.SMTP('smtp.zoho.in', 587, timeout=15)
            server.starttls()
            
        server.login(SMTP_EMAIL, SMTP_PASSWORD)
        server.sendmail(SMTP_EMAIL, to_email, msg.as_string())
        server.quit()
        return True
    except Exception as e:
        print(f"❌ Failed to send email: {e}")
        return False
    
def cleanup_recycle_bin():
    """
    Delete items from recycle_bin older than 30 days.
    Can be called periodically (e.g. via cron or manual).
    """
    cutoff = datetime.utcnow() - timedelta(days=30)
    try:
        paginator = s3_client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=S3_BUCKET_NAME, Prefix="recycle_bin/"):
            if "Contents" not in page:
                continue
            old_keys = []
            for obj in page["Contents"]:
                if obj["LastModified"].replace(tzinfo=None) < cutoff:
                    old_keys.append({"Key": obj["Key"]})
                    if len(old_keys) >= 1000:
                        s3_client.delete_objects(
                            Bucket=S3_BUCKET_NAME, Delete={"Objects": old_keys}
                        )
                        old_keys = []
            if old_keys:
                s3_client.delete_objects(
                    Bucket=S3_BUCKET_NAME, Delete={"Objects": old_keys}
                )
    except Exception as e:
        print("cleanup_recycle_bin error:", e)


# --- RECURSIVE DELETE HELPER ---
def delete_s3_folder_recursive(prefix):
    """Deletes all objects with the given prefix from S3."""
    try:
        paginator = s3_client.get_paginator('list_objects_v2')
        pages = paginator.paginate(Bucket=S3_BUCKET_NAME, Prefix=prefix)
        
        objects_to_delete = []
        for page in pages:
            if 'Contents' in page:
                for obj in page['Contents']:
                    objects_to_delete.append({'Key': obj['Key']})
                    
                    # S3 delete limit is 1000
                    if len(objects_to_delete) >= 1000:
                        s3_client.delete_objects(Bucket=S3_BUCKET_NAME, Delete={'Objects': objects_to_delete})
                        objects_to_delete = []
        
        if objects_to_delete:
            s3_client.delete_objects(Bucket=S3_BUCKET_NAME, Delete={'Objects': objects_to_delete})
            
        # Try to delete the folder marker itself if it exists
        s3_client.delete_object(Bucket=S3_BUCKET_NAME, Key=prefix)
        return True
    except Exception as e:
        print(f"Error deleting S3 folder {prefix}: {e}")
        return False

# ==========================================
# COMPLIANCE ROUTES (PRIVACY & ROBOTS)
# ==========================================
@app.get("/privacy-policy", response_class=HTMLResponse)
def privacy_policy(request: Request):
    return templates.TemplateResponse("privacy.html", {"request": request, "messages": get_flashed_messages(request)})

@app.get("/robots.txt", response_class=HTMLResponse)
def robots_txt():
    content = """User-agent: *
Allow: /
sitemap: https://nacloud.space/sitemap.xml
"""
    return HTMLResponse(content=content, media_type="text/plain")

# ==========================================
# AUTH ROUTES
# ==========================================

@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    if "user" in request.session:
        return RedirectResponse(url="/dashboard", status_code=303)
    return RedirectResponse(url="/login", status_code=303)

@app.get("/signup", response_class=HTMLResponse)
def signup_page(request: Request):
    return templates.TemplateResponse("signup.html", {"request": request, "messages": get_flashed_messages(request)})

@app.post("/signup")
def signup_post(request: Request, email: str = Form(...), password: str = Form(...), phone: str = Form(...)):
    # 1. Validate Email
    if not email.lower().endswith("@gmail.com"):
        flash(request, "Registration is restricted to @gmail.com addresses only.", "danger")
        return RedirectResponse(url="/signup", status_code=303)

    # 2. Validate Phone Number (Must be 10 digits)
    clean_phone = "".join(filter(str.isdigit, phone)) 
    if len(clean_phone) != 10:
        flash(request, "Invalid phone number. Must be exactly 10 digits.", "danger")
        return RedirectResponse(url="/signup", status_code=303)
    
    # Format for Cognito (+91 default)
    formatted_phone = "+91" + clean_phone

    try:
        # 3. Check for Duplicate Phone Number
        # Note: Requires cognito:ListUsers permission
        existing_users = cognito_client.list_users(
            UserPoolId=COGNITO_USER_POOL_ID,
            Filter=f'phone_number = "{formatted_phone}"'
        )
        
        if len(existing_users['Users']) > 0:
            flash(request, "This mobile number is already registered.", "danger")
            return RedirectResponse(url="/signup", status_code=303)

        # 4. Proceed with Signup
        secret_hash = get_secret_hash(email)
        cognito_client.sign_up(
            ClientId=COGNITO_CLIENT_ID,
            SecretHash=secret_hash,
            Username=email,
            Password=password,
            UserAttributes=[
                {'Name': 'email', 'Value': email},
                {'Name': 'phone_number', 'Value': formatted_phone}
            ]
        )
        flash(request, f"Account created! OTP sent.", "success")
        return RedirectResponse(url=f"/verify?username={email}", status_code=303)
        
    except ClientError as e:
        error_msg = e.response['Error']['Message']
        if "UsernameExistsException" in str(e):
            error_msg = "An account with this email already exists."
        flash(request, error_msg, "danger")
        return RedirectResponse(url="/signup", status_code=303)

@app.get("/verify", response_class=HTMLResponse)
def verify_page(request: Request, username: Optional[str] = ""):
    return templates.TemplateResponse("verify.html", {"request": request, "username": username, "messages": get_flashed_messages(request)})

@app.post("/verify")
def verify_post(request: Request, username: str = Form(...), otp: str = Form(...)):
    try:
        secret_hash = get_secret_hash(username)
        cognito_client.confirm_sign_up(ClientId=COGNITO_CLIENT_ID, SecretHash=secret_hash, Username=username, ConfirmationCode=otp)
        # Initialize user folders
        s3_client.put_object(Bucket=S3_BUCKET_NAME, Key=get_user_folder(username))
        flash(request, "Verified! Please login.", "success")
        return RedirectResponse(url="/login", status_code=303)
    except ClientError as e:
        flash(request, e.response['Error']['Message'], "danger")
        return RedirectResponse(url=f"/verify?username={username}", status_code=303)

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "messages": get_flashed_messages(request)})

@app.post("/login")
def login_post(request: Request, email: str = Form(...), password: str = Form(...)):
    try:
        secret_hash = get_secret_hash(email)
        response = cognito_client.initiate_auth(
            ClientId=COGNITO_CLIENT_ID, AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={'USERNAME': email, 'PASSWORD': password, 'SECRET_HASH': secret_hash}
        )
        request.session['user'] = email
        request.session['access_token'] = response['AuthenticationResult']['AccessToken']
        invalidate_storage_cache(request)
        flash(request, "Logged in successfully.", "success")
        return RedirectResponse(url="/dashboard", status_code=303)
    except ClientError as e:
        flash(request, e.response['Error']['Message'], "danger")
        return RedirectResponse(url="/login", status_code=303)

@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    flash(request, "Logged out.", "info")
    return RedirectResponse(url="/login", status_code=303)

@app.post("/api/mobile/login")
def mobile_login(email: str = Body(...), password: str = Body(...)):
    """
    Mobile login: returns Cognito tokens and email.
    Does NOT use web session; used only by mobile app.
    """
    try:
        secret_hash = get_secret_hash(email)
        resp = cognito_client.initiate_auth(
            ClientId=COGNITO_CLIENT_ID,
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': email,
                'PASSWORD': password,
                'SECRET_HASH': secret_hash,
            },
        )
        result = resp["AuthenticationResult"]

        return {
            "email": email,
            "access_token": result.get("AccessToken"),
            "id_token": result.get("IdToken"),
            "refresh_token": result.get("RefreshToken"),
        }
    except ClientError as e:
        return JSONResponse(
            status_code=401,
            content={"error": e.response["Error"]["Message"]},
        )

# --- FORGOT PASSWORD ROUTES ---
@app.get("/forgot-password", response_class=HTMLResponse)
def forgot_password_page(request: Request):
    return templates.TemplateResponse("forgot_password.html", {"request": request, "messages": get_flashed_messages(request)})

@app.post("/forgot-password")
def forgot_password_post(request: Request, email: str = Form(...)):
    try:
        secret_hash = get_secret_hash(email)
        cognito_client.forgot_password(ClientId=COGNITO_CLIENT_ID, SecretHash=secret_hash, Username=email)
        flash(request, f"Password reset code sent.", "success")
        return RedirectResponse(url=f"/reset-password?username={email}", status_code=303)
    except ClientError as e:
        flash(request, e.response['Error']['Message'], "danger")
        return RedirectResponse(url="/forgot-password", status_code=303)

@app.get("/reset-password", response_class=HTMLResponse)
def reset_password_page(request: Request, username: Optional[str] = ""):
    return templates.TemplateResponse("reset_password.html", {"request": request, "username": username, "messages": get_flashed_messages(request)})

@app.post("/reset-password")
def reset_password_post(request: Request, username: str = Form(...), otp: str = Form(...), new_password: str = Form(...)):
    try:
        secret_hash = get_secret_hash(username)
        cognito_client.confirm_forgot_password(ClientId=COGNITO_CLIENT_ID, SecretHash=secret_hash, Username=username, ConfirmationCode=otp, Password=new_password)
        flash(request, "Password reset! Login.", "success")
        return RedirectResponse(url="/login", status_code=303)
    except ClientError as e:
        flash(request, e.response['Error']['Message'], "danger")
        return RedirectResponse(url=f"/reset-password?username={username}", status_code=303)

# --- ADMIN ROUTES ---
@app.get("/admin", response_class=HTMLResponse)
def admin_panel(request: Request):
    if 'user' not in request.session: return RedirectResponse(url="/login", status_code=303)
    
    if request.session['user'] != ADMIN_EMAIL:
        flash(request, "Access Denied. Admin only.", "danger")
        return RedirectResponse(url="/dashboard", status_code=303)

    try:
        response = cognito_client.list_users(UserPoolId=COGNITO_USER_POOL_ID, Limit=60)
        users = []
        for u in response['Users']:
            email = next((attr['Value'] for attr in u['Attributes'] if attr['Name'] == 'email'), "Unknown")
            users.append({'email': email, 'status': u['UserStatus'], 'enabled': u['Enabled'], 'sub': u['Username']})
        return templates.TemplateResponse("admin.html", {"request": request, "users": users, "admin_email": ADMIN_EMAIL})
    except ClientError as e:
        flash(request, f"Error fetching users: {str(e)}", "danger")
        return RedirectResponse(url="/dashboard", status_code=303)

# ==========================================
# THUMBNAIL GENERATOR (HEIC & Image Preview)
# ==========================================
@app.get("/thumbnail")
def get_thumbnail(request: Request, key: str):
    if 'user' not in request.session: return JSONResponse({"error": "Unauthorized"}, status_code=401)
    
    try:
        file_obj = s3_client.get_object(Bucket=S3_BUCKET_NAME, Key=key)
        file_content = file_obj['Body'].read()
        img = Image.open(io.BytesIO(file_content))
        
        if img.mode in ("RGBA", "P"): img = img.convert("RGB")
        img.thumbnail((400, 400))
        
        thumb_io = io.BytesIO()
        img.save(thumb_io, "JPEG", quality=70)
        thumb_io.seek(0)
        return StreamingResponse(thumb_io, media_type="image/jpeg")
    except Exception:
        return JSONResponse({"error": "Thumbnail failed"}, status_code=500)

@app.post("/get_file_url")
async def get_file_url(request: Request, filename: str = Body(..., embed=True), current_path: str = Body(..., embed=True)):
    if 'user' not in request.session: return JSONResponse({"error": "Unauthorized"}, status_code=401)
    username = request.session['user']
    # Standard user path construction
    key = get_user_folder(username) + current_path + filename
    
    try:
        url = s3_client.generate_presigned_url(
            'get_object', Params={'Bucket': S3_BUCKET_NAME, 'Key': key}, ExpiresIn=300
        )
        return JSONResponse({"url": url})
    except ClientError as e: return JSONResponse({"error": str(e)}, status_code=500)


# ==========================================
# DASHBOARD
# ==========================================
@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, path: str = "", category: str = "all", view_user: str = None):
    if 'user' not in request.session: return RedirectResponse(url="/login", status_code=303)
    
    current_user = request.session['user']
    target_user = current_user 
    is_admin = (current_user == ADMIN_EMAIL)
    if view_user and is_admin: target_user = view_user
    
    user_root = get_user_folder(target_user)
    recycle_bin_root = get_recycle_bin_folder(target_user)
    
    is_recycle_bin = (category == "recycle_bin")
    search_prefix = recycle_bin_root if is_recycle_bin else user_root + path
    if ".." in path: path = ""
    
    files, folders = [], []
    total_size_bytes = 0
    
    # Total Size Calc (Sum of Active + Recycle Bin)
    try:
        paginator = s3_client.get_paginator('list_objects_v2')
        for page in paginator.paginate(Bucket=S3_BUCKET_NAME, Prefix=user_root):
            if 'Contents' in page:
                for obj in page['Contents']: total_size_bytes += obj['Size']
        for page in paginator.paginate(Bucket=S3_BUCKET_NAME, Prefix=recycle_bin_root):
            if 'Contents' in page:
                for obj in page['Contents']: total_size_bytes += obj['Size']
    except: pass

    try:
        if category in ['pictures', 'videos', 'documents', 'music']:
            paginator = s3_client.get_paginator('list_objects_v2')
            for page in paginator.paginate(Bucket=S3_BUCKET_NAME, Prefix=user_root):
                if 'Contents' in page:
                    for obj in page['Contents']:
                        ext = os.path.splitext(obj['Key'])[1].lower()
                        if ext in FILE_CATEGORIES.get(category, []):
                            files.append(process_s3_obj(obj, user_root, is_search=True))
        else:
            response = s3_client.list_objects_v2(Bucket=S3_BUCKET_NAME, Prefix=search_prefix, Delimiter='/')
            if 'CommonPrefixes' in response:
                for cp in response['CommonPrefixes']:
                    full_prefix = cp['Prefix']
                    folder_name = full_prefix[len(search_prefix):].strip('/')
                    folders.append({'name': folder_name, 'full_path': path + folder_name + '/'})
            if 'Contents' in response:
                for obj in response['Contents']:
                    if obj['Key'] == search_prefix: continue
                    files.append(process_s3_obj(obj, search_prefix))
    except ClientError: pass

    usage_gb = f"{total_size_bytes / (1024 ** 3):.4f} GB"
    breadcrumbs = []
    if not is_recycle_bin and category == "all":
        parts = path.strip('/').split('/')
        built_path = ""
        for part in parts:
            if part:
                built_path += part + "/"
                breadcrumbs.append({'name': part, 'path': built_path})

    return templates.TemplateResponse("dashboard.html", {
        "request": request, "user": current_user, "viewing_user": target_user, "is_admin": is_admin,
        "current_path": path, "category": category,
        "breadcrumbs": breadcrumbs, "folders": folders, "files": files, 
        "storage_usage": usage_gb, "is_recycle_bin": is_recycle_bin,
        "messages": get_flashed_messages(request)
    })

def process_s3_obj(obj, prefix_to_strip, is_search=False):
    if is_search:
        try: display_name = obj['Key'].split("user_data/")[1].split("/", 1)[1]
        except: display_name = obj['Key']
    else:
        display_name = obj['Key'][len(prefix_to_strip):]
    
    download_url = s3_client.generate_presigned_url('get_object', Params={'Bucket': S3_BUCKET_NAME, 'Key': obj['Key']}, ExpiresIn=3600)
    
    mime_type, _ = mimetypes.guess_type(obj['Key'])
    file_type = 'other'
    
    if obj['Key'].lower().endswith(('.heic', '.heif')):
        file_type = 'image'
    elif mime_type:
        if mime_type.startswith('image'): file_type = 'image'
        elif mime_type.startswith('video'): file_type = 'video'
    
    preview_url = download_url
    if file_type == 'image':
        # Use backend thumbnail generator
        preview_url = f"/thumbnail?key={obj['Key']}"

    return {
        'name': display_name,
        'size': f"{obj['Size']/1024:.2f} KB",
        'url': download_url,
        'preview_url': preview_url,
        'type': file_type,
        'full_key': obj['Key']
    }

@app.get("/api/mobile/list_files")
def mobile_list_files(email: str = Depends(verify_token), path: str = ""):
    """
    Now secure: The 'email' is derived from the 'Authorization' header token, 
    making it impossible for User A to list User B's files.
    """
    user_root = get_user_folder(email)
    search_prefix = user_root + path

    files: List[Dict] = []
    folders: List[Dict] = []

    try:
        response = s3_client.list_objects_v2(
            Bucket=S3_BUCKET_NAME,
            Prefix=search_prefix,
            Delimiter="/",
        )

        # Folders
        if "CommonPrefixes" in response:
            for cp in response["CommonPrefixes"]:
                full_prefix = cp["Prefix"]
                folder_name = full_prefix[len(search_prefix):].strip("/")
                folders.append(
                    {
                        "name": folder_name,
                        "path": path + folder_name + "/",
                    }
                )

        # Files
        if "Contents" in response:
            for obj in response["Contents"]:
                if obj["Key"] == search_prefix:
                    continue

                display_name = obj["Key"][len(search_prefix):]

                download_url = s3_client.generate_presigned_url(
                    "get_object",
                    Params={"Bucket": S3_BUCKET_NAME, "Key": obj["Key"]},
                    ExpiresIn=3600,
                )

                files.append(
                    {
                        "name": display_name,
                        "size_kb": round(obj["Size"] / 1024, 2),
                        "url": download_url,
                        "key": obj["Key"],
                    }
                )

        return {"folders": folders, "files": files}

    except ClientError as e:
        return JSONResponse(
            status_code=500,
            content={"error": str(e)},
        )

@app.get("/api/mobile/list_all_files")
def mobile_list_all_files(email: str = Depends(verify_token)):
    user_root = get_user_folder(email)
    recycle_root = get_recycle_bin_folder(email)
    files = []

    try:
        paginator = s3_client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=S3_BUCKET_NAME, Prefix=user_root):
            if "Contents" not in page:
                continue

            for obj in page["Contents"]:
                key = obj["Key"]
                # Skip the folder marker itself and recycle bin
                if key == user_root or key.startswith(recycle_root):
                    continue

                # Get display name relative to user_root
                display_name = key[len(user_root):]
                
                download_url = s3_client.generate_presigned_url(
                    "get_object",
                    Params={"Bucket": S3_BUCKET_NAME, "Key": key},
                    ExpiresIn=3600,
                )

                files.append({
                    "name": display_name.split('/')[-1], # Filename only
                    "full_path": display_name,            # Full relative path
                    "url": download_url,
                    "key": key,
                    "size": obj["Size"],
                    "last_modified": obj["LastModified"].isoformat(),
                })
        return {"files": files}
    except ClientError as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.post("/api/create-folder")
def mobile_create_folder(
    email: str = Depends(verify_token),
    path: str = Body(""),
    folder_name: str = Body(...),
):
    """
    Mobile: create a 'folder' for the given user and path.

    S3 key pattern:
      user_root = get_user_folder(email)
      key = user_root + path + folder_name + "/"
    """
    user_root = get_user_folder(email)
    prefix = user_root + (path or "")

    if prefix and not prefix.endswith("/"):
        prefix += "/"

    folder_key = f"{prefix}{folder_name}/"

    try:
        s3_client.put_object(Bucket=S3_BUCKET_NAME, Key=folder_key)
        return {"ok": True}
    except Exception as e:
        print("create_folder error:", e)
        raise HTTPException(status_code=500, detail="Failed to create folder")

@app.post("/api/mobile/delete_file")
def mobile_delete_file(
    email: str = Depends(verify_token),
    key: str = Body(...),
):
    """
    Permanently delete a file for a user.
    """
    user_root = get_user_folder(email)
    if not key.startswith(user_root):
        return JSONResponse(
            status_code=403,
            content={"error": "Not allowed"},
        )

    try:
        s3_client.delete_object(Bucket=S3_BUCKET_NAME, Key=key)
        return {"success": True}
    except ClientError as e:
        return JSONResponse(
            status_code=500,
            content={"error": str(e)},
        )

@app.post("/api/mobile/rename_file")
def mobile_rename_file(
    email: str = Depends(verify_token),
    old_key: str = Body(...),
    new_name: str = Body(...),
):
    """
    Rename a file. Keeps it in the same folder, only changes file name.
    """
    user_root = get_user_folder(email)
    if not old_key.startswith(user_root):
        return JSONResponse(
            status_code=403,
            content={"error": "Not allowed"},
        )

    # Build new key in same folder
    last_slash = old_key.rfind("/")
    if last_slash == -1:
        # unlikely, but fallback to root
        new_key = user_root + new_name
    else:
        folder_prefix = old_key[: last_slash + 1]
        new_key = folder_prefix + new_name

    try:
        s3_client.copy_object(
            Bucket=S3_BUCKET_NAME,
            CopySource={"Bucket": S3_BUCKET_NAME, "Key": old_key},
            Key=new_key,
        )
        s3_client.delete_object(Bucket=S3_BUCKET_NAME, Key=old_key)
        return {"success": True, "new_key": new_key}
    except ClientError as e:
        return JSONResponse(
            status_code=500,
            content={"error": str(e)},
        )

@app.post("/api/mobile/move_to_bin")
def mobile_move_to_bin(email: str = Depends(verify_token), key: str = Body(...)):
    """
    Soft delete: move a file from user_data to recycle_bin.
    """
    user_root = get_user_folder(email)
    recycle_root = get_recycle_bin_folder(email)

    if not key.startswith(user_root):
        return JSONResponse(status_code=403, content={"error": "Not allowed"})

    relative = key[len(user_root):]
    dest_key = recycle_root + relative

    try:
        s3_client.copy_object(
            Bucket=S3_BUCKET_NAME,
            CopySource={"Bucket": S3_BUCKET_NAME, "Key": key},
            Key=dest_key,
            StorageClass=STORAGE_CLASS,
        )
        s3_client.delete_object(Bucket=S3_BUCKET_NAME, Key=key)
        return {"success": True}
    except ClientError as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@app.get("/api/mobile/list_bin")
def mobile_list_bin(email: str = Depends(verify_token)):
    recycle_root = get_recycle_bin_folder(email)
    files = []

    try:
        paginator = s3_client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=S3_BUCKET_NAME, Prefix=recycle_root):
            if "Contents" not in page:
                continue
            for obj in page["Contents"]:
                key = obj["Key"]
                if key.endswith("/"):
                    continue

                display_name = key[len(recycle_root):]
                download_url = s3_client.generate_presigned_url(
                    "get_object",
                    Params={"Bucket": S3_BUCKET_NAME, "Key": key},
                    ExpiresIn=3600,
                )
                files.append(
                    {
                        "name": display_name,
                        "url": download_url,
                        "key": key,
                        "size": obj["Size"],
                        "last_modified": obj["LastModified"].isoformat(),
                    }
                )
        return {"files": files}
    except ClientError as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@app.get("/api/mobile/profile")
def mobile_profile(email: str = Depends(verify_token)):
    user_root = get_user_folder(email)
    recycle_root = get_recycle_bin_folder(email)

    total_bytes = 0
    file_count = 0

    try:
      paginator = s3_client.get_paginator("list_objects_v2")
      for page in paginator.paginate(Bucket=S3_BUCKET_NAME, Prefix=user_root):
          if "Contents" not in page:
              continue
          for obj in page["Contents"]:
              if obj["Key"].endswith("/"):
                  continue
              total_bytes += obj["Size"]
              file_count += 1
    except ClientError:
      pass

    # we ignore recycle bin for usage here – but you could add it too

    return {
        "email": email,
        "used_bytes": total_bytes,
        "file_count": file_count,
    }


@app.post("/api/mobile/restore_from_bin")
def mobile_restore_from_bin(email: str = Depends(verify_token), key: str = Body(...)):
    user_root = get_user_folder(email)
    recycle_root = get_recycle_bin_folder(email)

    if not key.startswith(recycle_root):
        return JSONResponse(status_code=403, content={"error": "Not allowed"})

    relative = key[len(recycle_root):]
    dest_key = user_root + relative

    try:
        s3_client.copy_object(
            Bucket=S3_BUCKET_NAME,
            CopySource={"Bucket": S3_BUCKET_NAME, "Key": key},
            Key=dest_key,
            StorageClass=STORAGE_CLASS,
        )
        s3_client.delete_object(Bucket=S3_BUCKET_NAME, Key=key)
        return {"success": True}
    except ClientError as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@app.post("/api/mobile/delete_from_bin")
def mobile_delete_from_bin(email: str = Depends(verify_token), key: str = Body(...)):
    recycle_root = get_recycle_bin_folder(email)
    if not key.startswith(recycle_root):
        return JSONResponse(status_code=403, content={"error": "Not allowed"})

    try:
        s3_client.delete_object(Bucket=S3_BUCKET_NAME, Key=key)
        return {"success": True}
    except ClientError as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@app.post("/api/mobile/signup")
def mobile_signup(email: str = Depends(verify_token), password: str = Body(...), phone: str = Body(...)):
    """
    Mobile signup endpoint.
    - email: full email (must end with @gmail.com if you keep web restriction)
    - password: the user's chosen password
    - phone: user phone digits (10 digits). Backend will prefix +91 (same as web) unless phone already has +country.
    Returns JSON { ok: True } or { error: "..."}
    """
    # 1. Email policy (same validation as web)
    try:
        if not email or not email.lower().endswith("@gmail.com"):
            return JSONResponse(status_code=400, content={"error": "Registration restricted to @gmail.com addresses."})

        # 2. Normalize phone (strip non-digit)
        clean_phone = "".join(filter(str.isdigit, phone))
        if len(clean_phone) == 10:
            formatted_phone = "+91" + clean_phone
        elif phone.startswith('+') and len(clean_phone) >= 10:
            # assume user provided country code already
            formatted_phone = "+" + clean_phone
        else:
            return JSONResponse(status_code=400, content={"error": "Invalid phone number. Must be 10 digits or include country code."})

        # 3. Check duplicate phone (optional; requires Cognito ListUsers permission)
        try:
            existing_users = cognito_client.list_users(
                UserPoolId=COGNITO_USER_POOL_ID,
                Filter=f'phone_number = "{formatted_phone}"'
            )
            if len(existing_users.get('Users', [])) > 0:
                return JSONResponse(status_code=400, content={"error": "This mobile number is already registered."})
        except Exception:
            # ignore list_users failure if permissions missing; still attempt signup
            pass

        # 4. Sign up with Cognito (same logic as web)
        secret_hash = get_secret_hash(email)
        resp = cognito_client.sign_up(
            ClientId=COGNITO_CLIENT_ID,
            SecretHash=secret_hash,
            Username=email,
            Password=password,
            UserAttributes=[
                {'Name': 'email', 'Value': email},
                {'Name': 'phone_number', 'Value': formatted_phone}
            ]
        )
        # Sign-up succeeded but requires confirmation code
        return JSONResponse(status_code=200, content={"ok": True, "message": "Signup successful. A verification code was sent to your email."})

    except cognito_client.exceptions.UsernameExistsException:
        return JSONResponse(status_code=400, content={"error": "An account with this email already exists."})
    except Exception as e:
        # keep error message non-verbose in production
        return JSONResponse(status_code=500, content={"error": str(e)})


@app.post("/api/mobile/verify")
def mobile_verify(username: str = Body(...), otp: str = Body(...)):
    """
    Confirm the user's signup (Cognito confirmation code).
    Returns { ok: True } or { error: "..." }
    """
    try:
        secret_hash = get_secret_hash(username)
        cognito_client.confirm_sign_up(ClientId=COGNITO_CLIENT_ID, SecretHash=secret_hash, Username=username, ConfirmationCode=otp)
        # Create user folder in S3 like the web flow (optional)
        s3_client.put_object(Bucket=S3_BUCKET_NAME, Key=get_user_folder(username))
        return JSONResponse(status_code=200, content={"ok": True, "message": "Verified. Please login."})
    except Exception as e:
        # Cognito returns descriptive exceptions (InvalidParameter, CodeMismatch, etc.)
        return JSONResponse(status_code=400, content={"error": str(e)})

# --- FILE OPS ---
@app.post("/create_folder")
def create_folder(request: Request, folder_name: str = Form(...), current_path: str = Form(""), category: str = Form("all")):
    if 'user' not in request.session: return RedirectResponse(url="/login", status_code=303)
    username = request.session['user']
    folder_name = "".join(x for x in folder_name if x.isalnum() or x in " _-")
    if folder_name:
        s3_key = get_user_folder(username) + current_path + folder_name + "/"
        try: s3_client.put_object(Bucket=S3_BUCKET_NAME, Key=s3_key)
        except: pass
    return RedirectResponse(url=f"/dashboard?path={current_path}&category={category}", status_code=303)

@app.post("/delete_files")
async def delete_files(request: Request, filenames: List[str] = Body(...), current_path: str = Body(""), permanent: bool = Body(False)):
    if 'user' not in request.session: return JSONResponse({"error": "Unauthorized"}, status_code=401)
    username = request.session['user']
    user_root = get_user_folder(username)
    recycle_root = get_recycle_bin_folder(username)
    objects_to_process = []
    for name in filenames:
        prefix_context = recycle_root if permanent else (user_root + current_path)
        key = prefix_context + name
        if name.endswith("/"):
            try:
                paginator = s3_client.get_paginator('list_objects_v2')
                for page in paginator.paginate(Bucket=S3_BUCKET_NAME, Prefix=key):
                    if 'Contents' in page:
                        for obj in page['Contents']: objects_to_process.append(obj['Key'])
            except: pass
        else: objects_to_process.append(key)
    if not objects_to_process: return JSONResponse({"message": "Empty"}, status_code=200)
    try:
        if permanent:
            chunk_size = 1000
            for i in range(0, len(objects_to_process), chunk_size):
                chunk = [{'Key': k} for k in objects_to_process[i:i+chunk_size]]
                s3_client.delete_objects(Bucket=S3_BUCKET_NAME, Delete={'Objects': chunk})
        else:
            for key in objects_to_process:
                relative_path = key[len(user_root):]
                new_key = recycle_root + relative_path
                s3_client.copy_object(Bucket=S3_BUCKET_NAME, CopySource={'Bucket': S3_BUCKET_NAME, 'Key': key}, Key=new_key, StorageClass='GLACIER_IR')
                s3_client.delete_object(Bucket=S3_BUCKET_NAME, Key=key)
        invalidate_storage_cache(request)
        return JSONResponse({"message": "Done"}, status_code=200)
    except ClientError as e: return JSONResponse({"error": str(e)}, status_code=500)

@app.post("/restore_files")
async def restore_files(request: Request, filenames: List[str] = Body(...)):
    if 'user' not in request.session: return JSONResponse({"error": "Unauthorized"}, status_code=401)
    username = request.session['user']
    user_root = get_user_folder(username)
    recycle_root = get_recycle_bin_folder(username)
    try:
        for name in filenames:
            src_key = recycle_root + name
            dest_key = user_root + name
            s3_client.copy_object(Bucket=S3_BUCKET_NAME, CopySource={'Bucket': S3_BUCKET_NAME, 'Key': src_key}, Key=dest_key, StorageClass=STORAGE_CLASS)
            s3_client.delete_object(Bucket=S3_BUCKET_NAME, Key=src_key)
        invalidate_storage_cache(request)
        return JSONResponse({"message": "Restored"}, status_code=200)
    except ClientError as e: return JSONResponse({"error": str(e)}, status_code=500)

@app.post("/get_zip_urls")
async def get_zip_urls(request: Request, filenames: List[str] = Body(...), current_path: str = Body(""), category: str = Body("all")): 
    if 'user' not in request.session: return JSONResponse({"error": "Unauthorized"}, status_code=401)
    username = request.session['user']
    user_root = get_user_folder(username)
    prefix_context = user_root + current_path
    download_targets = []
    try:
        for name in filenames:
            key = prefix_context + name
            if name.endswith("/"):
                paginator = s3_client.get_paginator('list_objects_v2')
                for page in paginator.paginate(Bucket=S3_BUCKET_NAME, Prefix=key):
                    if 'Contents' in page:
                        for obj in page['Contents']:
                            zip_path = obj['Key'][len(prefix_context):]
                            url = s3_client.generate_presigned_url('get_object', Params={'Bucket': S3_BUCKET_NAME, 'Key': obj['Key']}, ExpiresIn=3600)
                            download_targets.append({"url": url, "filename": zip_path})
            else:
                url = s3_client.generate_presigned_url('get_object', Params={'Bucket': S3_BUCKET_NAME, 'Key': key}, ExpiresIn=3600)
                download_targets.append({"url": url, "filename": name})
        return JSONResponse({"files": download_targets})
    except ClientError as e: return JSONResponse({"error": str(e)}, status_code=500)

# 1. Update the Web Endpoint (Session Based)
@app.post("/get_presigned_upload")
async def get_presigned_upload(
    request: Request, 
    filename: str = Body(..., embed=True), 
    file_type: str = Body(..., embed=True), 
    current_path: str = Body(..., embed=True)
):
    if 'user' not in request.session: 
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    
    username = request.session['user']
    
    user_root = get_user_folder(username).rstrip("/")
    clean_path = current_path.strip("/")

    if clean_path:
        key = f"{user_root}/{clean_path}/{filename}"
    else:
        key = f"{user_root}/{filename}"
    try:
        presigned = s3_client.generate_presigned_post(
            Bucket=S3_BUCKET_NAME, Key=key,
            Fields={"acl": "private", "Content-Type": file_type, "x-amz-storage-class": STORAGE_CLASS},
            Conditions=[
                {"acl": "private"}, 
                {"Content-Type": file_type}, 
                ["content-length-range", 0, MAX_UPLOAD_SIZE_BYTES], 
                {"x-amz-storage-class": STORAGE_CLASS}
            ],
            ExpiresIn=3600
        )
        return JSONResponse(presigned)
    except ClientError as e: 
        return JSONResponse({"error": str(e)}, status_code=500)


# 2. Update the Mobile Endpoint (Token Based)
@app.post("/api/mobile/get_presigned_upload")
def mobile_presigned_upload(
    filename: str = Body(...),
    file_type: str = Body(...),
    current_path: str = Body(""),
    email: str = Depends(verify_token)
):

    # FIX: Ensure there are no double slashes and paths are joined correctly
    user_root = get_user_folder(email).rstrip("/")
    # Clean the current_path: remove leading/trailing slashes
    clean_path = current_path.strip("/")
    
    if clean_path:
        key = f"{user_root}/{clean_path}/{filename}"
    else:
        key = f"{user_root}/{filename}"

    try:
        presigned = s3_client.generate_presigned_post(
            Bucket=S3_BUCKET_NAME,
            Key=key,
            Fields={
                "acl": "private",
                "Content-Type": file_type,
                "x-amz-storage-class": STORAGE_CLASS,
            },
            Conditions=[
                {"acl": "private"},
                {"Content-Type": file_type},
                ["content-length-range", 0, MAX_UPLOAD_SIZE_BYTES],
                {"x-amz-storage-class": STORAGE_CLASS},
            ],
            ExpiresIn=3600,
        )
        return presigned
    except ClientError as e:
        return JSONResponse(status_code=500, content={"error": str(e)})
    

@app.post("/upload_success")
async def upload_success(request: Request):
    if 'user' in request.session: invalidate_storage_cache(request)
    return JSONResponse({"status": "ok"})

# --- MOBILE APP API ---
@app.post("/upload") 
def upload(request: Request, files: Union[List[UploadFile], UploadFile] = File(...), current_path: str = Form("")):
    if 'user' not in request.session: return JSONResponse(content={"error": "Unauthorized"}, status_code=401)
    username = request.session['user']
    user_root = get_user_folder(username) + current_path
    if not isinstance(files, list): files = [files]
    success = 0
    for f in files:
        if not f.filename: continue
        s3_key = user_root + f.filename
        try:
            s3_client.upload_fileobj(f.file, S3_BUCKET_NAME, s3_key, ExtraArgs={'StorageClass': STORAGE_CLASS})
            success += 1
        except: pass
    if success > 0: invalidate_storage_cache(request); return JSONResponse(content={"message": "Success"}, status_code=200)
    return JSONResponse(content={"error": "Failed"}, status_code=500)


# ==========================================
# ACCOUNT DELETION (AUTOMATED)
# ==========================================
@app.post("/send_delete_otp")
def send_delete_otp(request: Request, email: str = Form(...)):
    session_user = request.session.get('user')
    if not email or email != session_user: return JSONResponse({"error": "Invalid email"}, status_code=400)
    
    otp = ''.join(random.choices(string.digits, k=6))
    request.session['delete_account_otp'] = otp
    request.session['delete_account_email'] = email
    
    send_email(email, "NaCloud Account Deletion Verification", f"Your OTP to delete your account is: {otp}")
    return JSONResponse({"message": "OTP sent", "status": "sent"})

@app.post("/confirm_delete_account")
def confirm_delete_account(request: Request, email: str = Form(...), otp: str = Form(...), reason: str = Form(...)):
    if request.session.get('delete_account_otp') != otp:
        return JSONResponse({"error": "Invalid OTP"}, status_code=400)

    # 1. AUTOMATICALLY DELETE DATA FROM S3
    user_root = get_user_folder(email)
    recycle_root = get_recycle_bin_folder(email)
    
    print(f"Deleting data for {email}...")
    delete_s3_folder_recursive(user_root)
    delete_s3_folder_recursive(recycle_root)

    # 2. AUTOMATICALLY DELETE USER FROM COGNITO
    try:
        access_token = request.session.get('access_token')
        if access_token:
             cognito_client.delete_user(AccessToken=access_token)
        else:
             # Fallback to Admin Delete
             cognito_client.admin_delete_user(UserPoolId=COGNITO_USER_POOL_ID, Username=email)
    except Exception as e:
        print(f"Cognito Delete Error: {e}")

    # 3. Notify Admin
    current_time = datetime.now()
    admin_body = f"""
    AUTOMATED DELETION REPORT
    -------------------------
    User Email: {email}
    Reason: {reason}
    Time: {current_time}
    
    Status:
    - S3 Data: Deleted Automatically
    - Cognito User: Deleted Automatically
    """
    send_email(ADMIN_EMAIL, f"USER DELETED: {email}", admin_body)
    
    request.session.clear()
    return JSONResponse({
        "message": "Account permanently deleted. Goodbye!", 
        "redirect": "/signup"
    })

@app.post("/api/login")
def api_login(request: Request, email: str = Form(...), password: str = Form(...)):
    try:
        secret_hash = get_secret_hash(email)
        response = cognito_client.initiate_auth(ClientId=COGNITO_CLIENT_ID, AuthFlow='USER_PASSWORD_AUTH', AuthParameters={'USERNAME': email, 'PASSWORD': password, 'SECRET_HASH': secret_hash})
        request.session['user'] = email
        return JSONResponse(content={"message": "Login Successful", "user": email}, status_code=200)
    except ClientError as e: return JSONResponse(content={"error": str(e)}, status_code=400)

if __name__ == '__main__':
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
