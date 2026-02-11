# NaCloud ☁️  
A Secure Cloud Storage Web Application

NaCloud is a full-stack cloud storage web application built using **FastAPI** and **AWS services**. It allows users to securely upload, organize, preview, download, and manage their files through a modern web dashboard with admin and mobile API support.

---

## 📌 Project Overview

NaCloud provides functionality similar to a personal cloud drive. Each user gets a private storage space backed by **Amazon S3**, protected by **AWS Cognito authentication**, and managed through a clean web interface built with **Bootstrap and Jinja2**.

The application supports both **web users** and **mobile clients** using secure token-based APIs.

---

## 🚀 Key Features

### 🔐 Authentication & User Management
- User registration using email & mobile number
- OTP-based email verification
- Secure login & logout
- Forgot password & reset password flow
- Session-based authentication
- Admin-only access control

### 📁 File & Folder Management
- Upload files up to **5GB** for free
- Create folders and nested directories
- Grid view & List view
- Download files and folders (ZIP support)
- Bulk select, bulk download & delete
- File preview support (Images, HEIC, documents)

### 🗑️ Recycle Bin
- Soft delete functionality
- Restore deleted files
- Permanent delete option
- Automatic cleanup of files older than 30 days

### 📱 Mobile API Support
- Token-based authentication using JWT
- List files & folders
- Create folders
- Rename, delete, move to recycle bin
- Secure API access per user

---

## 🛠️ Technology Stack

### Frontend
- HTML5, CSS3
- Bootstrap 5
- Jinja2 Templates

### Backend
- Python
- FastAPI
- Session Middleware
- Jinja2 Templating Engine

### Cloud & Storage
- AWS Cognito (Authentication)
- Amazon S3 (File storage)
- Amazon DynamoDB (Billing & metadata)
- AWS IAM (Access control)

### Additional Libraries
- Boto3 (AWS SDK)
- Pillow & pillow-heif (Image & HEIC preview)
- Python-Jose (JWT validation)
- SMTP (Email notifications)

---
