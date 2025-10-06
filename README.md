# Blood Bank Management System - Backend

## Overview
This is the backend API for the Blood Bank Management System, built with Express.js and designed for deployment on Google Cloud App Engine.

## Features
- **User Management**: Admin, Donor, and Recipient authentication
- **Blood Inventory**: Real-time blood stock management
- **Donation Management**: Walk-in donations and approval workflow
- **Location Services**: Google Places API integration for facility search
- **RESTful API**: Comprehensive endpoints for all operations

## Tech Stack
- **Framework**: Express.js
- **Database**: PostgreSQL (Supabase)
- **Authentication**: JWT with bcrypt
- **Cloud Platform**: Google Cloud App Engine
- **APIs**: Google Places, Geocoding, Distance Matrix

## Deployment
This backend is configured for automatic deployment to Google Cloud App Engine using GitHub Actions.

### Environment Variables Required:
- `SUPABASE_URL`: Your Supabase project URL
- `SUPABASE_KEY`: Your Supabase service role key
- `JWT_SECRET`: Secret key for JWT tokens
- `GOOGLE_PLACES_API_KEY`: Google Places API key
- `GOOGLE_GEOCODING_API_KEY`: Google Geocoding API key
- `GOOGLE_DISTANCE_MATRIX_API_KEY`: Google Distance Matrix API key
- `GOOGLE_MAPS_API_KEY`: Google Maps API key

### Deployment URL:
https://blood-bank-app-439123.appspot.com

## API Endpoints

### Authentication
- `POST /api/auth/signup` - User registration
- `POST /api/auth/login` - User login

### Donor
- `GET /api/donor/eligibility` - Check donation eligibility
- `POST /api/donor/donation` - Submit walk-in donation
- `GET /api/donor/dashboard` - Donor dashboard data

### Admin
- `GET /api/admin/dashboard` - Admin dashboard data
- `GET /api/admin/pending-donations` - Pending donations
- `POST /api/admin/approve-donation` - Approve donation
- `GET /api/admin/blood-inventory` - Blood inventory

### Recipient
- `GET /api/recipient/dashboard` - Recipient dashboard data
- `GET /api/recipient/nearby-facilities` - Find nearby facilities
- `POST /api/recipient/blood-request` - Submit blood request

### Health Check
- `GET /api/health` - Server health status
- `GET /api/network-test` - Network connectivity test

## Local Development

1. Install dependencies:
   ```bash
   npm install
   ```

2. Set up environment variables in `.env` file

3. Start the server:
   ```bash
   npm start
   ```

The server will run on port 8080 (Google Cloud compatible).

## Google Cloud App Engine Configuration

The `app.yaml` file contains the deployment configuration:
- Node.js 18 runtime
- Automatic scaling (1-10 instances)
- Environment variables injection
- Resource allocation (1 CPU, 0.5GB RAM)

## Security Features
- JWT authentication for all protected routes
- Password hashing with bcrypt
- Input validation and sanitization
- Environment variable configuration
- CORS enabled for frontend access

## Database Schema
Uses Supabase (PostgreSQL) with tables for:
- Users (admin, donor, recipient)
- Blood inventory
- Donations
- Blood requests
- User profiles

## Contributing
1. Fork the repository
2. Create a feature branch
3. Make changes and test locally
4. Submit a pull request

## License
ISC License
