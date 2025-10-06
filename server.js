const express = require('express');
const cors = require('cors');
const os = require('os');
const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 8080;

// Supabase Configuration
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;

const supabase = createClient(supabaseUrl, supabaseKey);

// Middleware
app.use(cors());
app.use(express.json());

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-default-jwt-secret-key';

// Validate required environment variables
if (!supabaseUrl || !supabaseKey) {
    console.error('❌ Missing required environment variables: SUPABASE_URL and SUPABASE_KEY');
    process.exit(1);
}

// Auth Middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid token' });
        }
        req.user = user;
        next();
    });
};

// Helper function to generate JWT token
const generateToken = (user) => {
    return jwt.sign(
        { 
            id: user.id, 
            email: user.email, 
            user_type: user.user_type 
        }, 
        JWT_SECRET, 
        { expiresIn: '24h' }
    );
};

// Google Places API function to get real nearby facilities
const getRealNearbyFacilities = async (latitude, longitude, radiusInMeters) => {
    const GOOGLE_PLACES_API_KEY = process.env.GOOGLE_PLACES_API_KEY;
    
    if (!GOOGLE_PLACES_API_KEY) {
        throw new Error('Google Places API key not configured');
    }

    console.log(`🔍 Using Google Places API with key: ${GOOGLE_PLACES_API_KEY.substring(0, 20)}...`);
    
    try {
        // Define search queries for medical facilities
        const searchQueries = [
            { keyword: 'hospital', type: 'hospital' },
            { keyword: 'blood bank', type: 'hospital' },
            { keyword: 'medical center', type: 'health' },
            { keyword: 'Apollo Hospital Coimbatore', type: 'hospital' },
            { keyword: 'KMCH Coimbatore', type: 'hospital' },
            { keyword: 'Ganga Hospital Coimbatore', type: 'hospital' },
            { keyword: 'PSG Hospital Coimbatore', type: 'hospital' }
        ];

        let allFacilities = [];

        // Search with each query
        for (const query of searchQueries) {
            try {
                const url = `https://maps.googleapis.com/maps/api/place/nearbysearch/json?` +
                    `location=${latitude},${longitude}&` +
                    `radius=${radiusInMeters}&` +
                    `keyword=${encodeURIComponent(query.keyword)}&` +
                    `type=${query.type}&` +
                    `key=${GOOGLE_PLACES_API_KEY}`;

                console.log(`🔍 Searching: ${query.keyword} (${query.type})`);
                
                const response = await fetch(url);
                const data = await response.json();

                if (data.status === 'OK' && data.results && data.results.length > 0) {
                    console.log(`✅ Found ${data.results.length} results for "${query.keyword}"`);
                    
                    // Transform Google Places results to our format
                    const facilities = data.results.map(place => ({
                        id: place.place_id,
                        name: place.name,
                        type: determineFacilityType(place.name, place.types),
                        address: place.vicinity || 'Address not available',
                        vicinity: place.vicinity,
                        location: {
                            lat: place.geometry.location.lat,
                            lng: place.geometry.location.lng
                        },
                        distance: calculateDistance(latitude, longitude, place.geometry.location.lat, place.geometry.location.lng),
                        distance_text: `${calculateDistance(latitude, longitude, place.geometry.location.lat, place.geometry.location.lng).toFixed(1)} km`,
                        duration: estimateDuration(calculateDistance(latitude, longitude, place.geometry.location.lat, place.geometry.location.lng)),
                        rating: place.rating || 0,
                        user_ratings_total: place.user_ratings_total || 0,
                        business_status: place.business_status || 'OPERATIONAL',
                        opening_hours: place.opening_hours || null,
                        photos: place.photos || [],
                        phone: null, // Would need Place Details API for this
                        website: null, // Would need Place Details API for this
                        services: inferServices(place.name, place.types),
                        specializations: inferSpecializations(place.name),
                        bloodInventory: generateMockBloodInventory(),
                        facilities: inferFacilities(place.types, place.rating),
                        lastUpdated: new Date().toISOString(),
                        reviews: [], // Would need Place Details API for this
                        query_type: query.keyword
                    }));

                    allFacilities.push(...facilities);
                } else {
                    console.log(`❌ No results for "${query.keyword}": ${data.status}`);
                    if (data.error_message) {
                        console.log(`❌ Error: ${data.error_message}`);
                    }
                }
            } catch (error) {
                console.error(`❌ Error searching for "${query.keyword}":`, error.message);
            }
        }

        // Remove duplicates based on place_id
        const uniqueFacilities = Array.from(
            new Map(allFacilities.map(facility => [facility.id, facility])).values()
        );

        // Sort by distance
        const sortedFacilities = uniqueFacilities
            .sort((a, b) => a.distance - b.distance)
            .slice(0, 20); // Limit to 20 results

        console.log(`🎯 Final results: ${sortedFacilities.length} unique facilities`);
        return sortedFacilities;

    } catch (error) {
        console.error('❌ Google Places API error:', error);
        throw error;
    }
};

// Helper functions for Google Places API
const calculateDistance = (lat1, lon1, lat2, lon2) => {
    const R = 6371; // Earth's radius in kilometers
    const dLat = (lat2 - lat1) * Math.PI / 180;
    const dLon = (lon2 - lon1) * Math.PI / 180;
    const a = Math.sin(dLat/2) * Math.sin(dLat/2) +
              Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) *
              Math.sin(dLon/2) * Math.sin(dLon/2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
    return R * c;
};

const estimateDuration = (distanceKm) => {
    const avgSpeedKmh = 30; // Average city driving speed
    const timeHours = distanceKm / avgSpeedKmh;
    const timeMinutes = Math.round(timeHours * 60);
    return `${timeMinutes} mins`;
};

const determineFacilityType = (name, types) => {
    const nameLC = name.toLowerCase();
    if (nameLC.includes('blood bank') || nameLC.includes('red cross')) {
        return 'Blood Bank';
    } else if (nameLC.includes('emergency')) {
        return 'Emergency Service';
    } else if (types.includes('hospital') || nameLC.includes('hospital')) {
        return 'Hospital';
    } else if (nameLC.includes('medical center') || nameLC.includes('clinic')) {
        return 'Medical Complex';
    }
    return 'Medical Facility';
};

const inferServices = (name, types) => {
    const nameLC = name.toLowerCase();
    const services = ['Blood Testing', 'Blood Storage'];
    
    if (nameLC.includes('blood bank') || nameLC.includes('donation')) {
        services.push('Blood Collection', 'Blood Donation');
    }
    if (types.includes('hospital') || nameLC.includes('hospital')) {
        services.push('Emergency Supply', '24/7 Service');
    }
    if (nameLC.includes('emergency')) {
        services.push('Emergency Services');
    }
    
    return services;
};

const inferSpecializations = (name) => {
    const specializations = ['All Blood Types'];
    const nameLC = name.toLowerCase();
    
    if (nameLC.includes('cancer') || nameLC.includes('oncology')) {
        specializations.push('Cancer Care');
    }
    if (nameLC.includes('pediatric') || nameLC.includes('children')) {
        specializations.push('Pediatric Care');
    }
    if (nameLC.includes('cardiac') || nameLC.includes('heart')) {
        specializations.push('Cardiac Care');
    }
    
    return specializations;
};

const inferFacilities = (types, rating) => {
    const facilities = ['Parking Available'];
    
    if (rating >= 4.0) {
        facilities.push('Highly Rated');
    }
    if (types.includes('hospital')) {
        facilities.push('Medical Staff', 'Emergency Services');
    }
    
    return facilities;
};

const generateMockBloodInventory = () => {
    const bloodTypes = ['A+', 'A-', 'B+', 'B-', 'AB+', 'AB-', 'O+', 'O-'];
    const inventory = {};
    
    bloodTypes.forEach(type => {
        inventory[type] = Math.floor(Math.random() * 50) + 10; // 10-60 units
    });
    
    return inventory;
};

// Routes

// Health Check
app.get('/api/health', (req, res) => {
    res.json({ status: 'OK', message: 'Blood Bank API is running' });
});

// Configuration endpoint to provide API keys to frontend
app.get('/api/config', (req, res) => {
    res.json({
        GOOGLE_PLACES_API_KEY: process.env.GOOGLE_PLACES_API_KEY,
        GOOGLE_GEOCODING_API_KEY: process.env.GOOGLE_GEOCODING_API_KEY,
        GOOGLE_DISTANCE_MATRIX_API_KEY: process.env.GOOGLE_DISTANCE_MATRIX_API_KEY,
        GOOGLE_MAPS_API_KEY: process.env.GOOGLE_MAPS_API_KEY
    });
});

// Public endpoint for nearby facilities (no authentication required)
app.get('/api/nearby-facilities', async (req, res) => {
    try {
        const { lat, lng, radius = 5 } = req.query;
        
        if (!lat || !lng) {
            return res.status(400).json({ 
                error: 'Latitude and longitude are required',
                message: 'Please provide lat and lng query parameters'
            });
        }

        const latitude = parseFloat(lat);
        const longitude = parseFloat(lng);
        const searchRadius = parseFloat(radius) * 1000; // Convert km to meters for Google API

        console.log(`🌍 Public API: Searching for facilities near [${latitude}, ${longitude}] within ${radius}km using Google Places API`);
        
        try {
            // Use Google Places API to get real data
            const facilities = await getRealNearbyFacilities(latitude, longitude, searchRadius);
            
            if (facilities && facilities.length > 0) {
                console.log(`✅ Public API: Found ${facilities.length} real facilities via Google Places`);
                res.json({
                    success: true,
                    facilities: facilities,
                    user_location: { latitude, longitude },
                    search_params: { radius: parseFloat(radius), type: 'all' },
                    total_found: facilities.length,
                    is_mock: false,
                    source: 'google_places_api'
                });
            } else {
                throw new Error('No facilities found via Google Places API');
            }
        } catch (googleError) {
            console.error('❌ Google Places API failed:', googleError.message);
            console.log('🔄 Falling back to mock data');
            
            // Fallback to mock data if Google API fails
            const mockFacilities = await getMockNearbyFacilities(latitude, longitude, parseFloat(radius));
            res.json(mockFacilities);
        }
        
    } catch (error) {
        console.error('❌ Public nearby facilities error:', error);
        res.status(500).json({ 
            error: 'Failed to fetch nearby facilities',
            message: error.message 
        });
    }
});

// Network test endpoint for React Native
app.get('/api/network-test', (req, res) => {
    console.log('🔍 Network test request received from:', req.ip, req.headers['user-agent']);
    res.json({ 
        status: 'SUCCESS', 
        message: 'React Native connection successful!',
        timestamp: new Date().toISOString(),
        clientIP: req.ip,
        headers: req.headers
    });
});

app.post('/api/network-test', (req, res) => {
    console.log('🔍 POST Network test request received from:', req.ip);
    console.log('🔍 Request body:', req.body);
    res.json({ 
        status: 'SUCCESS', 
        message: 'React Native POST connection successful!',
        timestamp: new Date().toISOString(),
        receivedData: req.body
    });
});

// Donor Eligibility Check
app.get('/api/donor/eligibility', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        
        // Get user details
        const { data: user, error: userError } = await supabase
            .from('users')
            .select('*')
            .eq('id', userId)
            .single();

        if (userError || !user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Check basic eligibility criteria
        const eligibilityChecks = {
            age: user.age >= 18 && user.age <= 65,
            bloodGroup: user.blood_group ? true : false,
            isActive: user.is_active
        };

        console.log('User data for eligibility check:', {
            id: user.id,
            age: user.age,
            blood_group: user.blood_group,
            is_active: user.is_active,
            user_type: user.user_type
        });
        console.log('Eligibility checks:', eligibilityChecks);

        // Get last donation date
        const { data: lastDonation } = await supabase
            .from('donations')
            .select('donation_date')
            .eq('donor_id', userId)
            .eq('status', 'completed')
            .order('donation_date', { ascending: false })
            .limit(1);

        let daysSinceLastDonation = null;
        let canDonateDate = new Date();
        
        if (lastDonation && lastDonation.length > 0) {
            const lastDonationDate = new Date(lastDonation[0].donation_date);
            const today = new Date();
            daysSinceLastDonation = Math.floor((today - lastDonationDate) / (1000 * 60 * 60 * 24));
            
            // Minimum 56 days (8 weeks) between donations
            if (daysSinceLastDonation < 56) {
                canDonateDate = new Date(lastDonationDate);
                canDonateDate.setDate(canDonateDate.getDate() + 56);
                eligibilityChecks.timeSinceLastDonation = false;
            } else {
                eligibilityChecks.timeSinceLastDonation = true;
            }
        } else {
            eligibilityChecks.timeSinceLastDonation = true; // First time donor
        }

        const isEligible = Object.values(eligibilityChecks).every(check => check === true);

        res.json({
            eligible: isEligible,
            checks: eligibilityChecks,
            daysSinceLastDonation,
            canDonateDate: canDonateDate.toISOString().split('T')[0],
            message: isEligible ? 'You are eligible to donate!' : 'Please check eligibility requirements'
        });

    } catch (error) {
        console.error('Eligibility check error:', error);
        res.status(500).json({ error: 'Failed to check eligibility' });
    }
});

// Get Available Donation Centers
// Get donation centers (public endpoint)
app.get('/api/donation-centers', async (req, res) => {
    try {
        // For now, return static data. In production, this would come from database
        const centers = [
            {
                id: 1,
                name: 'City Blood Bank',
                address: '123 Main Street, City Center',
                phone: '+1234567890',
                workingHours: '9:00 AM - 6:00 PM',
                availableSlots: ['10:00 AM', '11:00 AM', '2:00 PM', '3:00 PM', '4:00 PM']
            },
            {
                id: 2,
                name: 'General Hospital Blood Center',
                address: '456 Hospital Road, Medical District',
                phone: '+1234567891',
                workingHours: '8:00 AM - 8:00 PM',
                availableSlots: ['9:00 AM', '10:00 AM', '1:00 PM', '2:00 PM', '5:00 PM']
            },
            {
                id: 3,
                name: 'Community Health Center',
                address: '789 Community Blvd, Suburb',
                phone: '+1234567892',
                workingHours: '10:00 AM - 5:00 PM',
                availableSlots: ['11:00 AM', '12:00 PM', '3:00 PM', '4:00 PM']
            }
        ];

        res.json({ centers });
    } catch (error) {
        console.error('Error fetching donation centers:', error);
        res.status(500).json({ error: 'Failed to fetch donation centers' });
    }
});

// User Registration
app.post('/api/register', async (req, res) => {
    try {
        const { 
            email, 
            password, 
            user_type, 
            full_name, 
            phone, 
            blood_group, 
            age, 
            address,
            emergency_contact,
            medical_conditions 
        } = req.body;

        // Validate required fields
        if (!email || !password || !user_type || !full_name) {
            return res.status(400).json({ 
                error: 'Email, password, user type, and full name are required' 
            });
        }

        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ error: 'Invalid email format' });
        }

        // Validate user type
        if (!['admin', 'donor', 'recipient'].includes(user_type)) {
            return res.status(400).json({ 
                error: 'User type must be admin, donor, or recipient' 
            });
        }

        // Check if user already exists
        const { data: existingUser } = await supabase
            .from('users')
            .select('email, user_type, full_name')
            .eq('email', email.toLowerCase())
            .single();

        if (existingUser) {
            return res.status(400).json({ 
                error: 'Account already exists',
                message: `An account with email ${email} is already registered as ${existingUser.user_type}. Please use the login option or use a different email address.`,
                suggestion: 'Try logging in instead or contact support if you forgot your password.'
            });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert user into Supabase
        const { data, error } = await supabase
            .from('users')
            .insert([
                {
                    email: email.toLowerCase(),
                    password: hashedPassword,
                    user_type,
                    full_name,
                    phone: phone || null,
                    blood_group: blood_group || null,
                    age: age ? parseInt(age) : null,
                    address: address || null,
                    emergency_contact: emergency_contact || null,
                    medical_conditions: medical_conditions || null,
                    is_active: true,
                    created_at: new Date().toISOString()
                }
            ])
            .select()
            .single();

        if (error) {
            console.error('Supabase error:', error);
            return res.status(400).json({ error: error.message });
        }

        // Generate token
        const token = generateToken(data);

        // Remove password from response
        const { password: _, ...userWithoutPassword } = data;

        res.status(201).json({
            message: 'User registered successfully',
            user: userWithoutPassword,
            token
        });

    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// User Login
app.post('/api/login', async (req, res) => {
    try {
        const { email, password, user_type } = req.body;

        if (!email || !password || !user_type) {
            return res.status(400).json({ 
                error: 'Email, password, and user type are required' 
            });
        }

        // Validate user type
        if (!['admin', 'donor', 'recipient'].includes(user_type)) {
            return res.status(400).json({ 
                error: 'Invalid user type' 
            });
        }

        // Get user from Supabase
        const { data: user, error } = await supabase
            .from('users')
            .select('*')
            .eq('email', email.toLowerCase())
            .eq('user_type', user_type)
            .eq('is_active', true)
            .single();

        console.log('✅ Login attempt for:', { email: email.toLowerCase(), user_type });
        
        if (error || !user) {
            console.log('❌ Database error:', error?.message || 'User not found');
            if (error && error.code === 'PGRST116') {
                return res.status(401).json({ 
                    error: 'User not found', 
                    message: `No ${user_type} account found with email ${email}. Please check your email or register first.` 
                });
            }
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        console.log('✅ User found:', user.full_name || user.email);

        // Verify password
        const isValidPassword = await bcrypt.compare(password, user.password);
        console.log('🔐 Password verification:', isValidPassword ? '✅ Valid' : '❌ Invalid');
        
        if (!isValidPassword) {
            return res.status(401).json({ 
                error: 'Invalid password', 
                message: 'The password you entered is incorrect. Please try again.' 
            });
        }

        // Generate token
        const token = generateToken(user);

        // Remove password from response
        const { password: _, ...userWithoutPassword } = user;

        res.json({
            message: 'Login successful',
            user: userWithoutPassword,
            token
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get User Profile
app.get('/api/profile', authenticateToken, async (req, res) => {
    try {
        const { data: user, error } = await supabase
            .from('users')
            .select('id, email, user_type, full_name, phone, blood_group, age, address, emergency_contact, medical_conditions, created_at')
            .eq('id', req.user.id)
            .single();

        if (error) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json({ user });
    } catch (error) {
        console.error('Profile error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Update User Profile
app.put('/api/profile', authenticateToken, async (req, res) => {
    try {
        const { 
            full_name, 
            phone, 
            blood_group, 
            age, 
            address,
            emergency_contact,
            medical_conditions 
        } = req.body;

        const { data, error } = await supabase
            .from('users')
            .update({
                full_name,
                phone,
                blood_group,
                age,
                address,
                emergency_contact,
                medical_conditions,
                updated_at: new Date().toISOString()
            })
            .eq('id', req.user.id)
            .select()
            .single();

        if (error) {
            return res.status(400).json({ error: error.message });
        }

        const { password: _, ...userWithoutPassword } = data;
        res.json({ 
            message: 'Profile updated successfully', 
            user: userWithoutPassword 
        });

    } catch (error) {
        console.error('Profile update error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Enhanced: Get recipient dashboard stats with blood availability
app.get('/api/recipient/dashboard', authenticateToken, async (req, res) => {
    try {
        if (req.user.user_type !== 'recipient') {
            return res.status(403).json({ error: 'Access denied. Recipients only.' });
        }

        const { data: recipient, error: recipientError } = await supabase
            .from('users')
            .select('*')
            .eq('id', req.user.id)
            .single();

        if (recipientError || !recipient) {
            return res.status(404).json({ error: 'Recipient not found' });
        }

        // Get recipient's blood requests
        const { data: requests, error: requestsError } = await supabase
            .from('blood_requests')
            .select(`
                *,
                users!blood_requests_recipient_id_fkey(full_name, phone, email)
            `)
            .eq('recipient_id', req.user.id)
            .order('created_at', { ascending: false });

        // Get blood availability for recipient's blood group and compatible types
        const compatibleBloodTypes = getCompatibleBloodTypes(recipient.blood_group);
        const { data: bloodInventory, error: inventoryError } = await supabase
            .from('blood_inventory')
            .select('*')
            .in('blood_group', compatibleBloodTypes)
            .gt('units_available', 0);

        // Calculate stats
        const totalRequests = requests?.length || 0;
        const pendingRequests = requests?.filter(r => r.status === 'pending').length || 0;
        const fulfilledRequests = requests?.filter(r => r.status === 'fulfilled').length || 0;
        const urgentRequests = requests?.filter(r => r.urgency_level === 'critical').length || 0;

        const totalAvailableUnits = bloodInventory?.reduce((sum, item) => sum + item.units_available, 0) || 0;
        const criticalStock = bloodInventory?.filter(item => item.units_available < 10).length || 0;

        const stats = {
            recipient_profile: {
                id: recipient.id,
                full_name: recipient.full_name,
                blood_group: recipient.blood_group,
                medical_conditions: recipient.medical_conditions,
                emergency_contact: recipient.emergency_contact
            },
            request_summary: {
                total_requests: totalRequests,
                pending_requests: pendingRequests,
                fulfilled_requests: fulfilledRequests,
                urgent_requests: urgentRequests,
                success_rate: totalRequests > 0 ? Math.round((fulfilledRequests / totalRequests) * 100) : 0
            },
            blood_availability: {
                compatible_types: compatibleBloodTypes,
                total_available_units: totalAvailableUnits,
                critical_stock_types: criticalStock,
                inventory_by_type: bloodInventory?.map(item => ({
                    blood_group: item.blood_group,
                    units_available: item.units_available,
                    status: item.units_available < 5 ? 'critical' : 
                           item.units_available < 15 ? 'low' : 'available',
                    last_updated: item.last_updated
                })) || []
            },
            recent_requests: requests?.slice(0, 5) || []
        };

        console.log(`✅ Recipient dashboard loaded for: ${recipient.full_name}`);
        res.json({ success: true, stats });
    } catch (error) {
        console.error('Get recipient dashboard error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Enhanced: Create blood request with smart matching algorithm
app.post('/api/recipient/create-request', authenticateToken, async (req, res) => {
    try {
        if (req.user.user_type !== 'recipient') {
            return res.status(403).json({ error: 'Only recipients can create blood requests' });
        }

        const { 
            blood_group_needed,
            units_needed,
            urgency_level,
            medical_reason,
            hospital_name,
            hospital_address,
            doctor_name,
            doctor_contact,
            required_by_date,
            special_requirements,
            patient_condition
        } = req.body;

        // Validate required fields
        if (!blood_group_needed || !units_needed || !urgency_level || !medical_reason || !hospital_name) {
            return res.status(400).json({ 
                error: 'Missing required fields',
                required: ['blood_group_needed', 'units_needed', 'urgency_level', 'medical_reason', 'hospital_name']
            });
        }

        // Check blood availability
        const { data: availableBlood, error: availabilityError } = await supabase
            .from('blood_inventory')
            .select('*')
            .eq('blood_group', blood_group_needed)
            .gte('units_available', units_needed)
            .eq('status', 'available');

        const canFulfillImmediately = availableBlood && availableBlood.length > 0;

        // Create blood request
        const requestData = {
            recipient_id: req.user.id,
            blood_group_needed,
            units_needed: parseInt(units_needed),
            urgency_level, // critical, urgent, routine
            medical_reason,
            hospital_name,
            hospital_address,
            doctor_name,
            doctor_contact,
            required_by_date,
            special_requirements,
            patient_condition,
            status: canFulfillImmediately && urgency_level === 'critical' ? 'processing' : 'pending',
            can_fulfill_immediately: canFulfillImmediately,
            created_at: new Date().toISOString(),
            estimated_fulfillment: calculateEstimatedFulfillment(urgency_level, canFulfillImmediately)
        };

        const { data: newRequest, error: requestError } = await supabase
            .from('blood_requests')
            .insert([requestData])
            .select()
            .single();

        if (requestError) {
            console.error('Create blood request error:', requestError);
            return res.status(500).json({ error: 'Failed to create blood request' });
        }

        // If critical and blood available, notify admin immediately
        if (urgency_level === 'critical' && canFulfillImmediately) {
            // Auto-notify admin (in production, this would send real notifications)
            console.log(`🚨 CRITICAL REQUEST CREATED: ${newRequest.id} - ${blood_group_needed}, ${units_needed} units`);
        }

        // Find compatible donors to notify
        const { data: compatibleDonors, error: donorError } = await supabase
            .from('users')
            .select('id, full_name, email, blood_group, phone')
            .eq('user_type', 'donor')
            .eq('blood_group', blood_group_needed)
            .eq('is_active', true);

        res.json({
            success: true,
            message: 'Blood request created successfully',
            request: newRequest,
            blood_availability: {
                can_fulfill_immediately: canFulfillImmediately,
                available_units: availableBlood?.reduce((sum, item) => sum + item.units_available, 0) || 0,
                estimated_fulfillment: requestData.estimated_fulfillment
            },
            compatible_donors_found: compatibleDonors?.length || 0
        });

    } catch (error) {
        console.error('Create blood request error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Enhanced: Get blood availability with smart recommendations
app.get('/api/recipient/blood-availability/:bloodGroup', authenticateToken, async (req, res) => {
    try {
        if (req.user.user_type !== 'recipient') {
            return res.status(403).json({ error: 'Access denied. Recipients only.' });
        }

        const { bloodGroup } = req.params;
        const compatibleTypes = getCompatibleBloodTypes(bloodGroup);

        // Get current inventory
        const { data: inventory, error: inventoryError } = await supabase
            .from('blood_inventory')
            .select('*')
            .in('blood_group', compatibleTypes)
            .order('units_available', { ascending: false });

        // Get recent donation patterns
        const { data: recentDonations, error: donationsError } = await supabase
            .from('pending_donations')
            .select('blood_group, units_donated, created_at, status')
            .in('blood_group', compatibleTypes)
            .gte('created_at', new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString()) // Last 7 days
            .order('created_at', { ascending: false });

        // Calculate availability metrics
        const totalUnits = inventory?.reduce((sum, item) => sum + item.units_available, 0) || 0;
        const criticalTypes = inventory?.filter(item => item.units_available < 5).map(item => item.blood_group) || [];
        const lowTypes = inventory?.filter(item => item.units_available < 15 && item.units_available >= 5).map(item => item.blood_group) || [];

        // Generate smart recommendations
        const recommendations = [];
        if (criticalTypes.includes(bloodGroup)) {
            recommendations.push({
                type: 'urgent',
                message: `${bloodGroup} blood is critically low. Consider requesting alternative compatible types.`,
                alternatives: compatibleTypes.filter(type => type !== bloodGroup && !criticalTypes.includes(type))
            });
        }

        if (totalUnits < 10) {
            recommendations.push({
                type: 'planning',
                message: 'Low overall availability. Plan requests in advance and consider scheduling.',
                suggestion: 'Schedule non-urgent requests for later dates'
            });
        }

        res.json({
            success: true,
            blood_availability: {
                requested_type: bloodGroup,
                compatible_types: compatibleTypes,
                total_available_units: totalUnits,
                inventory_details: inventory?.map(item => ({
                    blood_group: item.blood_group,
                    units_available: item.units_available,
                    status: item.units_available < 5 ? 'critical' : 
                           item.units_available < 15 ? 'low' : 'available',
                    last_updated: item.last_updated,
                    expiry_date: item.expiry_date,
                    location: item.location
                })) || [],
                critical_types: criticalTypes,
                low_stock_types: lowTypes,
                recent_donations: recentDonations?.length || 0,
                recommendations
            }
        });

    } catch (error) {
        console.error('Get blood availability error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Enhanced: Get recipient request history with detailed tracking
app.get('/api/recipient/request-history', authenticateToken, async (req, res) => {
    try {
        if (req.user.user_type !== 'recipient') {
            return res.status(403).json({ error: 'Access denied. Recipients only.' });
        }

        const { page = 1, limit = 10, status = 'all' } = req.query;
        const offset = (page - 1) * limit;

        let query = supabase
            .from('blood_requests')
            .select(`
                *,
                users!blood_requests_recipient_id_fkey(full_name, phone, email)
            `)
            .eq('recipient_id', req.user.id)
            .order('created_at', { ascending: false })
            .range(offset, offset + limit - 1);

        if (status !== 'all') {
            query = query.eq('status', status);
        }

        const { data: requests, error: requestsError } = await query;

        // Get total count for pagination
        let countQuery = supabase
            .from('blood_requests')
            .select('id', { count: 'exact' })
            .eq('recipient_id', req.user.id);

        if (status !== 'all') {
            countQuery = countQuery.eq('status', status);
        }

        const { count, error: countError } = await countQuery;

        const totalPages = Math.ceil((count || 0) / limit);

        res.json({
            success: true,
            requests: requests || [],
            pagination: {
                current_page: parseInt(page),
                total_pages: totalPages,
                total_requests: count || 0,
                requests_per_page: parseInt(limit)
            },
            summary: {
                total_requests: count || 0,
                pending: requests?.filter(r => r.status === 'pending').length || 0,
                processing: requests?.filter(r => r.status === 'processing').length || 0,
                fulfilled: requests?.filter(r => r.status === 'fulfilled').length || 0,
                cancelled: requests?.filter(r => r.status === 'cancelled').length || 0
            }
        });

    } catch (error) {
        console.error('Get recipient request history error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Cancel blood request endpoint
app.post('/api/recipient/cancel-request/:requestId', authenticateToken, async (req, res) => {
    try {
        if (req.user.user_type !== 'recipient') {
            return res.status(403).json({ error: 'Access denied. Recipients only.' });
        }

        const { requestId } = req.params;
        const { reason = 'Cancelled by recipient' } = req.body;

        // First check if the request exists and belongs to the user
        const { data: existingRequest, error: fetchError } = await supabase
            .from('blood_requests')
            .select('*')
            .eq('id', requestId)
            .eq('recipient_id', req.user.id)
            .single();

        if (fetchError || !existingRequest) {
            return res.status(404).json({ 
                success: false, 
                error: 'Request not found or access denied' 
            });
        }

        // Check if request can be cancelled (only pending or approved requests)
        if (!['pending', 'approved'].includes(existingRequest.status)) {
            return res.status(400).json({ 
                success: false, 
                error: `Cannot cancel ${existingRequest.status} requests` 
            });
        }

        // Update the request status to cancelled
        const { data: updatedRequest, error: updateError } = await supabase
            .from('blood_requests')
            .update({ 
                status: 'cancelled',
                admin_notes: `Request cancelled by recipient. Reason: ${reason}`,
                updated_at: new Date().toISOString()
            })
            .eq('id', requestId)
            .eq('recipient_id', req.user.id)
            .select()
            .single();

        if (updateError) {
            console.error('Cancel request error:', updateError);
            return res.status(500).json({ 
                success: false, 
                error: 'Failed to cancel request' 
            });
        }

        res.json({
            success: true,
            message: 'Request cancelled successfully',
            request: updatedRequest,
            cancellation: {
                cancelled_at: new Date().toISOString(),
                reason: reason,
                previous_status: existingRequest.status
            }
        });

    } catch (error) {
        console.error('Cancel blood request error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Internal server error' 
        });
    }
});

// Update request urgency endpoint
app.post('/api/recipient/update-urgency/:requestId', authenticateToken, async (req, res) => {
    try {
        if (req.user.user_type !== 'recipient') {
            return res.status(403).json({ error: 'Access denied. Recipients only.' });
        }

        const { requestId } = req.params;
        const { urgency_level, additional_info = '' } = req.body;

        // Validate urgency level
        if (!['routine', 'urgent', 'critical'].includes(urgency_level)) {
            return res.status(400).json({ 
                success: false, 
                error: 'Invalid urgency level' 
            });
        }

        // Check if the request exists and belongs to the user
        const { data: existingRequest, error: fetchError } = await supabase
            .from('blood_requests')
            .select('*')
            .eq('id', requestId)
            .eq('recipient_id', req.user.id)
            .single();

        if (fetchError || !existingRequest) {
            return res.status(404).json({ 
                success: false, 
                error: 'Request not found or access denied' 
            });
        }

        // Check if request can be updated (only pending or approved requests)
        if (!['pending', 'approved'].includes(existingRequest.status)) {
            return res.status(400).json({ 
                success: false, 
                error: `Cannot update ${existingRequest.status} requests` 
            });
        }

        // Update the request urgency
        const { data: updatedRequest, error: updateError } = await supabase
            .from('blood_requests')
            .update({ 
                urgency_level: urgency_level,
                special_requirements: additional_info ? 
                    `${existingRequest.special_requirements || ''}\n\nUrgency Update: ${additional_info}`.trim() :
                    existingRequest.special_requirements,
                updated_at: new Date().toISOString()
            })
            .eq('id', requestId)
            .eq('recipient_id', req.user.id)
            .select()
            .single();

        if (updateError) {
            console.error('Update urgency error:', updateError);
            return res.status(500).json({ 
                success: false, 
                error: 'Failed to update request urgency' 
            });
        }

        res.json({
            success: true,
            message: 'Request urgency updated successfully',
            request: updatedRequest,
            update: {
                previous_urgency: existingRequest.urgency_level,
                new_urgency: urgency_level,
                updated_at: new Date().toISOString(),
                additional_info: additional_info
            }
        });

    } catch (error) {
        console.error('Update request urgency error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Internal server error' 
        });
    }
});

// Enhanced: Find nearby blood facilities using Google Places API
app.get('/api/recipient/nearby-facilities', authenticateToken, async (req, res) => {
    try {
        const { 
            latitude, 
            longitude, 
            radius = 5000, 
            type = 'all',
            search_query = ''
        } = req.query;

        if (!latitude || !longitude) {
            return res.status(400).json({ 
                success: false, 
                error: 'Location coordinates are required' 
            });
        }

        // Google Places API configuration
        const GOOGLE_PLACES_API_KEY = process.env.GOOGLE_PLACES_API_KEY;
        const GOOGLE_DISTANCE_MATRIX_API_KEY = process.env.GOOGLE_DISTANCE_MATRIX_API_KEY;

        if (!GOOGLE_PLACES_API_KEY) {
            console.log('Google Places API key not found, using mock data');
            return res.json(await getMockNearbyFacilities(latitude, longitude, radius));
        }

        const queries = [
            'blood bank',
            'hospital blood bank',
            'blood donation center',
            'medical center blood bank',
            'red cross blood center',
            'government blood bank'
        ];

        let allFacilities = [];

        // Search for each query type
        for (const query of queries) {
            try {
                const placesUrl = `https://maps.googleapis.com/maps/api/place/nearbysearch/json?` +
                    `location=${latitude},${longitude}&` +
                    `radius=${radius}&` +
                    `keyword=${encodeURIComponent(query)}&` +
                    `type=hospital&` +
                    `key=${GOOGLE_PLACES_API_KEY}`;

                const response = await fetch(placesUrl);
                const data = await response.json();

                if (data.status === 'OK' && data.results) {
                    const facilities = data.results.map(place => ({
                        id: place.place_id,
                        name: place.name,
                        vicinity: place.vicinity,
                        location: place.geometry.location,
                        rating: place.rating || 0,
                        user_ratings_total: place.user_ratings_total || 0,
                        types: place.types || [],
                        business_status: place.business_status,
                        price_level: place.price_level,
                        photos: place.photos || [],
                        query_type: query,
                        distance: null
                    }));
                    
                    allFacilities.push(...facilities);
                }
            } catch (error) {
                console.error(`Error searching for ${query}:`, error);
            }
        }

        // Remove duplicates based on place_id
        const uniqueFacilities = Array.from(
            new Map(allFacilities.map(facility => [facility.id, facility])).values()
        );

        // Calculate distances using Distance Matrix API
        const facilitiesWithDistance = await calculateDistancesGoogle(
            { latitude: parseFloat(latitude), longitude: parseFloat(longitude) },
            uniqueFacilities,
            GOOGLE_DISTANCE_MATRIX_API_KEY
        );

        // Sort by distance and limit results
        const sortedFacilities = facilitiesWithDistance
            .sort((a, b) => (a.distance || Infinity) - (b.distance || Infinity))
            .slice(0, 20);

        // Get detailed information for facilities
        const detailedFacilities = await getDetailedFacilityInfoGoogle(
            sortedFacilities,
            GOOGLE_PLACES_API_KEY
        );

        // Filter by type if specified
        let filteredFacilities = detailedFacilities;
        if (type !== 'all') {
            filteredFacilities = detailedFacilities.filter(facility => 
                facility.type === type
            );
        }

        // Filter by search query if provided
        if (search_query.trim()) {
            const query = search_query.toLowerCase();
            filteredFacilities = filteredFacilities.filter(facility =>
                facility.name.toLowerCase().includes(query) ||
                facility.address?.toLowerCase().includes(query) ||
                facility.services?.some(service => service.toLowerCase().includes(query))
            );
        }

        res.json({
            success: true,
            facilities: filteredFacilities,
            user_location: {
                latitude: parseFloat(latitude),
                longitude: parseFloat(longitude)
            },
            search_params: {
                radius: parseInt(radius),
                type: type,
                search_query: search_query
            },
            total_found: uniqueFacilities.length,
            filtered_count: filteredFacilities.length
        });

    } catch (error) {
        console.error('Nearby facilities search error:', error);
        
        // Fallback to mock data on error
        try {
            const mockData = await getMockNearbyFacilities(
                req.query.latitude, 
                req.query.longitude, 
                req.query.radius || 5000
            );
            res.json({
                ...mockData,
                fallback: true,
                error_message: 'Using fallback data due to API error'
            });
        } catch (fallbackError) {
            res.status(500).json({ 
                success: false, 
                error: 'Failed to find nearby facilities',
                details: error.message
            });
        }
    }
});

// Helper function to calculate distances using Google Distance Matrix API
async function calculateDistancesGoogle(origin, destinations, apiKey) {
    if (!destinations.length || !apiKey) {
        return destinations.map(facility => ({
            ...facility,
            distance: calculateStraightLineDistance(origin, facility.location),
            duration: 'Unknown',
            distance_text: `${calculateStraightLineDistance(origin, facility.location).toFixed(1)} km`
        }));
    }

    const batchSize = 10;
    let results = [];

    for (let i = 0; i < destinations.length; i += batchSize) {
        const batch = destinations.slice(i, i + batchSize);
        const destinationsString = batch
            .map(dest => `${dest.location.lat},${dest.location.lng}`)
            .join('|');

        try {
            const distanceUrl = `https://maps.googleapis.com/maps/api/distancematrix/json?` +
                `origins=${origin.latitude},${origin.longitude}&` +
                `destinations=${destinationsString}&` +
                `units=metric&` +
                `mode=driving&` +
                `key=${apiKey}`;

            const response = await fetch(distanceUrl);
            const data = await response.json();

            if (data.status === 'OK' && data.rows[0]) {
                const elements = data.rows[0].elements;
                const batchResults = batch.map((facility, index) => {
                    const element = elements[index];
                    
                    return {
                        ...facility,
                        distance: element.status === 'OK' ? 
                            element.distance.value / 1000 :
                            calculateStraightLineDistance(origin, facility.location),
                        duration: element.status === 'OK' ? 
                            element.duration.text : 
                            'Unknown',
                        distance_text: element.status === 'OK' ?
                            element.distance.text :
                            `${calculateStraightLineDistance(origin, facility.location).toFixed(1)} km`
                    };
                });

                results.push(...batchResults);
            } else {
                // Fallback to straight-line distance
                results.push(...batch.map(facility => ({
                    ...facility,
                    distance: calculateStraightLineDistance(origin, facility.location),
                    duration: 'Unknown',
                    distance_text: `${calculateStraightLineDistance(origin, facility.location).toFixed(1)} km`
                })));
            }
        } catch (error) {
            console.error('Distance calculation error for batch:', error);
            results.push(...batch.map(facility => ({
                ...facility,
                distance: calculateStraightLineDistance(origin, facility.location),
                duration: 'Unknown',
                distance_text: `${calculateStraightLineDistance(origin, facility.location).toFixed(1)} km`
            })));
        }
    }

    return results;
}

// Helper function to get detailed facility information
async function getDetailedFacilityInfoGoogle(facilities, apiKey) {
    const detailedFacilities = [];

    for (const facility of facilities.slice(0, 15)) { // Limit API calls
        try {
            if (!apiKey) {
                // Add basic mock details
                detailedFacilities.push({
                    ...facility,
                    address: facility.vicinity,
                    phone: null,
                    website: null,
                    opening_hours: null,
                    type: determineFacilityTypeFromName(facility),
                    services: inferServicesFromName(facility),
                    specializations: ['All Blood Types'],
                    bloodInventory: generateMockBloodInventory(),
                    facilities: ['Basic Services'],
                    lastUpdated: new Date().toISOString()
                });
                continue;
            }

            const detailsUrl = `https://maps.googleapis.com/maps/api/place/details/json?` +
                `place_id=${facility.id}&` +
                `fields=name,formatted_address,formatted_phone_number,website,opening_hours,photos,reviews&` +
                `key=${apiKey}`;

            const response = await fetch(detailsUrl);
            const data = await response.json();

            if (data.status === 'OK' && data.result) {
                const details = data.result;
                
                detailedFacilities.push({
                    ...facility,
                    address: details.formatted_address || facility.vicinity,
                    phone: details.formatted_phone_number || null,
                    website: details.website || null,
                    opening_hours: details.opening_hours || null,
                    photos: details.photos || facility.photos,
                    reviews: details.reviews || [],
                    type: determineFacilityTypeFromName(facility),
                    services: inferServicesFromName(facility),
                    specializations: inferSpecializationsFromName(facility),
                    bloodInventory: generateMockBloodInventory(),
                    facilities: inferFacilitiesFromRating(facility),
                    lastUpdated: new Date().toISOString()
                });
            } else {
                detailedFacilities.push({
                    ...facility,
                    address: facility.vicinity,
                    phone: null,
                    website: null,
                    opening_hours: null,
                    type: determineFacilityTypeFromName(facility),
                    services: inferServicesFromName(facility),
                    specializations: ['All Blood Types'],
                    bloodInventory: generateMockBloodInventory(),
                    facilities: ['Basic Services'],
                    lastUpdated: new Date().toISOString()
                });
            }
        } catch (error) {
            console.error(`Error getting details for ${facility.name}:`, error);
            detailedFacilities.push({
                ...facility,
                address: facility.vicinity,
                type: determineFacilityTypeFromName(facility),
                services: inferServicesFromName(facility),
                bloodInventory: generateMockBloodInventory(),
                lastUpdated: new Date().toISOString()
            });
        }

        // Small delay to respect API limits
        await new Promise(resolve => setTimeout(resolve, 100));
    }

    return detailedFacilities;
}

// Helper functions for facility classification
function determineFacilityTypeFromName(facility) {
    const name = facility.name.toLowerCase();
    const types = facility.types || [];
    
    if (name.includes('red cross') || name.includes('blood bank')) {
        return 'Blood Bank';
    } else if (name.includes('emergency') || types.includes('emergency')) {
        return 'Emergency Service';
    } else if (types.includes('hospital')) {
        return 'Hospital';
    } else if (name.includes('medical center') || name.includes('clinic')) {
        return 'Medical Complex';
    } else if (name.includes('community') || name.includes('ngo')) {
        return 'NGO Blood Bank';
    }
    return 'Medical Facility';
}

function inferServicesFromName(facility) {
    const name = facility.name.toLowerCase();
    const baseServices = ['Blood Testing', 'Blood Storage'];
    
    if (name.includes('donation') || name.includes('blood bank')) {
        baseServices.push('Blood Collection', 'Blood Donation');
    }
    if (name.includes('emergency') || name.includes('hospital')) {
        baseServices.push('Emergency Supply', '24/7 Service');
    }
    if (name.includes('mobile') || name.includes('camp')) {
        baseServices.push('Mobile Blood Drive', 'Community Outreach');
    }
    
    return baseServices;
}

function inferSpecializationsFromName(facility) {
    const name = facility.name.toLowerCase();
    const specializations = ['All Blood Types'];
    
    if (name.includes('plasma')) specializations.push('Plasma');
    if (name.includes('platelet')) specializations.push('Platelets');
    if (name.includes('pediatric') || name.includes('children')) specializations.push('Pediatric');
    if (name.includes('research')) specializations.push('Research');
    
    return specializations;
}

function inferFacilitiesFromRating(facility) {
    const baseFacilities = ['Parking Available'];
    const rating = facility.rating || 0;
    
    if (rating >= 4.0) baseFacilities.push('Highly Rated', 'Quality Service');
    if (facility.types?.includes('hospital')) baseFacilities.push('Medical Staff', 'Emergency Services');
    
    return baseFacilities;
}

// Helper function for straight-line distance calculation
function calculateStraightLineDistance(origin, destination) {
    const R = 6371; // Earth's radius in kilometers
    const dLat = toRadians(destination.lat - origin.latitude);
    const dLon = toRadians(destination.lng - origin.longitude);
    
    const a = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
              Math.cos(toRadians(origin.latitude)) * 
              Math.cos(toRadians(destination.lat)) *
              Math.sin(dLon / 2) * Math.sin(dLon / 2);
    
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
    return R * c;
}

function toRadians(degrees) {
    return degrees * (Math.PI / 180);
}

// Mock data generator for fallback
async function getMockNearbyFacilities(latitude, longitude, radius) {
    const mockFacilities = [
        {
            id: 'mock_1',
            name: 'City General Hospital Blood Bank',
            type: 'Hospital',
            address: '123 Medical Center Drive, Downtown',
            vicinity: 'Medical Center Drive',
            distance: 0.8,
            distance_text: '0.8 km',
            duration: '3 mins',
            phone: '+91-98765-43210',
            website: 'https://citygeneral.com',
            rating: 4.8,
            user_ratings_total: 245,
            opening_hours: {
                open_now: true,
                weekday_text: [
                    'Monday: 24 hours', 'Tuesday: 24 hours', 'Wednesday: 24 hours',
                    'Thursday: 24 hours', 'Friday: 24 hours', 'Saturday: 24 hours', 'Sunday: 24 hours'
                ]
            },
            services: ['Blood Collection', 'Blood Testing', 'Emergency Supply', '24/7 Service'],
            specializations: ['All Blood Types', 'Platelets', 'Plasma'],
            bloodInventory: generateMockBloodInventory(),
            facilities: ['Parking Available', 'Wheelchair Accessible', 'Emergency Services'],
            lastUpdated: new Date().toISOString(),
            location: { lat: parseFloat(latitude) + 0.01, lng: parseFloat(longitude) + 0.01 }
        },
        {
            id: 'mock_2',
            name: 'Red Cross Blood Center',
            type: 'Blood Bank',
            address: '456 Charity Road, Central District',
            vicinity: 'Charity Road',
            distance: 1.2,
            distance_text: '1.2 km',
            duration: '4 mins',
            phone: '+91-98765-43211',
            website: 'https://redcross.org',
            rating: 4.9,
            user_ratings_total: 189,
            opening_hours: {
                open_now: true,
                weekday_text: [
                    'Monday: 6:00 AM – 10:00 PM', 'Tuesday: 6:00 AM – 10:00 PM',
                    'Wednesday: 6:00 AM – 10:00 PM', 'Thursday: 6:00 AM – 10:00 PM',
                    'Friday: 6:00 AM – 10:00 PM', 'Saturday: 8:00 AM – 8:00 PM', 'Sunday: 8:00 AM – 6:00 PM'
                ]
            },
            services: ['Blood Donation', 'Blood Storage', 'Mobile Blood Drive', 'Community Outreach'],
            specializations: ['Rare Blood Types', 'Autologous Donation'],
            bloodInventory: generateMockBloodInventory(),
            facilities: ['Air Conditioned', 'Refreshment Area', 'Free Parking'],
            lastUpdated: new Date().toISOString(),
            location: { lat: parseFloat(latitude) - 0.01, lng: parseFloat(longitude) + 0.015 }
        }
    ];

    return {
        success: true,
        facilities: mockFacilities,
        user_location: {
            latitude: parseFloat(latitude),
            longitude: parseFloat(longitude)
        },
        search_params: {
            radius: parseInt(radius),
            type: 'all'
        },
        total_found: mockFacilities.length,
        is_mock: true
    };
}

// Helper function to calculate estimated fulfillment time
function calculateEstimatedFulfillment(urgencyLevel, canFulfillImmediately) {
    if (canFulfillImmediately && urgencyLevel === 'critical') {
        return 'Within 2 hours';
    } else if (urgencyLevel === 'critical') {
        return 'Within 24 hours';
    } else if (urgencyLevel === 'urgent') {
        return 'Within 2-3 days';
    } else {
        return 'Within 1 week';
    }
}

// Helper function to get compatible blood types
function getCompatibleBloodTypes(patientBloodGroup) {
    const compatibility = {
        'A+': ['A+', 'A-', 'O+', 'O-'],
        'A-': ['A-', 'O-'],
        'B+': ['B+', 'B-', 'O+', 'O-'],
        'B-': ['B-', 'O-'],
        'AB+': ['A+', 'A-', 'B+', 'B-', 'AB+', 'AB-', 'O+', 'O-'], // Universal recipient
        'AB-': ['A-', 'B-', 'AB-', 'O-'],
        'O+': ['O+', 'O-'],
        'O-': ['O-']
    };
    
    return compatibility[patientBloodGroup] || [patientBloodGroup];
}

// Blood Request Routes (for recipients) - EXISTING
app.post('/api/blood-request', authenticateToken, async (req, res) => {
    try {
        if (req.user.user_type !== 'recipient') {
            return res.status(403).json({ error: 'Only recipients can create blood requests' });
        }

        const { 
            blood_group_needed, 
            units_needed, 
            urgency_level, 
            hospital_name, 
            hospital_address, 
            required_by_date, 
            notes 
        } = req.body;

        const { data, error } = await supabase
            .from('blood_requests')
            .insert([
                {
                    recipient_id: req.user.id,
                    blood_group_needed,
                    units_needed,
                    urgency_level,
                    hospital_name,
                    hospital_address,
                    required_by_date,
                    notes,
                    status: 'pending',
                    created_at: new Date().toISOString()
                }
            ])
            .select()
            .single();

        if (error) {
            return res.status(400).json({ error: error.message });
        }

        res.status(201).json({
            message: 'Blood request created successfully',
            request: data
        });

    } catch (error) {
        console.error('Blood request error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get Blood Requests
app.get('/api/blood-requests', authenticateToken, async (req, res) => {
    try {
        let query = supabase
            .from('blood_requests')
            .select(`
                *,
                users!blood_requests_recipient_id_fkey(full_name, phone, email)
            `);

        // If recipient, only show their requests
        if (req.user.user_type === 'recipient') {
            query = query.eq('recipient_id', req.user.id);
        }

        const { data, error } = await query.order('created_at', { ascending: false });

        if (error) {
            return res.status(400).json({ error: error.message });
        }

        res.json({ requests: data });

    } catch (error) {
        console.error('Get blood requests error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Donation Routes (for donors)
app.post('/api/donation', authenticateToken, async (req, res) => {
    try {
        if (req.user.user_type !== 'donor') {
            return res.status(403).json({ error: 'Only donors can record donations' });
        }

        const { 
            donation_date, 
            units_donated, 
            donation_center, 
            notes 
        } = req.body;

        const { data, error } = await supabase
            .from('donations')
            .insert([
                {
                    donor_id: req.user.id,
                    donation_date,
                    units_donated,
                    donation_center,
                    notes,
                    status: 'completed',
                    created_at: new Date().toISOString()
                }
            ])
            .select()
            .single();

        if (error) {
            return res.status(400).json({ error: error.message });
        }

        res.status(201).json({
            message: 'Donation recorded successfully',
            donation: data
        });

    } catch (error) {
        console.error('Donation error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get Donations
app.get('/api/donations', authenticateToken, async (req, res) => {
    try {
        let query = supabase
            .from('donations')
            .select(`
                *,
                users!donations_donor_id_fkey(full_name, phone, email, blood_group)
            `);

        // If donor, only show their donations
        if (req.user.user_type === 'donor') {
            query = query.eq('donor_id', req.user.id);
        }

        const { data, error } = await query.order('donation_date', { ascending: false });

        if (error) {
            return res.status(400).json({ error: error.message });
        }

        res.json({ donations: data });

    } catch (error) {
        console.error('Get donations error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Schedule Donation Appointment
app.post('/api/donor/schedule-donation', authenticateToken, async (req, res) => {
    try {
        const { donation_center, donation_date, donation_time, donation_type, notes } = req.body;
        const donor_id = req.user.id;

        // Validate donor
        if (req.user.user_type !== 'donor') {
            return res.status(403).json({ error: 'Only donors can schedule donations' });
        }

        // Validate required fields
        if (!donation_center || !donation_date) {
            return res.status(400).json({ error: 'Donation center and date are required' });
        }

        // Check eligibility first
        const eligibilityResponse = await fetch(`${req.protocol}://${req.get('host')}/api/donor/eligibility`, {
            headers: { Authorization: req.headers.authorization }
        });
        const eligibility = await eligibilityResponse.json();

        if (!eligibility.eligible) {
            return res.status(400).json({ 
                error: 'Not eligible to donate',
                message: `You can donate again on ${eligibility.canDonateDate}`
            });
        }

        // Create scheduled donation record
        const { data, error } = await supabase
            .from('donations')
            .insert([
                {
                    donor_id,
                    donation_date,
                    units_donated: 1, // Default to 1 unit
                    donation_center: `${donation_center}${donation_time ? ` at ${donation_time}` : ''}`,
                    notes: notes || `${donation_type} donation scheduled`,
                    status: 'scheduled'
                }
            ])
            .select()
            .single();

        if (error) {
            return res.status(400).json({ error: error.message });
        }

        res.status(201).json({
            message: 'Donation scheduled successfully',
            donation: data,
            appointment: {
                center: donation_center,
                date: donation_date,
                time: donation_time,
                type: donation_type
            }
        });

    } catch (error) {
        console.error('Schedule donation error:', error);
        res.status(500).json({ error: 'Failed to schedule donation' });
    }
});

// Helper function to check for pending donations
const checkPendingDonations = async (donorId) => {
    try {
        const { data: pendingDonations, error } = await supabase
            .from('donations')
            .select('*')
            .eq('donor_id', donorId)
            .in('status', ['pending_admin_approval', 'scheduled'])
            .order('created_at', { ascending: false });

        if (error) throw error;

        return {
            hasPending: pendingDonations && pendingDonations.length > 0,
            pendingCount: pendingDonations ? pendingDonations.length : 0,
            latestPending: pendingDonations && pendingDonations.length > 0 ? pendingDonations[0] : null
        };
    } catch (error) {
        console.error('Error checking pending donations:', error);
        return { hasPending: false, pendingCount: 0, latestPending: null };
    }
};

// Complete Walk-in Donation
app.post('/api/donor/walk-in-donation', authenticateToken, async (req, res) => {
    try {
        console.log('=== NEW DONATION SUBMISSION ===');
        console.log('User:', req.user.full_name, '(', req.user.id, ')');
        console.log('Request body:', req.body);
        
        const { 
            donation_center, 
            units_donated, 
            notes, 
            verification_photo, 
            ai_verification, 
            status,
            verification_status 
        } = req.body;
        const donor_id = req.user.id;

        // Validate donor
        if (req.user.user_type !== 'donor') {
            return res.status(403).json({ 
                error: 'Access denied',
                title: 'Permission Error',
                message: 'Only donors can record donations'
            });
        }

        // Get complete donor information including blood group
        const { data: donor, error: donorError } = await supabase
            .from('users')
            .select('full_name, blood_group, email')
            .eq('id', donor_id)
            .single();

        if (donorError || !donor) {
            console.error('Donor fetch error:', donorError);
            return res.status(400).json({ error: 'Donor information not found' });
        }

        console.log('Donor details:', donor.full_name, 'Blood group:', donor.blood_group);

        // Check for pending donations first
        const pendingCheck = await checkPendingDonations(req.user.id);
        
        if (pendingCheck.hasPending) {
            return res.status(400).json({
                error: 'Pending donation exists',
                title: 'Donation Already Pending',
                message: `You have ${pendingCheck.pendingCount} donation(s) awaiting admin approval. Please wait for approval before submitting a new donation.`,
                pendingDonation: {
                    date: pendingCheck.latestPending.donation_date,
                    center: pendingCheck.latestPending.donation_center,
                    units: pendingCheck.latestPending.units_donated,
                    status: pendingCheck.latestPending.status,
                    submittedAt: pendingCheck.latestPending.submitted_at
                }
            });
        }

        // Validate required fields
        if (!donation_center) {
            return res.status(400).json({ error: 'Donation center is required' });
        }

        // For AI verification, require photo and verification data
        if (verification_photo && !ai_verification) {
            return res.status(400).json({ error: 'AI verification data is required when photo is provided' });
        }

        // Check eligibility first (only for completed donations)
        if (status !== 'pending_admin_approval') {
            const eligibilityResponse = await fetch(`${req.protocol}://${req.get('host')}/api/donor/eligibility`, {
                headers: { Authorization: req.headers.authorization }
            });
            const eligibility = await eligibilityResponse.json();

            if (!eligibility.eligible) {
                return res.status(400).json({ 
                    error: 'Not eligible to donate',
                    message: `You can donate again on ${eligibility.canDonateDate}`
                });
            }
        }

        // Create donation record with AI verification data
        console.log('Creating donation record...');
        const { data, error } = await supabase
            .from('donations')
            .insert([
                {
                    donor_id,
                    donation_date: new Date().toISOString().split('T')[0],
                    units_donated: units_donated || 1,
                    donation_center,
                    notes: notes || 'Walk-in donation',
                    status: status || 'pending_admin_approval',
                    verification_photo: verification_photo || null,
                    ai_verification: ai_verification || null,
                    verification_status: verification_status || 'ai_verified',
                    admin_approved: false,
                    submitted_at: new Date().toISOString(),
                    source: 'walk_in'
                }
            ])
            .select()
            .single();

        if (error) {
            console.error('Donation creation error:', error);
            return res.status(400).json({ error: error.message });
        }

        console.log('✅ Donation created successfully:', data.id);

        // CRITICAL: Update blood inventory immediately for pending donations too
        console.log('=== UPDATING BLOOD INVENTORY ===');
        console.log('Blood group to update:', donor.blood_group);
        console.log('Units to add:', units_donated || 1);

        if (donor && donor.blood_group) {
            try {
                // Get existing inventory for this blood group
                const { data: existingInventory, error: fetchError } = await supabase
                    .from('blood_inventory')
                    .select('units_available')
                    .eq('blood_group', donor.blood_group)
                    .single();

                console.log('Existing inventory check:', existingInventory);

                if (existingInventory) {
                    // Update existing inventory
                    const newTotal = existingInventory.units_available + (units_donated || 1);
                    console.log('Updating existing inventory:', existingInventory.units_available, '→', newTotal);
                    
                    const { data: updateResult, error: updateError } = await supabase
                        .from('blood_inventory')
                        .update({
                            units_available: newTotal,
                            updated_at: new Date().toISOString()
                        })
                        .eq('blood_group', donor.blood_group)
                        .select();
                    
                    if (updateError) {
                        console.error('❌ Inventory update failed:', updateError);
                    } else {
                        console.log('✅ Blood inventory updated successfully!');
                        console.log('Updated inventory:', updateResult);
                    }
                } else {
                    // Create new inventory entry
                    console.log('Creating new inventory entry for', donor.blood_group);
                    
                    const expiryDate = new Date();
                    expiryDate.setDate(expiryDate.getDate() + 7);
                    
                    const { data: insertResult, error: insertError } = await supabase
                        .from('blood_inventory')
                        .insert({
                            blood_group: donor.blood_group,
                            units_available: units_donated || 1,
                            location: donation_center || 'Main Blood Bank',
                            expiry_date: expiryDate.toISOString().split('T')[0],
                            created_at: new Date().toISOString(),
                            updated_at: new Date().toISOString()
                        })
                        .select();
                    
                    if (insertError) {
                        console.error('❌ Inventory creation failed:', insertError);
                    } else {
                        console.log('✅ New blood inventory created!');
                        console.log('New inventory:', insertResult);
                    }
                }
            } catch (inventoryError) {
                console.error('Blood inventory update error:', inventoryError);
                // Don't fail the whole donation for inventory errors
            }
        } else {
            console.warn('⚠️ No blood group found for donor, skipping inventory update');
        }

        // Return success response
        console.log('=== DONATION SUBMISSION COMPLETE ===');
        res.status(201).json({
            success: true,
            message: 'Donation submitted for admin approval',
            donation: data,
            ai_verification: ai_verification,
            status: 'pending_approval',
            certificate: {
                donorName: donor.full_name,
                bloodGroup: donor.blood_group,
                date: data.donation_date,
                center: donation_center,
                units: units_donated || 1
            }
        });

    } catch (error) {
        console.error('=== DONATION SUBMISSION ERROR ===');
        console.error('Error details:', error);
        res.status(500).json({ 
            error: 'Failed to record donation',
            details: error.message 
        });
    }
});

// Record Past Donation
app.post('/api/donor/past-donation', authenticateToken, async (req, res) => {
    try {
        const { donation_center, donation_date, units_donated, notes, source } = req.body;
        const donor_id = req.user.id;

        // Validate donor
        if (req.user.user_type !== 'donor') {
            return res.status(403).json({ error: 'Only donors can record donations' });
        }

        // Validate required fields
        if (!donation_center || !donation_date) {
            return res.status(400).json({ error: 'Donation center and date are required' });
        }

        // Validate date is within last 90 days
        const donationDateObj = new Date(donation_date);
        const today = new Date();
        const ninetyDaysAgo = new Date(today);
        ninetyDaysAgo.setDate(today.getDate() - 90);

        if (donationDateObj < ninetyDaysAgo || donationDateObj > today) {
            return res.status(400).json({ 
                error: 'Donation date must be within the last 90 days' 
            });
        }

        // Create past donation record
        const { data, error } = await supabase
            .from('donations')
            .insert([
                {
                    donor_id,
                    donation_date,
                    units_donated: units_donated || 1,
                    donation_center,
                    notes: notes || 'Past donation recorded manually',
                    status: 'completed',
                    source: source || 'manual_entry'
                }
            ])
            .select()
            .single();

        if (error) {
            return res.status(400).json({ error: error.message });
        }

        // Add blood inventory entry for past donation
        const { data: donor } = await supabase
            .from('users')
            .select('blood_group, full_name')
            .eq('id', donor_id)
            .single();

        if (donor && donor.blood_group) {
            // Update blood inventory for past donation
            try {
                // Get existing inventory for this blood group
                const { data: existingInventory } = await supabase
                    .from('blood_inventory')
                    .select('units_available')
                    .eq('blood_group', donor.blood_group)
                    .single();

                if (existingInventory) {
                    // Update existing inventory
                    const newTotal = existingInventory.units_available + (units_donated || 1);
                    await supabase
                        .from('blood_inventory')
                        .update({
                            units_available: newTotal,
                            updated_at: new Date().toISOString()
                        })
                        .eq('blood_group', donor.blood_group);
                    
                    console.log(`✅ Past donation: Updated ${donor.blood_group} inventory: +${units_donated || 1} units (total: ${newTotal})`);
                } else {
                    // Create new inventory entry if none exists
                    const donationDateObj = new Date(donation_date);
                    const expiryDate = new Date(donationDateObj);
                    expiryDate.setDate(donationDateObj.getDate() + 7); // 7 days from donation
                    
                    await supabase
                        .from('blood_inventory')
                        .insert({
                            blood_group: donor.blood_group,
                            units_available: units_donated || 1,
                            location: donation_center,
                            expiry_date: expiryDate.toISOString().split('T')[0]
                        });
                    
                    console.log(`✅ Past donation: Created new ${donor.blood_group} inventory: ${units_donated || 1} units`);
                }
            } catch (inventoryError) {
                console.error('Blood inventory update error for past donation:', inventoryError);
                // Don't fail the whole donation for inventory errors
            }
        }

        res.status(201).json({
            message: 'Past donation recorded successfully!',
            donation: data,
            certificate: {
                donorName: req.user.full_name,
                date: data.donation_date,
                center: donation_center,
                units: units_donated || 1,
                bloodGroup: user?.blood_group,
                isPastDonation: true
            }
        });

    } catch (error) {
        console.error('Past donation error:', error);
        res.status(500).json({ error: 'Failed to record past donation' });
    }
});

// Get Donor's Pending Donations
app.get('/api/donor/pending-donations', authenticateToken, async (req, res) => {
    try {
        if (req.user.user_type !== 'donor') {
            return res.status(403).json({ error: 'Access denied' });
        }

        const { data: pendingDonations, error } = await supabase
            .from('donations')
            .select('*')
            .eq('donor_id', req.user.id)
            .in('status', ['pending_admin_approval', 'scheduled'])
            .order('created_at', { ascending: false });

        if (error) throw error;

        res.json({ 
            pendingDonations: pendingDonations || [],
            count: pendingDonations ? pendingDonations.length : 0
        });
    } catch (error) {
        console.error('Error fetching pending donations:', error);
        res.status(500).json({ error: 'Failed to fetch pending donations' });
    }
});

// Get Donor Statistics
app.get('/api/donor/stats', authenticateToken, async (req, res) => {
    try {
        const donor_id = req.user.id;

        if (req.user.user_type !== 'donor') {
            return res.status(403).json({ error: 'Only donors can view donation stats' });
        }

        // Get donation statistics
        const { data: donations, error } = await supabase
            .from('donations')
            .select('*')
            .eq('donor_id', donor_id)
            .eq('status', 'completed');

        if (error) {
            return res.status(400).json({ error: error.message });
        }

        const totalDonations = donations.length;
        const totalUnits = donations.reduce((sum, donation) => sum + donation.units_donated, 0);
        const lastDonation = donations.length > 0 ? 
            Math.max(...donations.map(d => new Date(d.donation_date))) : null;

        // Calculate next eligible date
        let nextEligibleDate = new Date();
        if (lastDonation) {
            nextEligibleDate = new Date(lastDonation);
            nextEligibleDate.setDate(nextEligibleDate.getDate() + 56); // 8 weeks
        }

        res.json({
            stats: {
                totalDonations,
                totalUnits,
                lastDonationDate: lastDonation ? new Date(lastDonation).toISOString().split('T')[0] : null,
                nextEligibleDate: nextEligibleDate.toISOString().split('T')[0],
                donationHistory: donations.map(d => ({
                    date: d.donation_date,
                    center: d.donation_center,
                    units: d.units_donated,
                    status: d.status
                }))
            }
        });

    } catch (error) {
        console.error('Donor stats error:', error);
        res.status(500).json({ error: 'Failed to get donor statistics' });
    }
});

// Admin Routes
app.get('/api/admin/dashboard', authenticateToken, async (req, res) => {
    try {
        if (req.user.user_type !== 'admin') {
            return res.status(403).json({ error: 'Admin access required' });
        }

        // Get dashboard statistics
        const [usersResult, requestsResult, donationsResult] = await Promise.all([
            supabase.from('users').select('user_type', { count: 'exact' }),
            supabase.from('blood_requests').select('status', { count: 'exact' }),
            supabase.from('donations').select('id', { count: 'exact' })
        ]);

        const stats = {
            total_users: usersResult.count || 0,
            total_requests: requestsResult.count || 0,
            total_donations: donationsResult.count || 0,
            users_by_type: {},
            requests_by_status: {}
        };

        // Count users by type
        if (usersResult.data) {
            usersResult.data.forEach(user => {
                stats.users_by_type[user.user_type] = (stats.users_by_type[user.user_type] || 0) + 1;
            });
        }

        // Count requests by status
        if (requestsResult.data) {
            requestsResult.data.forEach(request => {
                stats.requests_by_status[request.status] = (stats.requests_by_status[request.status] || 0) + 1;
            });
        }

        res.json({ stats });

    } catch (error) {
        console.error('Admin dashboard error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get All Users (Admin only)
app.get('/api/admin/users', authenticateToken, async (req, res) => {
    try {
        if (req.user.user_type !== 'admin') {
            return res.status(403).json({ error: 'Admin access required' });
        }

        const { data, error } = await supabase
            .from('users')
            .select('id, email, user_type, full_name, phone, blood_group, age, is_active, created_at')
            .order('created_at', { ascending: false });

        if (error) {
            return res.status(400).json({ error: error.message });
        }

        res.json({ users: data });

    } catch (error) {
        console.error('Get users error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get Blood Inventory (Admin only)
app.get('/api/admin/blood-inventory', authenticateToken, async (req, res) => {
    try {
        if (req.user.user_type !== 'admin') {
            return res.status(403).json({ error: 'Admin access required' });
        }

        console.log('=== ADMIN BLOOD INVENTORY REQUEST ===');
        
        const { data: inventory, error } = await supabase
            .from('blood_inventory')
            .select('*')
            .order('last_updated', { ascending: false });

        if (error) {
            console.error('Admin blood inventory fetch error:', error);
            return res.status(400).json({ error: error.message });
        }

        console.log('📊 Admin inventory fetch successful:', inventory?.length || 0, 'items');

        // Calculate summary statistics
        const summary = {
            totalUnits: inventory?.reduce((sum, item) => sum + item.units_available, 0) || 0,
            bloodGroups: inventory?.length || 0,
            totalBatches: inventory?.length || 0,
            lastUpdated: inventory?.[0]?.last_updated || null
        };

        // Group by blood group for better organization
        const groupedInventory = {};
        inventory?.forEach(item => {
            if (!groupedInventory[item.blood_group]) {
                groupedInventory[item.blood_group] = [];
            }
            groupedInventory[item.blood_group].push(item);
        });

        res.json({
            success: true,
            inventory: inventory || [],
            groupedInventory,
            summary
        });

    } catch (error) {
        console.error('Admin blood inventory error:', error);
        res.status(500).json({ error: 'Failed to fetch blood inventory' });
    }
});

// Admin: Get pending donations for approval
app.get('/api/admin/pending-donations', authenticateToken, async (req, res) => {
    try {
        if (req.user.user_type !== 'admin') {
            return res.status(403).json({ error: 'Only admins can view pending donations' });
        }

        const { data, error } = await supabase
            .from('donations')
            .select(`
                *,
                users!donor_id (
                    id,
                    full_name,
                    email,
                    blood_group
                )
            `)
            .eq('admin_approved', false)
            .order('created_at', { ascending: false });

        if (error) {
            return res.status(400).json({ error: error.message });
        }

        res.json({ pendingDonations: data || [] });

    } catch (error) {
        console.error('Get pending donations error:', error);
        res.status(500).json({ error: 'Failed to fetch pending donations' });
    }
});

// Admin: Get all blood requests for management
app.get('/api/admin/blood-requests', authenticateToken, async (req, res) => {
    try {
        if (req.user.user_type !== 'admin') {
            return res.status(403).json({ error: 'Only admins can view blood requests' });
        }

        const { data, error } = await supabase
            .from('blood_requests')
            .select(`
                *,
                users!blood_requests_recipient_id_fkey (
                    id,
                    full_name,
                    email,
                    phone,
                    blood_group
                )
            `)
            .order('created_at', { ascending: false });

        if (error) {
            console.error('Admin blood requests error:', error);
            return res.status(400).json({ error: error.message });
        }

        console.log(`📋 Admin retrieved ${data?.length || 0} blood requests`);

        res.json({ 
            success: true,
            bloodRequests: data || [],
            total: data?.length || 0
        });

    } catch (error) {
        console.error('Get admin blood requests error:', error);
        res.status(500).json({ error: 'Failed to fetch blood requests' });
    }
});

// Admin: Update blood request status
app.post('/api/admin/update-blood-request/:requestId', authenticateToken, async (req, res) => {
    try {
        if (req.user.user_type !== 'admin') {
            return res.status(403).json({ error: 'Only admins can update blood requests' });
        }

        const { requestId } = req.params;
        const { status, admin_notes } = req.body;

        // Validate status
        const validStatuses = ['pending', 'approved', 'rejected', 'fulfilled', 'cancelled'];
        if (!validStatuses.includes(status)) {
            return res.status(400).json({ error: 'Invalid status' });
        }

        const { data, error } = await supabase
            .from('blood_requests')
            .update({
                status,
                admin_notes,
                updated_at: new Date().toISOString()
            })
            .eq('id', requestId)
            .select();

        if (error) {
            console.error('Update blood request error:', error);
            return res.status(400).json({ error: error.message });
        }

        if (!data || data.length === 0) {
            return res.status(404).json({ error: 'Blood request not found' });
        }

        console.log(`✅ Admin updated blood request ${requestId} to ${status}`);

        res.json({
            success: true,
            message: `Blood request ${status} successfully`,
            bloodRequest: data[0]
        });

    } catch (error) {
        console.error('Update blood request error:', error);
        res.status(500).json({ error: 'Failed to update blood request' });
    }
});

// Admin: Approve or reject donation
app.post('/api/admin/approve-donation/:donationId', authenticateToken, async (req, res) => {
    try {
        console.log('🔄 Admin approval request:', { donationId: req.params.donationId, action: req.body.action });
        
        if (req.user.user_type !== 'admin') {
            return res.status(403).json({ error: 'Only admins can approve donations' });
        }

        const { donationId } = req.params;
        const { action, admin_notes } = req.body;

        if (!['approve', 'reject'].includes(action)) {
            return res.status(400).json({ error: 'Action must be either approve or reject' });
        }

        // Get donation details first
        const { data: donation, error: fetchError } = await supabase
            .from('donations')
            .select('*, users!donor_id(blood_group, full_name)')
            .eq('id', donationId)
            .single();

        if (fetchError || !donation) {
            console.error('❌ Donation not found:', fetchError);
            return res.status(404).json({ error: 'Donation not found' });
        }

        console.log('📋 Found donation:', {
            id: donation.id,
            donor: donation.users?.blood_group,
            units: donation.units_donated,
            status: donation.status
        });

        // Update donation status
        const updateData = {
            status: action === 'approve' ? 'completed' : 'rejected',
            admin_approved: action === 'approve',
            approved_by: req.user.id,
            admin_notes: admin_notes || null,
            approved_at: new Date().toISOString(),
            verification_status: action === 'approve' ? 'admin_approved' : 'rejected'
        };

        const { error: updateError } = await supabase
            .from('donations')
            .update(updateData)
            .eq('id', donationId);

        if (updateError) {
            console.error('❌ Error updating donation:', updateError);
            return res.status(400).json({ error: updateError.message });
        }

        console.log('✅ Donation status updated successfully');

        // If approved, update blood inventory
        if (action === 'approve' && donation.users?.blood_group) {
            try {
                console.log('🩸 Adding new blood inventory entry...');
                
                // Create new inventory entry for each approved donation
                const expiryDate = new Date();
                expiryDate.setDate(expiryDate.getDate() + 42); // 42 days from approval
                
                const batchNumber = `${donation.users.blood_group}-${new Date().toISOString().split('T')[0].replace(/-/g, '')}-${Math.floor(Math.random() * 9999).toString().padStart(4, '0')}`;
                
                const { data: inventoryResult, error: inventoryError } = await supabase
                    .from('blood_inventory')
                    .insert({
                        blood_group: donation.users.blood_group,
                        units_available: donation.units_donated,
                        batch_number: batchNumber,
                        donation_id: donation.id,
                        donor_id: donation.donor_id,
                        donor_name: donation.users.full_name,
                        donation_date: donation.donation_date,
                        collection_date: new Date().toISOString().split('T')[0],
                        expiry_date: expiryDate.toISOString().split('T')[0],
                        status: 'available',
                        location: donation.donation_center || 'Main Blood Bank',
                        notes: `Added from approved donation ID: ${donation.id}`,
                        created_at: new Date().toISOString(),
                        last_updated: new Date().toISOString()
                    })
                    .select();
                
                if (inventoryError) {
                    console.error('❌ Inventory creation failed:', inventoryError);
                } else {
                    console.log(`✅ Admin approved: Created new ${donation.users.blood_group} inventory batch: ${donation.units_donated} units`);
                    console.log('📦 New inventory entry:', inventoryResult);
                }
            } catch (inventoryError) {
                console.error('❌ Blood inventory update error during admin approval:', inventoryError);
                // Don't fail the approval for inventory errors
            }
        }

        res.json({ 
            success: true,
            message: `Donation ${action}d successfully`,
            donation: { ...donation, ...updateData }
        });

    } catch (error) {
        console.error('❌ Approve donation error:', error);
        res.status(500).json({ error: 'Failed to process donation approval' });
    }
});

// Submit donation request (simplified version)
app.post('/api/donor/submit-donation-request', authenticateToken, async (req, res) => {
    console.log('=== SUBMIT DONATION REQUEST ===');
    console.log('User:', req.user);
    console.log('Body:', req.body);
    
    try {
        if (req.user.user_type !== 'donor') {
            return res.status(403).json({ error: 'Access denied. Only donors can submit donation requests.' });
        }

        const { donationDetails } = req.body;

        // Basic validation
        if (!donationDetails) {
            return res.status(400).json({ 
                error: 'Missing donation details',
                message: 'Please provide donation details'
            });
        }

        console.log('Creating donation with details:', donationDetails);

        // Insert donation into donations table with admin_approved = false for pending approval
        const { data: donation, error } = await supabase
            .from('donations')
            .insert({
                donor_id: req.user.id,
                donation_date: donationDetails.donation_date || new Date().toISOString().split('T')[0],
                units_donated: donationDetails.units_donated || 1,
                donation_center: donationDetails.donation_center || 'Walk-in Donation',
                notes: donationDetails.notes || '',
                status: 'completed',
                admin_approved: false // Pending admin approval
            })
            .select()
            .single();

        if (error) {
            console.error('Error creating donation:', error);
            return res.status(400).json({ error: error.message });
        }

        console.log('Donation created successfully:', donation);

        res.json({
            success: true,
            message: 'Donation request submitted successfully for admin approval',
            donation: donation
        });

    } catch (error) {
        console.error('Submit donation request error:', error);
        res.status(500).json({ error: 'Failed to submit donation request' });
    }
});

// Check donation eligibility (buffer period)
app.get('/api/donor/check-eligibility', authenticateToken, async (req, res) => {
    try {
        if (req.user.user_type !== 'donor') {
            return res.status(403).json({ error: 'Only donors can check eligibility' });
        }

        let eligibility = null;
        try {
            const { data: eligibilityCheck, error } = await supabase
                .rpc('check_donation_eligibility', { donor_uuid: req.user.id });

            if (error) {
                console.error('Error checking donation eligibility with function:', error);
                
                // Fallback: Check eligibility manually if function doesn't exist
                const { data: lastDonation, error: lastDonationError } = await supabase
                    .from('donations')
                    .select('donation_date')
                    .eq('donor_id', req.user.id)
                    .eq('status', 'completed')
                    .eq('admin_approved', true)
                    .order('donation_date', { ascending: false })
                    .limit(1);

                if (lastDonationError) {
                    console.error('Error checking last donation:', lastDonationError);
                    return res.status(500).json({ error: 'Failed to check donation eligibility' });
                }

                // Manual eligibility calculation
                if (lastDonation && lastDonation.length > 0) {
                    const lastDonationDate = new Date(lastDonation[0].donation_date);
                    const daysSince = Math.floor((new Date() - lastDonationDate) / (1000 * 60 * 60 * 24));
                    const daysRemaining = Math.max(0, 56 - daysSince);
                    
                    eligibility = {
                        is_eligible: daysSince >= 56,
                        last_donation_date: lastDonation[0].donation_date,
                        next_eligible_date: new Date(lastDonationDate.getTime() + (56 * 24 * 60 * 60 * 1000)).toISOString().split('T')[0],
                        days_remaining: daysRemaining,
                        reason: daysSince >= 56 ? 'Buffer period completed - eligible to donate' : `Buffer period active - must wait ${daysRemaining} more days`
                    };
                } else {
                    // First time donor
                    eligibility = {
                        is_eligible: true,
                        last_donation_date: null,
                        next_eligible_date: new Date().toISOString().split('T')[0],
                        days_remaining: 0,
                        reason: 'First time donor - eligible to donate'
                    };
                }
            } else {
                eligibility = eligibilityCheck[0];
            }
        } catch (functionError) {
            console.error('Function call failed, using fallback:', functionError);
            
            // Fallback eligibility check - first check pending donations
            const { data: pendingDonations, error: pendingError } = await supabase
                .from('pending_donations')
                .select('id')
                .eq('donor_id', req.user.id)
                .eq('status', 'pending_admin_approval');

            let pendingCount = 0;
            if (pendingDonations && !pendingError) {
                pendingCount = pendingDonations.length;
            }

            if (pendingCount > 0) {
                eligibility = {
                    is_eligible: false,
                    last_donation_date: null,
                    next_eligible_date: null,
                    days_remaining: 0,
                    reason: `You have ${pendingCount} pending donation${pendingCount > 1 ? 's' : ''} awaiting admin approval. Please wait for approval before submitting new requests.`,
                    pending_donations_count: pendingCount
                };
            } else {
                // Check buffer period
                const { data: lastDonation, error: lastDonationError } = await supabase
                    .from('donations')
                    .select('donation_date')
                    .eq('donor_id', req.user.id)
                    .eq('status', 'completed')
                    .eq('admin_approved', true)
                    .order('donation_date', { ascending: false })
                    .limit(1);

            if (lastDonationError) {
                console.error('Error in fallback eligibility check:', lastDonationError);
                // Return eligible by default if we can't check
                eligibility = {
                    is_eligible: true,
                    last_donation_date: null,
                    next_eligible_date: new Date().toISOString().split('T')[0],
                    days_remaining: 0,
                    reason: 'Unable to verify donation history - proceeding with caution'
                };
            } else if (lastDonation && lastDonation.length > 0) {
                const lastDonationDate = new Date(lastDonation[0].donation_date);
                const daysSince = Math.floor((new Date() - lastDonationDate) / (1000 * 60 * 60 * 24));
                const daysRemaining = Math.max(0, 56 - daysSince);
                
                eligibility = {
                    is_eligible: daysSince >= 56,
                    last_donation_date: lastDonation[0].donation_date,
                    next_eligible_date: new Date(lastDonationDate.getTime() + (56 * 24 * 60 * 60 * 1000)).toISOString().split('T')[0],
                    days_remaining: daysRemaining,
                    reason: daysSince >= 56 ? 'Buffer period completed - eligible to donate' : `Buffer period active - must wait ${daysRemaining} more days`,
                    pending_donations_count: pendingCount
                };
            } else {
                // First time donor
                eligibility = {
                    is_eligible: true,
                    last_donation_date: null,
                    next_eligible_date: new Date().toISOString().split('T')[0],
                    days_remaining: 0,
                    reason: 'First time donor - eligible to donate',
                    pending_donations_count: pendingCount
                };
            }
            }
        }
        
        res.json({
            isEligible: eligibility.is_eligible,
            lastDonationDate: eligibility.last_donation_date,
            nextEligibleDate: eligibility.next_eligible_date,
            daysRemaining: eligibility.days_remaining,
            reason: eligibility.reason,
            pendingDonationsCount: eligibility.pending_donations_count || 0
        });

    } catch (error) {
        console.error('Check eligibility error:', error);
        res.status(500).json({ error: 'Failed to check donation eligibility' });
    }
});

// Enhanced: Get pending donations for admin with full details
app.get('/api/admin/enhanced-pending-donations', authenticateToken, async (req, res) => {
    try {
        if (req.user.user_type !== 'admin') {
            return res.status(403).json({ error: 'Only admins can view pending donations' });
        }

        const { data, error } = await supabase
            .from('admin_pending_donations_view')
            .select('*')
            .order('submitted_at', { ascending: true }); // Oldest first for fairness

        if (error) {
            console.error('Error fetching pending donations:', error);
            return res.status(400).json({ error: error.message });
        }

        res.json({ 
            success: true,
            pendingDonations: data || [],
            count: data?.length || 0
        });

    } catch (error) {
        console.error('Get enhanced pending donations error:', error);
        res.status(500).json({ error: 'Failed to fetch pending donations' });
    }
});

// Enhanced: Approve or reject pending donation with certificate generation
app.post('/api/admin/process-donation-request/:pendingId', authenticateToken, async (req, res) => {
    try {
        if (req.user.user_type !== 'admin') {
            return res.status(403).json({ error: 'Only admins can process donation requests' });
        }

        const { pendingId } = req.params;
        const { action, admin_notes } = req.body;

        if (!['approve', 'reject'].includes(action)) {
            return res.status(400).json({ error: 'Action must be either approve or reject' });
        }

        // Get pending donation details
        const { data: pendingDonation, error: fetchError } = await supabase
            .from('pending_donations')
            .select(`
                *,
                users!donor_id (
                    id,
                    full_name,
                    email,
                    blood_group,
                    phone
                )
            `)
            .eq('id', pendingId)
            .single();

        if (fetchError || !pendingDonation) {
            return res.status(404).json({ error: 'Pending donation not found' });
        }

        // Double-check risk score before approval
        if (action === 'approve' && pendingDonation.risk_score > 60) {
            return res.status(400).json({ 
                error: 'Cannot approve high-risk donation',
                message: `Risk score (${pendingDonation.risk_score}%) exceeds safety threshold (60%)` 
            });
        }

        // Update pending donation status
        const updateData = {
            status: action === 'approve' ? 'approved' : 'rejected',
            admin_id: req.user.id,
            admin_notes: admin_notes || null,
            admin_decision_date: new Date().toISOString()
        };

        // If approving, also generate certificate data
        if (action === 'approve') {
            const certificateData = {
                certificateNumber: `CERT-${Date.now()}-${pendingDonation.id.substring(0, 8)}`,
                donorName: pendingDonation.users.full_name,
                bloodGroup: pendingDonation.users.blood_group,
                units: pendingDonation.units_donated,
                donationCenter: pendingDonation.donation_center,
                donationDate: pendingDonation.donation_date,
                approvalDate: new Date().toISOString(),
                adminName: req.user.full_name || 'Admin',
                riskScore: pendingDonation.risk_score,
                validityPeriod: '1 year'
            };

            updateData.certificate_generated = true;
            updateData.certificate_data = certificateData;
            updateData.certificate_generated_at = new Date().toISOString();
        }

        const { error: updateError } = await supabase
            .from('pending_donations')
            .update(updateData)
            .eq('id', pendingId);

        if (updateError) {
            console.error('Error updating pending donation:', updateError);
            return res.status(400).json({ error: updateError.message });
        }

        // The trigger will automatically create donation record and update inventory
        // for approved donations, so we don't need to do it manually here

        res.json({
            success: true,
            message: `Donation request ${action}d successfully`,
            action: action,
            certificateGenerated: action === 'approve',
            certificateData: action === 'approve' ? updateData.certificate_data : null
        });

    } catch (error) {
        console.error('Process donation request error:', error);
        res.status(500).json({ error: 'Failed to process donation request' });
    }
});

// Enhanced: Get donor dashboard stats with pending approvals
app.get('/api/donor/enhanced-stats', authenticateToken, async (req, res) => {
    try {
        if (req.user.user_type !== 'donor') {
            return res.status(403).json({ error: 'Only donors can view their stats' });
        }

        const { data: allDonations, error: donationsError } = await supabase
            .from('donations')
            .select('*')
            .eq('donor_id', req.user.id)
            .order('donation_date', { ascending: false });

        if (donationsError) {
            console.error('❌ Error fetching donations for donor:', req.user.email, donationsError);
            return res.status(400).json({ error: donationsError.message });
        }

        console.log('📊 Found donations for donor:', req.user.email, {
            total_records: allDonations.length,
            completed: allDonations.filter(d => d.status === 'completed').length,
            pending: allDonations.filter(d => d.status === 'pending_admin_approval').length
        });

        // Calculate stats from actual donations
        const completedDonations = allDonations.filter(d => d.status === 'completed' && d.admin_approved === true);
        const pendingDonations = allDonations.filter(d => d.status === 'pending_admin_approval');
        
        const totalDonations = completedDonations.length;
        const totalUnits = completedDonations.reduce((sum, d) => sum + (d.units_donated || 1), 0);
        const lastDonation = completedDonations[0];
        const lastDonationDate = lastDonation ? lastDonation.donation_date : null;
        
        // Calculate next eligible date (56 days after last donation)
        let nextEligibleDate = null;
        if (lastDonationDate) {
            const lastDate = new Date(lastDonationDate);
            const nextDate = new Date(lastDate);
            nextDate.setDate(nextDate.getDate() + 56); // 8 weeks buffer period
            nextEligibleDate = nextDate.toISOString().split('T')[0];
        }

        const stats = {
            donor_id: req.user.id,
            total_donations: totalDonations,
            total_units: totalUnits,
            last_donation_date: lastDonationDate,
            next_eligible_date: nextEligibleDate,
            pending_approvals: pendingDonations.length,
            latest_risk_score: 0,
            eligibility_status: pendingDonations.length > 0 ? 'pending_review' : 'eligible',
            donationHistory: allDonations,
            pendingDonations: pendingDonations
        };

        console.log('✅ Enhanced stats calculated for donor:', req.user.email || req.user.id, {
            total_donations: stats.total_donations,
            pending_approvals: stats.pending_approvals,
            donation_history_count: allDonations.length
        });

        res.json({
            success: true,
            stats: stats
        });

    } catch (error) {
        console.error('Get enhanced donor stats error:', error);
        res.status(500).json({ error: 'Failed to fetch donor statistics' });
    }
});

// Risk calculation helper function
function calculateRiskScore(basicInfo, medicalData, healthConditions) {
    let riskScore = 0;

    // Age risk factors
    const age = parseInt(basicInfo.age);
    if (age < 18 || age > 65) riskScore += 30;
    else if (age < 21 || age > 60) riskScore += 15;

    // Weight risk factors
    const weight = parseFloat(basicInfo.weight);
    if (weight < 50) riskScore += 25;
    else if (weight < 55) riskScore += 10;

    // Blood pressure risk
    const systolic = parseFloat(medicalData.bloodPressure?.systolic);
    const diastolic = parseFloat(medicalData.bloodPressure?.diastolic);
    if (systolic > 140 || systolic < 90 || diastolic > 90 || diastolic < 60) {
        riskScore += 20;
    }

    // Hemoglobin risk
    const hemoglobin = parseFloat(medicalData.hemoglobin);
    if (hemoglobin < 12.5) riskScore += 25;
    else if (hemoglobin < 13.0) riskScore += 10;

    // Heart rate risk
    const heartRate = parseFloat(medicalData.heartRate);
    if (heartRate < 50 || heartRate > 100) riskScore += 15;

    // Temperature risk
    const temperature = parseFloat(medicalData.temperature);
    if (temperature > 37.5 || temperature < 36.0) riskScore += 20;

    // Health conditions risk
    if (healthConditions.recentIllness) riskScore += 15;
    if (healthConditions.chronicConditions) riskScore += 20;
    if (healthConditions.currentMedications) riskScore += 10;
    if (healthConditions.allergies) riskScore += 5;

    // Last donation date risk
    if (basicInfo.lastDonationDate) {
        const daysSinceLastDonation = Math.floor(
            (new Date() - new Date(basicInfo.lastDonationDate)) / (1000 * 60 * 60 * 24)
        );
        if (daysSinceLastDonation < 56) riskScore += 30; // Too soon
    }

    return Math.min(Math.round(riskScore), 100); // Cap at 100%
}

// Risk flags generation helper function
function generateRiskFlags(basicInfo, medicalData, healthConditions) {
    const flags = [];

    const age = parseInt(basicInfo.age);
    const weight = parseFloat(basicInfo.weight);
    const systolic = parseFloat(medicalData.bloodPressure?.systolic);
    const diastolic = parseFloat(medicalData.bloodPressure?.diastolic);
    const hemoglobin = parseFloat(medicalData.hemoglobin);
    const heartRate = parseFloat(medicalData.heartRate);
    const temperature = parseFloat(medicalData.temperature);

    if (age < 18 || age > 65) {
        flags.push({ type: 'age', severity: 'high', message: 'Age outside safe donation range' });
    }

    if (weight < 50) {
        flags.push({ type: 'weight', severity: 'high', message: 'Weight below minimum requirement' });
    }

    if (systolic > 140 || diastolic > 90) {
        flags.push({ type: 'blood_pressure', severity: 'high', message: 'High blood pressure' });
    }

    if (systolic < 90 || diastolic < 60) {
        flags.push({ type: 'blood_pressure', severity: 'medium', message: 'Low blood pressure' });
    }

    if (hemoglobin < 12.5) {
        flags.push({ type: 'hemoglobin', severity: 'high', message: 'Low hemoglobin levels' });
    }

    if (heartRate < 50 || heartRate > 100) {
        flags.push({ type: 'heart_rate', severity: 'medium', message: 'Abnormal heart rate' });
    }

    if (temperature > 37.5) {
        flags.push({ type: 'temperature', severity: 'high', message: 'Elevated body temperature' });
    }

    if (healthConditions.recentIllness) {
        flags.push({ type: 'health', severity: 'medium', message: 'Recent illness reported' });
    }

    if (healthConditions.chronicConditions) {
        flags.push({ type: 'health', severity: 'high', message: 'Chronic health conditions' });
    }

    if (basicInfo.lastDonationDate) {
        const daysSinceLastDonation = Math.floor(
            (new Date() - new Date(basicInfo.lastDonationDate)) / (1000 * 60 * 60 * 24)
        );
        if (daysSinceLastDonation < 56) {
            flags.push({ 
                type: 'donation_frequency', 
                severity: 'high', 
                message: `Too soon since last donation (${daysSinceLastDonation} days ago, minimum 56 days required)` 
            });
        }
    }

    return flags;
}

// Additional Admin Analytics Endpoints

// Get detailed user analytics
app.get('/api/admin/user-analytics', authenticateToken, async (req, res) => {
    try {
        if (req.user.user_type !== 'admin') {
            return res.status(403).json({ error: 'Admin access required' });
        }

        const { data: users, error } = await supabase
            .from('users')
            .select('*')
            .order('created_at', { ascending: false });

        if (error) {
            return res.status(400).json({ error: error.message });
        }

        // Process analytics data
        const analytics = {
            totalUsers: users.length,
            usersByType: {
                admin: users.filter(u => u.user_type === 'admin').length,
                donor: users.filter(u => u.user_type === 'donor').length,
                recipient: users.filter(u => u.user_type === 'recipient').length
            },
            recentRegistrations: users.filter(u => {
                const registrationDate = new Date(u.created_at);
                const weekAgo = new Date();
                weekAgo.setDate(weekAgo.getDate() - 7);
                return registrationDate > weekAgo;
            }).length,
            bloodGroupDistribution: {}
        };

        // Calculate blood group distribution
        users.forEach(user => {
            if (user.blood_group) {
                analytics.bloodGroupDistribution[user.blood_group] = 
                    (analytics.bloodGroupDistribution[user.blood_group] || 0) + 1;
            }
        });

        res.json({ success: true, analytics });

    } catch (error) {
        console.error('User analytics error:', error);
        res.status(500).json({ error: 'Failed to fetch user analytics' });
    }
});

// Get donation analytics
app.get('/api/admin/donation-analytics', authenticateToken, async (req, res) => {
    try {
        if (req.user.user_type !== 'admin') {
            return res.status(403).json({ error: 'Admin access required' });
        }

        const { data: donations, error } = await supabase
            .from('donations')
            .select('*')
            .order('donation_date', { ascending: false });

        if (error) {
            return res.status(400).json({ error: error.message });
        }

        const analytics = {
            totalDonations: donations.length,
            completedDonations: donations.filter(d => d.status === 'completed').length,
            pendingDonations: donations.filter(d => d.status === 'pending_admin_approval').length,
            rejectedDonations: donations.filter(d => d.status === 'rejected').length,
            totalUnits: donations.reduce((sum, d) => sum + (d.units_donated || 0), 0),
            approvalRate: donations.length > 0 ? 
                (donations.filter(d => d.status === 'completed').length / donations.length * 100).toFixed(1) : 0,
            recentDonations: donations.filter(d => {
                const donationDate = new Date(d.donation_date || d.created_at);
                const weekAgo = new Date();
                weekAgo.setDate(weekAgo.getDate() - 7);
                return donationDate > weekAgo;
            }).length
        };

        res.json({ success: true, analytics });

    } catch (error) {
        console.error('Donation analytics error:', error);
        res.status(500).json({ error: 'Failed to fetch donation analytics' });
    }
});

// Get inventory analytics
app.get('/api/admin/inventory-analytics', authenticateToken, async (req, res) => {
    try {
        if (req.user.user_type !== 'admin') {
            return res.status(403).json({ error: 'Admin access required' });
        }

        const { data: inventory, error } = await supabase
            .from('blood_inventory')
            .select('*');

        if (error) {
            return res.status(400).json({ error: error.message });
        }

        const today = new Date();
        const analytics = {
            totalUnits: inventory.reduce((sum, item) => sum + item.units_available, 0),
            totalBatches: inventory.length,
            expiringUnits: inventory.filter(item => {
                const expiryDate = new Date(item.expiry_date);
                const daysRemaining = Math.ceil((expiryDate - today) / (1000 * 60 * 60 * 24));
                return daysRemaining > 0 && daysRemaining <= 7;
            }).reduce((sum, item) => sum + item.units_available, 0),
            expiredUnits: inventory.filter(item => {
                const expiryDate = new Date(item.expiry_date);
                return expiryDate < today;
            }).reduce((sum, item) => sum + item.units_available, 0),
            bloodGroupBreakdown: {}
        };

        // Calculate blood group breakdown
        inventory.forEach(item => {
            if (!analytics.bloodGroupBreakdown[item.blood_group]) {
                analytics.bloodGroupBreakdown[item.blood_group] = {
                    totalUnits: 0,
                    batches: 0,
                    availableUnits: 0,
                    expiringUnits: 0,
                    expiredUnits: 0
                };
            }

            const group = analytics.bloodGroupBreakdown[item.blood_group];
            group.totalUnits += item.units_available;
            group.batches += 1;

            const expiryDate = new Date(item.expiry_date);
            const daysRemaining = Math.ceil((expiryDate - today) / (1000 * 60 * 60 * 24));

            if (daysRemaining < 0) {
                group.expiredUnits += item.units_available;
            } else if (daysRemaining <= 7) {
                group.expiringUnits += item.units_available;
            } else {
                group.availableUnits += item.units_available;
            }
        });

        res.json({ success: true, analytics });

    } catch (error) {
        console.error('Inventory analytics error:', error);
        res.status(500).json({ error: 'Failed to fetch inventory analytics' });
    }
});

// Update user status (activate/deactivate)
app.post('/api/admin/update-user-status/:userId', authenticateToken, async (req, res) => {
    try {
        if (req.user.user_type !== 'admin') {
            return res.status(403).json({ error: 'Admin access required' });
        }

        const { userId } = req.params;
        const { isActive } = req.body;

        const { data, error } = await supabase
            .from('users')
            .update({ is_active: isActive })
            .eq('id', userId)
            .select();

        if (error) {
            return res.status(400).json({ error: error.message });
        }

        res.json({ 
            success: true, 
            message: `User ${isActive ? 'activated' : 'deactivated'} successfully`,
            user: data[0]
        });

    } catch (error) {
        console.error('Update user status error:', error);
        res.status(500).json({ error: 'Failed to update user status' });
    }
});

// Get system health status
app.get('/api/admin/system-health', authenticateToken, async (req, res) => {
    try {
        if (req.user.user_type !== 'admin') {
            return res.status(403).json({ error: 'Admin access required' });
        }

        // Check database connectivity
        const { data: healthCheck, error } = await supabase
            .from('users')
            .select('count')
            .limit(1);

        const health = {
            database: error ? 'error' : 'healthy',
            api: 'healthy',
            timestamp: new Date().toISOString(),
            uptime: process.uptime(),
            version: '1.0.0',
            environment: process.env.NODE_ENV || 'development'
        };

        res.json({ success: true, health });

    } catch (error) {
        console.error('System health error:', error);
        res.status(500).json({ 
            success: false, 
            health: {
                database: 'error',
                api: 'error',
                timestamp: new Date().toISOString()
            }
        });
    }
});

// Start server
// Debug endpoint to check blood inventory status
app.get('/api/debug/blood-inventory', async (req, res) => {
    try {
        console.log('=== DEBUG: Checking blood inventory ===');
        
        const { data: inventory, error } = await supabase
            .from('blood_inventory')
            .select('*')
            .order('last_updated', { ascending: false });

        if (error) {
            console.error('Debug inventory fetch error:', error);
            throw error;
        }

        console.log('Current blood inventory:', inventory);

        res.json({
            success: true,
            count: inventory?.length || 0,
            inventory: inventory || [],
            message: inventory?.length ? `Found ${inventory.length} inventory entries` : 'No inventory entries found',
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        console.error('Debug inventory error:', error);
        res.status(500).json({ 
            error: 'Failed to fetch inventory',
            details: error.message 
        });
    }
});

// Debug endpoint for testing frontend connection (no auth required)
app.get('/api/debug/blood-inventory-public', async (req, res) => {
    try {
        console.log('=== PUBLIC DEBUG: Frontend connection test ===');
        
        const { data: inventory, error } = await supabase
            .from('blood_inventory')
            .select('id, blood_group, units_available, location, expiry_date, last_updated')
            .order('last_updated', { ascending: false });

        if (error) {
            console.error('Public debug inventory fetch error:', error);
            throw error;
        }

        console.log('📱 Frontend connection test - inventory count:', inventory?.length || 0);

        res.json({
            success: true,
            message: 'Frontend connection working!',
            count: inventory?.length || 0,
            inventory: inventory || [],
            testTime: new Date().toISOString(),
            // Format for frontend display
            formattedInventory: inventory?.map(item => ({
                bloodGroup: item.blood_group,
                units: item.units_available,
                location: item.location,
                expiryDate: item.expiry_date,
                lastUpdated: item.last_updated
            })) || []
        });
    } catch (error) {
        console.error('Public debug error:', error);
        res.status(500).json({ 
            error: 'Failed to fetch inventory',
            details: error.message 
        });
    }
});

// Debug endpoint to check all donations
app.get('/api/debug/donations', async (req, res) => {
    try {
        console.log('=== DEBUG: Checking all donations ===');
        
        const { data: donations, error } = await supabase
            .from('donations')
            .select(`
                *,
                users!donor_id(full_name, blood_group, email)
            `)
            .order('created_at', { ascending: false });

        if (error) {
            console.error('Debug donations fetch error:', error);
            throw error;
        }

        console.log('Current donations:', donations);

        res.json({
            success: true,
            count: donations?.length || 0,
            donations: donations || [],
            message: donations?.length ? `Found ${donations.length} donations` : 'No donations found',
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        console.error('Debug donations error:', error);
        res.status(500).json({ 
            error: 'Failed to fetch donations',
            details: error.message 
        });
    }
});

// =============================================================================
// NOTIFICATION ENDPOINTS FOR BLOOD REQUESTS
// =============================================================================

// Endpoint to handle blood request notifications to nearby facilities
app.post('/api/notifications/blood-request', async (req, res) => {
    try {
        console.log('📧 Processing blood request notification...');
        
        const {
            requestId,
            bloodGroup,
            unitsNeeded,
            urgencyLevel,
            medicalReason,
            hospitalName,
            requiredByDate,
            patientLocation,
            nearbyFacilities
        } = req.body;

        // Validate required fields
        if (!requestId || !bloodGroup || !unitsNeeded || !nearbyFacilities) {
            return res.status(400).json({
                success: false,
                error: 'Missing required notification data'
            });
        }

        // Store notification in database for tracking
        const notificationData = {
            request_id: requestId,
            blood_group: bloodGroup,
            units_needed: unitsNeeded,
            urgency_level: urgencyLevel,
            medical_reason: medicalReason,
            hospital_name: hospitalName,
            required_by_date: requiredByDate,
            patient_latitude: patientLocation.latitude,
            patient_longitude: patientLocation.longitude,
            facilities_notified: nearbyFacilities.length,
            notification_sent_at: new Date().toISOString(),
            status: 'sent'
        };

        // In a real implementation, you would:
        // 1. Send emails to nearby blood banks
        // 2. Send SMS notifications
        // 3. Push notifications to blood bank apps
        // 4. Store in notifications table

        // For demo, we'll simulate the notification process
        const notificationResults = [];
        
        for (const facility of nearbyFacilities) {
            // Simulate sending notification to each facility
            const notification = {
                facilityId: facility.id,
                facilityName: facility.name,
                facilityAddress: facility.address,
                distance: facility.distance,
                category: facility.category,
                notificationMethod: facility.category === 'blood_bank' ? 'email+sms' : 'email',
                status: 'sent',
                sentAt: new Date().toISOString()
            };
            
            notificationResults.push(notification);
            
            // Log the notification (in production, this would be actual email/SMS)
            console.log(`📧 Notification sent to ${facility.name} (${facility.category}) - ${facility.distance}km away`);
        }

        // Priority notifications for critical requests
        if (urgencyLevel === 'critical') {
            console.log('🚨 CRITICAL BLOOD REQUEST - Priority notifications sent!');
            
            // Send additional notifications to:
            // 1. Regional blood centers
            // 2. Emergency contact lists
            // 3. Volunteer donor networks
        }

        // Return success response
        res.json({
            success: true,
            message: `Blood request notifications sent successfully`,
            data: {
                requestId: requestId,
                bloodGroup: bloodGroup,
                unitsNeeded: unitsNeeded,
                urgencyLevel: urgencyLevel,
                facilitiesNotified: nearbyFacilities.length,
                notifications: notificationResults,
                priorityAlert: urgencyLevel === 'critical',
                estimatedResponseTime: urgencyLevel === 'critical' ? '1-2 hours' : 
                                     urgencyLevel === 'urgent' ? '4-8 hours' : '24-48 hours'
            }
        });

    } catch (error) {
        console.error('❌ Notification processing error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to process notifications',
            details: error.message
        });
    }
});

// Get notification history for a blood request
app.get('/api/notifications/request/:requestId', async (req, res) => {
    try {
        const { requestId } = req.params;
        
        // In a real implementation, fetch from notifications table
        // For now, return sample data
        const notifications = [
            {
                id: 'notif_001',
                requestId: requestId,
                facilityName: 'City General Hospital Blood Bank',
                facilityType: 'blood_bank',
                distance: '2.3 km',
                notificationSent: '2025-10-04T15:30:00Z',
                status: 'sent',
                response: null
            },
            {
                id: 'notif_002',
                requestId: requestId,
                facilityName: 'Regional Medical Center',
                facilityType: 'hospital',
                distance: '4.7 km',
                notificationSent: '2025-10-04T15:30:00Z',
                status: 'sent',
                response: null
            }
        ];

        res.json({
            success: true,
            requestId: requestId,
            notifications: notifications,
            totalNotified: notifications.length
        });

    } catch (error) {
        console.error('❌ Notification history error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch notification history'
        });
    }
});

// Send emergency broadcast for critical blood requests
app.post('/api/notifications/emergency-broadcast', async (req, res) => {
    try {
        const {
            requestId,
            bloodGroup,
            unitsNeeded,
            hospitalName,
            contactNumber,
            radius = 25000 // 25km for emergency broadcasts
        } = req.body;

        // Emergency broadcast logic
        console.log(`🚨 EMERGENCY BROADCAST: ${bloodGroup} blood needed - ${unitsNeeded} units`);
        console.log(`🏥 Hospital: ${hospitalName}`);
        console.log(`📞 Contact: ${contactNumber}`);
        console.log(`📍 Broadcast radius: ${radius/1000}km`);

        // In production, this would:
        // 1. Send push notifications to all registered donors in the area
        // 2. Post to social media emergency accounts
        // 3. Contact local news stations
        // 4. Alert all blood banks in the region
        // 5. Trigger automated calling system

        res.json({
            success: true,
            message: 'Emergency broadcast initiated',
            broadcastId: `emergency_${Date.now()}`,
            estimatedReach: 5000, // Estimated people reached
            channels: ['push_notifications', 'sms', 'email', 'social_media'],
            priority: 'CRITICAL'
        });

    } catch (error) {
        console.error('❌ Emergency broadcast error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to initiate emergency broadcast'
        });
    }
});

app.listen(PORT, '0.0.0.0', () => {
    // Get the actual network IP address
    const networkInterfaces = os.networkInterfaces();
    let localIP = 'localhost';
    
    // Find the first non-internal IPv4 address
    for (const interfaceName in networkInterfaces) {
        const addresses = networkInterfaces[interfaceName];
        for (const address of addresses) {
            if (address.family === 'IPv4' && !address.internal) {
                localIP = address.address;
                break;
            }
        }
        if (localIP !== 'localhost') break;
    }
    
    console.log(`🩸 Blood Bank API Server running on port ${PORT}`);
    console.log(`🌐 Server accessible at: http://${localIP}:${PORT}`);
    console.log(`🌐 Localhost access: http://localhost:${PORT}`);
    console.log(`🔗 Supabase URL: ${supabaseUrl}`);
});

module.exports = app;
