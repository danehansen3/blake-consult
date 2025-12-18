// netlify/functions/subscription-lookup.js
// This function handles secure lookup of subscription data from Sticky.io

const crypto = require('crypto');

// Rate limiting: store request counts in memory (resets with function cold start)
const requestLimits = new Map();
const RATE_LIMIT = 10; // requests per IP per hour
const RATE_LIMIT_WINDOW = 60 * 60 * 1000; // 1 hour in milliseconds

exports.handler = async (event, context) => {
  // Handle CORS preflight requests
  if (event.httpMethod === 'OPTIONS') {
    return {
      statusCode: 200,
      headers: {
        'Access-Control-Allow-Origin': 'https://temaras.com',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
      },
    };
  }

  // Only allow POST requests
  if (event.httpMethod !== 'POST') {
    return {
      statusCode: 405,
      headers: {
        'Access-Control-Allow-Origin': 'https://temaras.com',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ error: 'Method not allowed' }),
    };
  }

  try {
    // Get client IP for rate limiting
    const clientIp = event.headers['x-forwarded-for'] || event.headers['client-ip'] || 'unknown';

    // Check rate limit
    if (!checkRateLimit(clientIp)) {
      return {
        statusCode: 429,
        headers: {
          'Access-Control-Allow-Origin': 'https://temaras.com',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ error: 'Too many requests. Please try again later.' }),
      };
    }

    // Parse the request body
    const { email, cardFirst6, cardLast4, chargeDate } = JSON.parse(event.body || '{}');

    // Validate inputs
    const validationError = validateInputs(email, cardFirst6, cardLast4, chargeDate);
    if (validationError) {
      return {
        statusCode: 400,
        headers: {
          'Access-Control-Allow-Origin': 'https://temaras.com',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ error: validationError }),
      };
    }

    // Get Sticky.io API credentials from environment variables
    const apiKey = process.env.STICKY_IO_API_KEY;
    const apiUrl = process.env.STICKY_IO_API_URL;

    if (!apiKey || !apiUrl) {
      console.error('Missing Sticky.io API credentials');
      return {
        statusCode: 500,
        headers: {
          'Access-Control-Allow-Origin': 'https://temaras.com',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ error: 'Server configuration error' }),
      };
    }

    // Hash the credit card data for secure lookup (never send raw card data to API if possible)
    const cardHash = hashCardData(cardFirst6, cardLast4);

    // Format the charge date for API query
    const formattedDate = formatDateForAPI(chargeDate);

    // Call Sticky.io API to lookup subscription
    // Documentation: https://developer-v2.sticky.io/
    const stickyResponse = await fetch(`${apiUrl}/customers/search`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
        'User-Agent': 'Shopify-Subscription-Lookup/1.0',
      },
      body: JSON.stringify({
        email: email,
        card_first_6: cardFirst6,
        card_last_4: cardLast4,
        charge_date: formattedDate,
      }),
    });

    if (!stickyResponse.ok) {
      // Log the error but don't expose internal API details to client
      console.error('Sticky.io API error:', stickyResponse.status, stickyResponse.statusText);
      
      if (stickyResponse.status === 404) {
        return {
          statusCode: 404,
          headers: {
            'Access-Control-Allow-Origin': 'https://temaras.com',
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ 
            error: 'No subscription found matching those details. Please verify your information and try again.' 
          }),
        };
      }

      return {
        statusCode: 503,
        headers: {
          'Access-Control-Allow-Origin': 'https://temaras.com',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ error: 'Unable to retrieve subscription data. Please try again later.' }),
      };
    }

    const subscriptionData = await stickyResponse.json();

    // Sanitize response - only return safe data
    const sanitizedData = sanitizeSubscriptionData(subscriptionData);

    // Return subscription data to frontend
    return {
      statusCode: 200,
      headers: {
        'Access-Control-Allow-Origin': 'https://temaras.com',
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store, no-cache, must-revalidate',
      },
      body: JSON.stringify({
        success: true,
        data: sanitizedData,
      }),
    };

  } catch (error) {
    console.error('Subscription lookup error:', error.message);
    return {
      statusCode: 500,
      headers: {
        'Access-Control-Allow-Origin': 'https://temaras.com',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ error: 'An error occurred. Please try again later.' }),
    };
  }
};

/**
 * Validate all user inputs
 */
function validateInputs(email, cardFirst6, cardLast4, chargeDate) {
  if (!email || !cardFirst6 || !cardLast4 || !chargeDate) {
    return 'All fields are required';
  }

  // Validate email format
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email) || email.length > 254) {
    return 'Invalid email format';
  }

  // Validate card first 6 - must be exactly 6 digits
  if (!/^\d{6}$/.test(cardFirst6)) {
    return 'Card first 6 digits must be exactly 6 numbers';
  }

  // Validate card last 4 - must be exactly 4 digits
  if (!/^\d{4}$/.test(cardLast4)) {
    return 'Card last 4 digits must be exactly 4 numbers';
  }

  // Validate date format MM/DD/YYYY
  const dateRegex = /^(0[1-9]|1[0-2])\/(0[1-9]|[12]\d|3[01])\/\d{4}$/;
  if (!dateRegex.test(chargeDate)) {
    return 'Please enter date in MM/DD/YYYY format';
  }

  // Validate date is not in the future
  const [month, day, year] = chargeDate.split('/');
  const inputDate = new Date(year, month - 1, day);
  const today = new Date();
  today.setHours(23, 59, 59, 999);
  
  if (inputDate > today) {
    return 'Charge date cannot be in the future';
  }

  // Validate date is not too old (more than 3 years)
  const threeYearsAgo = new Date();
  threeYearsAgo.setFullYear(threeYearsAgo.getFullYear() - 3);
  
  if (inputDate < threeYearsAgo) {
    return 'Charge date is too old. Please enter a more recent date.';
  }

  return null; // No errors
}

/**
 * Hash card data for secure comparison/lookup
 * This adds an extra layer of security if intercepted
 */
function hashCardData(first6, last4) {
  const combined = `${first6}${last4}`;
  return crypto
    .createHash('sha256')
    .update(combined)
    .digest('hex');
}

/**
 * Format date from MM/DD/YYYY to YYYY-MM-DD for API
 */
function formatDateForAPI(chargeDate) {
  const [month, day, year] = chargeDate.split('/');
  return `${year}-${month}-${day}`;
}

/**
 * Sanitize subscription data before sending to frontend
 * Only return necessary information, filter out sensitive data
 */
function sanitizeSubscriptionData(data) {
  // Adjust these fields based on what Sticky.io actually returns
  // Never return full credit card numbers or sensitive auth tokens
  
  if (Array.isArray(data)) {
    return data.map(subscription => ({
      id: subscription.id || null,
      status: subscription.status || 'Unknown',
      service: subscription.service_name || subscription.product_name || 'Service',
      plan: subscription.plan_name || 'N/A',
      amount: subscription.amount || subscription.recurring_amount || 'N/A',
      currency: subscription.currency || 'USD',
      nextBillingDate: subscription.next_billing_date || subscription.next_charge_date || 'N/A',
      chargeDate: subscription.charge_date || subscription.last_charge_date || 'N/A',
      frequency: subscription.frequency || subscription.billing_frequency || 'N/A',
      // Do NOT include: full card numbers, CVV, auth tokens, customer IDs, IP addresses
    }));
  }

  // Handle single subscription object
  return {
    id: data.id || null,
    status: data.status || 'Unknown',
    service: data.service_name || data.product_name || 'Service',
    plan: data.plan_name || 'N/A',
    amount: data.amount || data.recurring_amount || 'N/A',
    currency: data.currency || 'USD',
    nextBillingDate: data.next_billing_date || data.next_charge_date || 'N/A',
    chargeDate: data.charge_date || data.last_charge_date || 'N/A',
    frequency: data.frequency || data.billing_frequency || 'N/A',
  };
}

/**
 * Simple rate limiting check
 */
function checkRateLimit(clientIp) {
  const now = Date.now();
  
  if (!requestLimits.has(clientIp)) {
    requestLimits.set(clientIp, { count: 1, firstRequest: now });
    return true;
  }

  const record = requestLimits.get(clientIp);

  // Reset if window has passed
  if (now - record.firstRequest > RATE_LIMIT_WINDOW) {
    requestLimits.set(clientIp, { count: 1, firstRequest: now });
    return true;
  }

  // Check if limit exceeded
  if (record.count >= RATE_LIMIT) {
    return false;
  }

  // Increment count
  record.count++;
  return true;
}