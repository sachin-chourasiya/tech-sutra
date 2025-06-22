const Hapi = require('@hapi/hapi');
const Jwt = require('@hapi/jwt');
const Joi = require('@hapi/joi');
const Boom = require('@hapi/boom');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// Mock user database - In production, use a real database
const users = [
  {
    id: 1,
    email: 'client@example.com',
    password: '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', // password
    role: 'client',
    name: 'John Client'
  },
  {
    id: 2,
    email: 'developer@example.com',
    password: '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', // password
    role: 'developer',
    name: 'Jane Developer'
  },
  {
    id: 3,
    email: 'admin@example.com',
    password: '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', // password
    role: 'admin',
    name: 'Admin User'
  }
];

// JWT Secret - In production, use environment variable
const JWT_SECRET = 'your-super-secret-jwt-key-change-this-in-production';

const init = async () => {
  const server = Hapi.server({
    port: 4000,
    host: 'localhost',
    routes: {
      cors: {
        origin: ['http://localhost:3001'], // Next.js frontend URL
        credentials: true
      }
    }
  });

  // Register JWT plugin
  await server.register(Jwt);

  // JWT authentication strategy
  server.auth.strategy('jwt', 'jwt', {
    keys: JWT_SECRET,
    verify: {
      aud: 'urn:audience:techsutra',
      iss: 'urn:issuer:techsutra',
      sub: false,
      nbf: true,
      exp: true,
      maxAgeSec: 14400, // 4 hours
      timeSkewSec: 15
    },
    validate: async (artifacts, request, h) => {
      // Validate the user still exists and is active
      const user = users.find(u => u.id === artifacts.decoded.payload.userId);
      if (!user) {
        return { isValid: false };
      }

      return {
        isValid: true,
        credentials: {
          userId: user.id,
          email: user.email,
          role: user.role,
          name: user.name
        }
      };
    }
  });

  // Set default auth strategy
  server.auth.default('jwt');

  // Helper function to generate JWT token
  const generateToken = (user) => {
    const payload = {
      userId: user.id,
      email: user.email,
      role: user.role,
      name: user.name
    };

    return jwt.sign(payload, JWT_SECRET, {
      expiresIn: '4h',
      issuer: 'urn:issuer:techsutra',
      audience: 'urn:audience:techsutra'
    });
  };

  // Login route (no auth required)
  server.route({
    method: 'POST',
    path: '/api/login',
    options: {
      auth: false,
      validate: {
        payload: Joi.object({
          email: Joi.string().email().required(),
          password: Joi.string().min(6).required()
        })
      }
    },
    handler: async (request, h) => {
      const { email, password } = request.payload;

      try {
        // Find user by email
        const user = users.find(u => u.email.toLowerCase() === email.toLowerCase());
        if (!user) {
          return h.response({
            success: false,
            message: 'Invalid email or password'
          }).code(401);
        }

        // Verify password
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
          return h.response({
            success: false,
            message: 'Invalid email or password'
          }).code(401);
        }

        // Generate JWT token
        const token = generateToken(user);

        // Return success response
        return h.response({
          success: true,
          message: 'Login successful',
          data: {
            token,
            user: {
              id: user.id,
              email: user.email,
              role: user.role,
              name: user.name
            }
          }
        }).code(200);

      } catch (error) {
        console.error('Login error:', error);
        return h.response({
          success: false,
          message: 'Internal server error'
        }).code(500);
      }
    }
  });

  // Protected route to get user profile
  server.route({
    method: 'GET',
    path: '/api/profile',
    handler: async (request, h) => {
      const { credentials } = request.auth;

      return h.response({
        success: true,
        data: {
          user: credentials
        }
      }).code(200);
    }
  });

  // Protected route to verify token
  server.route({
    method: 'GET',
    path: '/api/verify',
    handler: async (request, h) => {
      const { credentials } = request.auth;

      return h.response({
        success: true,
        message: 'Token is valid',
        data: {
          user: credentials
        }
      }).code(200);
    }
  });

  // Role-based protected routes
  server.route({
    method: 'GET',
    path: '/api/admin/users',
    options: {
      pre: [
        {
          method: (request, h) => {
            if (request.auth.credentials.role !== 'admin') {
              throw Boom.forbidden('Admin access required');
            }
            return h.continue;
          }
        }
      ]
    },
    handler: async (request, h) => {
      // Return user list (admin only)
      const userList = users.map(user => ({
        id: user.id,
        email: user.email,
        role: user.role,
        name: user.name
      }));

      return h.response({
        success: true,
        data: { users: userList }
      }).code(200);
    }
  });

  // Health check route (no auth required)
  server.route({
    method: 'GET',
    path: '/api/health',
    options: {
      auth: false
    },
    handler: async (request, h) => {
      return h.response({
        success: true,
        message: 'Server is running',
        timestamp: new Date().toISOString()
      }).code(200);
    }
  });

  await server.start();
  console.log('🚀 Hapi.js server running on %s', server.info.uri);
  console.log('📋 Available test accounts:');
  console.log('   Client: client@example.com / password');
  console.log('   Developer: developer@example.com / password');
  console.log('   Admin: admin@example.com / password');
};

process.on('unhandledRejection', (err) => {
  console.log(err);
  process.exit(1);
});

init();
