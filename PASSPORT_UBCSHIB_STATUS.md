# Passport UBC Shibboleth Integration Status

## ✅ What's Implemented

### 1. **Package Installation**
- ✅ `passport-ubcshib` installed
- ✅ `passport` installed
- ✅ `passport-saml` installed (dependency)

### 2. **Strategy Configuration** (`src/config/passport.js`)
- ✅ UBC Shibboleth Strategy configured
- ✅ Uses correct import pattern (with fallback)
- ✅ Configuration options match documentation:
  - ✅ `issuer` - Service Provider Identity
  - ✅ `callbackUrl` - Callback URL after authentication
  - ✅ `privateKeyPath` - Path to private key for signing
  - ✅ `attributeConfig` - Attribute selection (defaults to `['ubcEduCwlPuid', 'mail', 'eduPersonAffiliation']`)
  - ✅ `enableSLO` - Single logout support
  - ✅ `validateInResponseTo` - Response validation
  - ✅ `acceptedClockSkewMs` - Clock skew tolerance

### 3. **Routes** (`src/routes/auth.js`)
- ✅ `GET /api/auth/ubcshib` - Initiates UBC Shibboleth authentication
- ✅ `POST /api/auth/ubcshib/callback` - Handles callback from UBC IdP
- ✅ Role-based redirects (instructor/student/ta)
- ✅ Session management (backward compatible)

### 4. **Profile Handling**
- ✅ Extracts `profile.nameID`
- ✅ Extracts `profile.attributes.ubcEduCwlPuid`
- ✅ Extracts `profile.attributes.mail`
- ✅ Extracts `profile.attributes.eduPersonAffiliation`
- ✅ Role mapping from affiliation (faculty/staff → instructor, student → student)
- ✅ User creation/retrieval via `User.createOrGetSAMLUser()`

### 5. **Helper Middleware** (Available via `passport.ubcShibHelpers`)
- ✅ `ensureAuthenticated` - Available but not yet integrated into routes
- ✅ `logout` - Available but not yet integrated into logout route
- ✅ `conditionalAuth` - Available for future use

### 6. **Environment Variables Support**
- ✅ `SAML_ENVIRONMENT` or `UBC_SAML_ENVIRONMENT` (STAGING/PRODUCTION)
- ✅ `UBC_SAML_ISSUER` or `SAML_ISSUER`
- ✅ `UBC_SAML_CALLBACK_URL` or `SAML_CALLBACK_URL`
- ✅ `UBC_SAML_PRIVATE_KEY_PATH` or `SAML_PRIVATE_KEY_PATH`
- ✅ `UBC_SAML_ATTRIBUTES` (comma-separated list)
- ✅ `UBC_SAML_ENABLE_SLO`
- ✅ `UBC_SAML_VALIDATE_IN_RESPONSE_TO`
- ✅ `UBC_SAML_CLOCK_SKEW_MS`

## 📋 What's Missing (Optional Enhancements)

### 1. **Helper Middleware Integration**
The helper middleware is available but not yet used in routes. You can optionally:
- Use `passport.ubcShibHelpers.ensureAuthenticated()` for protected routes
- Use `passport.ubcShibHelpers.logout('/')` for logout (includes SLO support)
- Use `passport.ubcShibHelpers.conditionalAuth()` for conditional protection

**Note:** Our existing middleware (`requireAuth`, `requireRole`, etc.) already works and is backward compatible. The helper middleware is optional.

### 2. **Certificate Management**
- The library automatically fetches IdP certificates from metadata
- Manual certificate configuration is supported via `cert` option (not currently used)

## 🚀 How to Enable

### Step 1: Set Environment Variables

Add to your `.env` file:

```env
# UBC Shibboleth Configuration
SAML_ENVIRONMENT=STAGING  # or PRODUCTION
UBC_SAML_ISSUER=https://your-app.example.com/shibboleth
UBC_SAML_CALLBACK_URL=https://your-app.example.com/api/auth/ubcshib/callback
UBC_SAML_PRIVATE_KEY_PATH=/path/to/your/private.key

# Optional
UBC_SAML_ATTRIBUTES=ubcEduCwlPuid,mail,eduPersonAffiliation
UBC_SAML_ENABLE_SLO=true
UBC_SAML_VALIDATE_IN_RESPONSE_TO=true
UBC_SAML_CLOCK_SKEW_MS=0
```

### Step 2: Register with UBC IAM

1. Contact UBC IAM team
2. Provide your Service Provider metadata
3. Get your Entity ID (issuer) confirmed
4. Configure callback URL registration

### Step 3: Test

- **Staging:** Visit `https://authentication.stg.id.ubc.ca/idp/shibboleth` to see available attributes
- **Production:** Visit `https://authentication.ubc.ca/idp/shibboleth`

### Step 4: Access UBC Shibboleth Login

Users can authenticate via:
- `GET /api/auth/ubcshib` - Redirects to UBC IdP
- After authentication, redirects to appropriate dashboard based on role

## 📝 Differences from Documentation

1. **Import Pattern:** We use a try-catch with fallback for graceful degradation if package isn't available
2. **Route Paths:** We use `/api/auth/ubcshib` instead of `/auth/ubcshib` (matches our API structure)
3. **User Model:** We use our existing `User.createOrGetSAMLUser()` instead of a custom `findOrCreate`
4. **Session Storage:** We maintain backward compatibility by storing session data in the old format

## ✅ Status: **READY TO USE**

The integration is complete and matches the passport-ubcshib documentation. Once environment variables are configured and UBC IAM registration is complete, UBC Shibboleth authentication will work automatically.







