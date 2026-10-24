# Global Delivery Services - Netlify version

Netlify cannot run a normal Express server, so this version runs the same code as a
Netlify Function (see netlify/functions/api.js). The pages in `public` are served by Netlify,
and all /api/... requests go to the function. A permanent PostgreSQL database is REQUIRED.

## Step 1 - Free online database (Neon)
1. Create a free account at neon.tech and make a project.
2. Copy the connection string (starts with postgresql://). Prefer the "pooled" one if shown.

## Step 2 - Put the project on GitHub
1. Create a free GitHub account and a new repository.
2. Upload ALL files in this folder (server.js, app.js, netlify.toml, package.json, public, netlify...).
   Do NOT upload node_modules.

## Step 3 - Netlify
1. At netlify.com choose Add new site > Import an existing project > GitHub > pick your repository.
2. Leave the build settings as they are (netlify.toml sets everything).
3. BEFORE deploying, open Site configuration > Environment variables and add:
   - DATABASE_URL    = the Neon connection string
   - SESSION_SECRET  = any long random text (30+ characters)
   - ADMIN_USERNAME  = admin
   - ADMIN_PASSWORD  = a strong password (used only to create the first admin)
4. Deploy.
5. Customers: https://YOUR-SITE.netlify.app      Staff: https://YOUR-SITE.netlify.app/staff

## Before real customers
- Edit public/config.js with your real phone, WhatsApp, email, address and hours.
- Replace public/logo.svg with your own logo.
- After the first admin exists you may delete ADMIN_PASSWORD from the environment variables.

## Run on your own computer (testing)
npm install
$env:ADMIN_PASSWORD="choose-a-strong-password"; npm start      (first time only needs the password)
Then open http://localhost:3000 and http://localhost:3000/staff
Without DATABASE_URL it uses the local file noxin.db.
