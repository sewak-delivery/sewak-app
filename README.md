# SEWAK – Local Shopping & Delivery

Bilingual Hindi/English mobile-first web app for Dalmau and Murai Bagh.

## Run locally
1. Use Node.js 20+ and PostgreSQL.
2. Create a PostgreSQL database and run `schema.sql`.
3. Copy `.env.example` to `.env` and enter real credentials.
4. Run `npm install`, then `npm start`.
5. Open `http://localhost:8080`.

## API
- `GET /api/health`
- `POST /api/auth/request-otp` and `POST /api/auth/verify-otp`
- `GET /api/shops` and `GET /api/shops/:id/products`
- Customer orders, shop-owner order management and delivery-partner endpoints are in `server.js`.

## Deployment
Deploy this Node.js service to a Node-compatible host and attach a PostgreSQL database. Set the environment variables listed in `.env.example`. Run `schema.sql` on the production database before opening the app. Review hosting and database pricing before creating paid resources.

## Before public launch
Configure a real SMS OTP provider and comply with Indian SMS/DLT requirements. Create verified shop and delivery accounts using a secure admin process; do not allow users to choose privileged roles. Add real shop/product/inventory data, set an approved delivery fee, test Razorpay in test mode, and add privacy, support, backups and monitoring. Never commit secrets.
