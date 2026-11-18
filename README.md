# Scamurai – Think Before You Click

A rule-based scam detection and awareness website. The frontend uses plain HTML, CSS and JavaScript. The backend uses Node.js, Express and the existing rule-based analysis engine.

## Project structure

- `index.html` – website structure
- `src/styles.css` – styling
- `src/app.js` – browser interactions and API calls
- `server.ts` – Express API and scam-analysis rules

## Run locally

Requirements: Node.js 22.12 or newer.

1. Install dependencies: `npm install`
2. Start the backend in one terminal: `npm run dev:backend`
3. Start the frontend in a second terminal: `npm run dev`
4. Open the local Vite URL shown in the frontend terminal (usually `http://localhost:5173`).

The Vite development server forwards `/api` requests to the Express backend on port 3000.

## Deploy

- Frontend: deploy this repository to Vercel using the Vite preset, build command `npm run build`, and output directory `dist`. Set `VITE_API_BASE_URL` to the Render backend URL.
- Backend: deploy the same repository to Render as a Web Service. Build command: `npm install`. Start command: `npm start`. Set `FRONTEND_URL` to the Vercel frontend URL.

The backend listens on the `PORT` environment variable supplied by Render.
