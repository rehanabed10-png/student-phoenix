# 🦅 Student Phoenix

**Student Phoenix** is an Academic Operating Platform designed to bring student and faculty academic workflows into a unified, reliable system.

---

## 📌 Development Philosophy & Status

Student Phoenix is developed strictly **phase-by-phase**. Each phase focuses on building, testing, verifying, and documenting a foundational capability before progressing to the next.

- **Current Stage**: Phase 1 — Project Foundation
- **Current Objective**: Establish a clean, modular full-stack foundation with independent frontend and backend workspaces.

---

## 🛠️ Technology Stack (Phase 1)

### Frontend
- **Framework**: [React](https://react.dev/)
- **Build Tool**: [Vite](https://vitejs.dev/)
- **Language**: [TypeScript](https://www.typescriptlang.org/)

### Backend
- **Framework**: [NestJS](https://nestjs.com/)
- **Language**: [TypeScript](https://www.typescriptlang.org/)
- **Platform**: Node.js

### Database & Future Infrastructure (Planned for subsequent phases)
- PostgreSQL + Prisma ORM (Planned)
- Socket.IO, Redis, Docker, AI capabilities (Planned for future phases)

---

## 📁 Repository Structure

```text
student-phoenix/
├── frontend/         # React + Vite + TypeScript application
├── backend/          # NestJS + TypeScript API application
├── docs/             # Architecture and platform documentation
│   └── PHOENIX_BRAIN.md
├── .env.example      # Environment variables template
├── .gitignore        # Root git ignore rules
└── README.md         # Project documentation
```

---

## 🚀 Getting Started

### Prerequisites
- [Node.js](https://nodejs.org/) (v20+ recommended)
- [npm](https://www.npmjs.com/)

---

### Running the Frontend

1. Navigate to the frontend directory:
   ```bash
   cd frontend
   ```
2. Install dependencies:
   ```bash
   npm install
   ```
3. Start the Vite development server:
   ```bash
   npm run dev
   ```
4. Build for production:
   ```bash
   npm run build
   ```

---

### Running the Backend

1. Navigate to the backend directory:
   ```bash
   cd backend
   ```
2. Install dependencies:
   ```bash
   npm install
   ```
3. Start the NestJS development server:
   ```bash
   npm run start:dev
   ```
4. Build for production:
   ```bash
   npm run build
   ```
5. Check service health:
   ```bash
   curl http://localhost:3000/health
   ```
   Expected response:
   ```json
   {
     "status": "ok",
     "service": "student-phoenix-api"
   }
   ```

---

## 🔒 Security & Secrets

Do not commit sensitive configuration or secrets to the repository. Use local `.env` files based on `.env.example`.
