# 🦅 Student Phoenix — Phoenix Brain

## 1. Vision

Student Phoenix is an academic operating platform designed to bring
student and faculty academic workflows into one system.

## 2. Core Users

- Student
- Faculty
- Admin

## 3. MVP

- Authentication
- Role-based access
- Student Dashboard
- Timetable
- Courses
- Assignments
- Notes & Observations
- Quizzes
- Manual Attendance
- Basic Analytics

## 4. V1

- Coding Environment
- Coding Error Journal
- Exam System
- Lab Session Management
- Reports
- Notifications

## 5. V2

- Lab Computer Client
- Real-Time Lab Monitoring
- Exam Monitoring & Alerts
- Phoenix AI
- Advanced Analytics

## 6. Technology Stack

### Frontend
React
Vite
TypeScript

### Backend
NestJS
TypeScript

### Database
PostgreSQL
Prisma

### Future Infrastructure
Socket.IO
Redis
Docker
Piston/Judge0
Phoenix AI

## 7. Development Principle

AI assists development, but humans remain responsible for
architecture, understanding, testing and final decisions.

## 8. Current Stage

Phase 1.5 — Architecture Lock

## 9. Current Goal

Establish scalable, modular frontend and backend architectural blueprints
and prepare database configurations before introducing feature code.

## 10. Architectural Principles & Decisions (Phase 1.5 Lock)

### Core Rules (Non-Negotiable)
- **Frontend**: React + Vite + TypeScript. Layered architecture: `components/`, `layouts/`, `pages/`, `features/`, `hooks/`, `services/`, `lib/`, `types/`.
- **Backend**: NestJS + TypeScript. Domain-driven modules under `src/modules/` and cross-cutting concerns under `src/common/`.
- **Database**: PostgreSQL with Prisma ORM. Schema migrations and models to be introduced strictly phase-by-phase.
- **API Style**: REST API as the primary backend protocol.
- **Real-Time**: Socket.IO isolated strictly to real-time features (lab monitoring, live session alerts).
- **Security & Auth (Upcoming)**: Stateless JWT access tokens + persistent refresh tokens with Role-Based Access Control (RBAC).
- **Separation of Concerns**: Controllers handle transport only; business logic resides strictly in domain services.
- **Configuration & Secrets**: Centralized environment-driven configuration; no secrets in source code.

## 11. Important Rule

Do not build the entire platform at once.

Build one feature at a time, test it, understand it,
document it and commit it.