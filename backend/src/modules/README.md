# Student Phoenix — Backend Domain Modules

This directory houses domain-driven modules for the Student Phoenix platform. In accordance with the project development rules, modules are introduced strictly phase-by-phase when active requirements and database models are locked.

---

## 🏛️ Domain Architecture Roadmap

### MVP Domains (Phase 2+)
- `auth`: Authentication, JWT issuance, refresh token management, role enforcement.
- `users`: User entity management, profile data, role assignments (Student, Faculty, Admin).
- `timetable`: Academic schedules, class timings, and recurring lecture blocks.
- `courses`: Course catalogs, enrollments, syllabi, and section management.
- `assignments`: Homework briefs, submissions, grading statuses, and feedback.
- `notes`: Student academic notes, faculty observations, and attachments.
- `quizzes`: Quick assessments, multiple-choice questions, and score records.
- `attendance`: Manual and automated lecture attendance tracking.
- `analytics`: Foundational academic metrics and progress summaries.

### V1 Domains
- `coding`: In-browser programming problem sets and sandbox interfaces.
- `error-journal`: Tracking programming errors, explanations, and debugging insights.
- `exam`: Formal assessment orchestration, question banks, and timers.
- `lab-sessions`: Laboratory scheduling, workstation assignments, and lab agendas.
- `reports`: Academic transcripts, attendance summaries, and performance sheets.
- `notifications`: Multi-channel system alerts and message dispatches.

### V2 Domains & Infrastructure
- `monitoring`: Real-time lab computer client telemetries and live session tracking.
- `alerts`: Anomaly alerts, proctoring/exam monitoring triggers.
- `ai`: Phoenix AI assistance and workflow automations.
- `code-execution`: Secure sandbox execution (Piston / Judge0 / containerized runners).
- `files`: Document and asset storage management.
- `realtime`: Dedicated Socket.IO gateways for live telemetries and messaging.
- `audit-log`: Security and compliance audit trailing.
- `common`: Cross-cutting guards, interceptors, filters, and Prisma ORM integration (`src/common/`).

---

## 📐 Implementation Rules
1. **Separation of Concerns**: Controllers only handle HTTP routing and validation. All business logic belongs in Injectable Services.
2. **Database Access**: Direct database operations are encapsulated in services via `PrismaService`.
3. **No Premature Implementation**: Modules must NOT be scaffolded with dummy routes, speculative models, or mock data until their designated phase begins.
