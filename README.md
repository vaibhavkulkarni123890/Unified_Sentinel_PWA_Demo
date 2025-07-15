---

# Unified Sentinel – PWA for Smart Retail

A Progressive Web App that detects and prevents fraudulent returns/replacements in retail workflows.  
Frontend is built with **React.js** and deployed as a PWA; backend APIs are powered by **Crow (C++)** for high-performance request handling.

---

## 🔧 Tech Stack

- **Frontend:** React 18, Vite, PWA (Service Workers + Manifest)
- **Backend:** C++20, Crow Web Framework, MongoDB C++ Driver
- **Database:** MongoDB Atlas (or local instance)
- **Build Tools:** CMake, vcpkg
- **Deployment:** Firebase Hosting (frontend), self-hosted or Docker container (backend)

---

## ✨ Features

- Fraud Detection APIs: Crow routes expose `/api/validate`, `/api/returns`, etc.
- Installable PWA: Works offline and syncs when reconnected.
- Secure Workflow: Input validation, JWT-based Crow middleware.
- Scalable & Modular: Backend is stateless and deployable on containers or VMs.

---

## 📂 Folder Structure

```
unified-sentinel/
├── frontend/          # React PWA
│   ├── src/
│   └── public/
└── backend-crow/      # C++ Crow API
    ├── CMakeLists.txt
    ├── src/
    │   ├── main.cpp
    │   └── routes/
    └── include/
```

---

## 🛠️ Backend Setup (Crow C++)

```bash
# Install vcpkg and dependencies
sudo apt update && sudo apt install build-essential cmake git
git clone https://github.com/microsoft/vcpkg.git
./vcpkg/bootstrap-vcpkg.sh
./vcpkg/vcpkg install crow mongo-cxx-driver

# Build project
cd backend-crow
cmake -Bbuild -DCMAKE_TOOLCHAIN_FILE=../vcpkg/scripts/buildsystems/vcpkg.cmake
cmake --build build
./build/unified-sentinel-api
```

---

## 🚀 Frontend Setup (React PWA)

```bash
cd frontend
npm install
npm run dev      # for development
npm run build    # for production build
```

---
