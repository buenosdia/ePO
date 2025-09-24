import React from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import Scripts from './pages/Scripts';
import Jobs from './pages/Jobs';
import Credentials from './pages/Credentials';

function RequireAuth({ children }: { children: JSX.Element }) {
  const { token, claims } = useAuth();
  if (!token || !claims) {
    return <Navigate to="/login" replace />;
  }
  const now = Date.now() / 1000;
  if (claims.exp && claims.exp < now) {
    return <Navigate to="/login" replace />;
  }
  return children;
}

createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/" element={<RequireAuth><Dashboard /></RequireAuth>} />
          <Route path="/scripts" element={<RequireAuth><Scripts /></RequireAuth>} />
          <Route path="/jobs" element={<RequireAuth><Jobs /></RequireAuth>} />
          <Route path="/credentials" element={<RequireAuth><Credentials /></RequireAuth>} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  </React.StrictMode>
);
