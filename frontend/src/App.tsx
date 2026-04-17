import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './contexts/AuthContext';
import ProtectedRoute from './components/ProtectedRoute';
import Login from './pages/Login';
import AdminDashboard from './pages/AdminDashboard';
import AdminIOCs from './pages/AdminIOCs';
import AdminAnalysts from './pages/AdminAnalysts';
import AdminSettings from './pages/AdminSettings';
import AdminRules from './pages/AdminRules';
import AdminCampaigns from './pages/AdminCampaigns';
import AnalystDashboard from './pages/AnalystDashboard';
import SubmitIOC from './pages/SubmitIOC';
import MyCampaigns from './pages/MyCampaigns';

function LoginGuard() {
  const { isAuthenticated, user } = useAuth();
  if (isAuthenticated && user) {
    return <Navigate to={user.role === 'admin' ? '/admin' : '/analyst'} replace />;
  }
  return <Login />;
}

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<LoginGuard />} />

          {/* ── Admin routes ── */}
          <Route path="/admin" element={
            <ProtectedRoute requiredRole="admin"><AdminDashboard /></ProtectedRoute>
          }/>
          <Route path="/admin/iocs" element={
            <ProtectedRoute requiredRole="admin"><AdminIOCs /></ProtectedRoute>
          }/>
          <Route path="/admin/analysts" element={
            <ProtectedRoute requiredRole="admin"><AdminAnalysts /></ProtectedRoute>
          }/>
          <Route path="/admin/settings" element={
            <ProtectedRoute requiredRole="admin"><AdminSettings /></ProtectedRoute>
          }/>
          <Route path="/admin/rules" element={
            <ProtectedRoute requiredRole="admin"><AdminRules /></ProtectedRoute>
          }/>
          <Route path="/admin/campaigns" element={
            <ProtectedRoute requiredRole="admin"><AdminCampaigns /></ProtectedRoute>
          }/>

          {/* ── Analyst routes ── */}
          <Route path="/analyst" element={
            <ProtectedRoute requiredRole="analyst"><AnalystDashboard /></ProtectedRoute>
          }/>
          <Route path="/analyst/submit" element={
            <ProtectedRoute requiredRole="analyst"><SubmitIOC /></ProtectedRoute>
          }/>
          <Route path="/analyst/campaigns" element={
            <ProtectedRoute requiredRole="analyst"><MyCampaigns /></ProtectedRoute>
          }/>

          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}