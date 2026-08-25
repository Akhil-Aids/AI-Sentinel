import { Navigate, Route, Routes } from 'react-router-dom';
import DashboardPage from './components/DashboardPage';
import LoginPage from './components/LoginPage';
import ProtectedRoute from './components/ProtectedRoute';
import EventsPage from './components/EventsPage';
import AlertsPage from './components/AlertsPage';
import IncidentsPage from './components/IncidentsPage';
import IncidentDetailPage from './components/IncidentDetailPage';
import HostsPage from './components/HostsPage';
import RulesPage from './components/RulesPage';
import PhishingPage from './components/PhishingPage';
import NetworkPage from './components/NetworkPage';
import AssistantPage from './components/AssistantPage';
import SystemPage from './components/SystemPage';
import { isAuthenticated } from './api';

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<ProtectedRoute><DashboardPage /></ProtectedRoute>} />
      <Route path="/events" element={<ProtectedRoute><EventsPage /></ProtectedRoute>} />
      <Route path="/alerts" element={<ProtectedRoute><AlertsPage /></ProtectedRoute>} />
      <Route path="/incidents" element={<ProtectedRoute><IncidentsPage /></ProtectedRoute>} />
      <Route path="/incidents/:id" element={<ProtectedRoute><IncidentDetailPage /></ProtectedRoute>} />
      <Route path="/hosts" element={<ProtectedRoute><HostsPage /></ProtectedRoute>} />
      <Route path="/rules" element={<ProtectedRoute><RulesPage /></ProtectedRoute>} />
      <Route path="/phishing" element={<ProtectedRoute><PhishingPage /></ProtectedRoute>} />
      <Route path="/network" element={<ProtectedRoute><NetworkPage /></ProtectedRoute>} />
      <Route path="/assistant" element={<ProtectedRoute><AssistantPage /></ProtectedRoute>} />
      <Route path="/system" element={<ProtectedRoute><SystemPage /></ProtectedRoute>} />
      <Route path="/login" element={isAuthenticated() ? <Navigate to="/" replace /> : <LoginPage />} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
