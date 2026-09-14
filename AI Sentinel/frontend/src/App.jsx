import { Navigate, Route, Routes } from 'react-router-dom';
import DashboardPage from './components/DashboardPage';
import LoginPage from './components/LoginPage';
import ProtectedRoute from './components/ProtectedRoute';
import EventsPage from './components/EventsPage';
import AlertsPage from './components/AlertsPage';
import IncidentsPage from './components/IncidentsPage';
import IncidentDetailPage from './components/IncidentDetailPage';
import HostsPage from './components/HostsPage';
import HostDetailPage from './components/HostDetailPage';
import ReportsPage from './components/ReportsPage';
import RulesPage from './components/RulesPage';
import PhishingPage from './components/PhishingPage';
import NetworkPage from './components/NetworkPage';
import AssistantPage from './components/AssistantPage';
import SystemPage from './components/SystemPage';
import SearchPage from './components/SearchPage';
import ThreatHuntingPage from './components/ThreatHuntingPage';
import IocPage from './components/IocPage';
import ApprovalsPage from './components/ApprovalsPage';
import SlaPage from './components/SlaPage';
import MitrePage from './components/MitrePage';
import PosturePage from './components/PosturePage';
import DataQualityPage from './components/DataQualityPage';
import CasesPage from './components/CasesPage';
import EvidencePage from './components/EvidencePage';
import TasksPage from './components/TasksPage';
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
      <Route path="/hosts/:hostname" element={<ProtectedRoute><HostDetailPage /></ProtectedRoute>} />
      <Route path="/reports" element={<ProtectedRoute><ReportsPage /></ProtectedRoute>} />
      <Route path="/rules" element={<ProtectedRoute><RulesPage /></ProtectedRoute>} />
      <Route path="/phishing" element={<ProtectedRoute><PhishingPage /></ProtectedRoute>} />
      <Route path="/network" element={<ProtectedRoute><NetworkPage /></ProtectedRoute>} />
      <Route path="/assistant" element={<ProtectedRoute><AssistantPage /></ProtectedRoute>} />
      <Route path="/search" element={<ProtectedRoute><SearchPage /></ProtectedRoute>} />
      <Route path="/hunts" element={<ProtectedRoute><ThreatHuntingPage /></ProtectedRoute>} />
      <Route path="/iocs" element={<ProtectedRoute><IocPage /></ProtectedRoute>} />
      <Route path="/approvals" element={<ProtectedRoute><ApprovalsPage /></ProtectedRoute>} />
      <Route path="/sla" element={<ProtectedRoute><SlaPage /></ProtectedRoute>} />
      <Route path="/mitre" element={<ProtectedRoute><MitrePage /></ProtectedRoute>} />
      <Route path="/posture" element={<ProtectedRoute><PosturePage /></ProtectedRoute>} />
      <Route path="/data-quality" element={<ProtectedRoute><DataQualityPage /></ProtectedRoute>} />
      <Route path="/cases" element={<ProtectedRoute><CasesPage /></ProtectedRoute>} />
      <Route path="/evidence" element={<ProtectedRoute><EvidencePage /></ProtectedRoute>} />
      <Route path="/tasks" element={<ProtectedRoute><TasksPage /></ProtectedRoute>} />
      <Route path="/system" element={<ProtectedRoute><SystemPage /></ProtectedRoute>} />
      <Route path="/login" element={isAuthenticated() ? <Navigate to="/" replace /> : <LoginPage />} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
