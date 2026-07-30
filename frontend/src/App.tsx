import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import CoreLayout from '@/components/layout/CoreLayout';
import Agent from '@/pages/Agent';
import Sessions from '@/pages/Sessions';
import SessionDetail from '@/pages/SessionDetail';

const queryClient = new QueryClient();

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <Router>
        <Routes>
          <Route element={<CoreLayout />}>
            <Route path="/" element={<Navigate to="/agent" replace />} />
            <Route path="/agent" element={<Agent />} />
            <Route path="/sessions" element={<Sessions />} />
            <Route path="/sessions/:id" element={<SessionDetail />} />
            <Route path="*" element={<Navigate to="/agent" replace />} />
          </Route>
        </Routes>
      </Router>
    </QueryClientProvider>
  );
}

export default App;
