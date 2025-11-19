# SolVX Web Frontend Guide

## Overview

The SolVX frontend is a React-based dashboard that provides real-time visualization of network security data.

## Quick Start

### Prerequisites

- Node.js 18+ and npm
- SolVX API server running (`solvx api start`)

### Create React Frontend

```bash
# Navigate to web directory
cd solvx_net/web

# Create React app with Vite
npm create vite@latest frontend -- --template react
cd frontend

# Install dependencies
npm install
npm install axios recharts @tanstack/react-query
npm install -D tailwindcss postcss autoprefixer
npx tailwindcss init -p
```

### Configure Tailwind CSS

Edit `tailwind.config.js`:

```javascript
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {},
  },
  plugins: [],
}
```

Add to `src/index.css`:

```css
@tailwind base;
@tailwind components;
@tailwind utilities;
```

### API Client Setup

Create `src/api/client.js`:

```javascript
import axios from 'axios';

const API_BASE_URL = 'http://localhost:8000';

export const api = axios.create({
  baseURL: API_BASE_URL,
});

export const getStats = () => api.get('/stats');
export const getDevices = (params) => api.get('/devices', { params });
export const getAlerts = (params) => api.get('/alerts', { params });
export const getNetworkHealth = () => api.get('/network-health');
export const getThreatScores = () => api.get('/threat-scores');
export const runDetection = () => api.post('/detect/run');
```

### Dashboard Components

#### 1. Network Health Widget

```jsx
// src/components/NetworkHealth.jsx
import { useQuery } from '@tanstack/react-query';
import { getNetworkHealth } from '../api/client';

export function NetworkHealth() {
  const { data } = useQuery({
    queryKey: ['network-health'],
    queryFn: () => getNetworkHealth().then(res => res.data),
    refetchInterval: 30000, // Refresh every 30s
  });

  if (!data) return <div>Loading...</div>;

  const healthColors = {
    excellent: 'bg-green-500',
    good: 'bg-blue-500',
    fair: 'bg-yellow-500',
    poor: 'bg-orange-500',
    critical: 'bg-red-500',
  };

  return (
    <div className="bg-white p-6 rounded-lg shadow">
      <h2 className="text-2xl font-bold mb-4">Network Health</h2>
      <div className={`text-4xl font-bold ${healthColors[data.health_status]} text-white p-4 rounded`}>
        {data.network_score.toFixed(1)}/100
      </div>
      <p className="mt-2 text-lg capitalize">{data.health_status}</p>
      <div className="mt-4 grid grid-cols-2 gap-4">
        <div>
          <p className="text-sm text-gray-600">Total Devices</p>
          <p className="text-2xl font-bold">{data.total_devices}</p>
        </div>
        <div>
          <p className="text-sm text-gray-600">Critical Alerts</p>
          <p className="text-2xl font-bold text-red-600">{data.critical_open_alerts}</p>
        </div>
      </div>
    </div>
  );
}
```

#### 2. Alerts List

```jsx
// src/components/AlertsList.jsx
import { useQuery } from '@tanstack/react-query';
import { getAlerts } from '../api/client';

export function AlertsList() {
  const { data } = useQuery({
    queryKey: ['alerts'],
    queryFn: () => getAlerts({ status: 'open' }).then(res => res.data),
    refetchInterval: 10000,
  });

  const severityColors = {
    critical: 'bg-red-100 text-red-800',
    high: 'bg-orange-100 text-orange-800',
    medium: 'bg-yellow-100 text-yellow-800',
    low: 'bg-blue-100 text-blue-800',
  };

  return (
    <div className="bg-white p-6 rounded-lg shadow">
      <h2 className="text-2xl font-bold mb-4">Recent Alerts</h2>
      <div className="space-y-3">
        {data?.map(alert => (
          <div key={alert.id} className="border-l-4 border-red-500 pl-4 py-2">
            <div className="flex justify-between items-start">
              <div>
                <p className="font-semibold">{alert.title}</p>
                <p className="text-sm text-gray-600">{alert.description.slice(0, 100)}...</p>
              </div>
              <span className={`px-2 py-1 rounded text-xs ${severityColors[alert.severity]}`}>
                {alert.severity}
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
```

#### 3. Device List

```jsx
// src/components/DeviceList.jsx
import { useQuery } from '@tanstack/react-query';
import { getDevices, getThreatScores } from '../api/client';

export function DeviceList() {
  const { data: devices } = useQuery({
    queryKey: ['devices'],
    queryFn: () => getDevices().then(res => res.data),
  });

  const { data: scores } = useQuery({
    queryKey: ['threat-scores'],
    queryFn: () => getThreatScores().then(res => res.data),
  });

  const getDeviceScore = (deviceId) => {
    return scores?.find(s => s.device_id === deviceId)?.score || 0;
  };

  return (
    <div className="bg-white p-6 rounded-lg shadow">
      <h2 className="text-2xl font-bold mb-4">Devices</h2>
      <table className="w-full">
        <thead>
          <tr className="border-b">
            <th className="text-left p-2">MAC Address</th>
            <th className="text-left p-2">Vendor</th>
            <th className="text-left p-2">Trust</th>
            <th className="text-right p-2">Threat Score</th>
          </tr>
        </thead>
        <tbody>
          {devices?.map(device => (
            <tr key={device.id} className="border-b hover:bg-gray-50">
              <td className="p-2 font-mono text-sm">{device.mac_address}</td>
              <td className="p-2">{device.vendor || 'Unknown'}</td>
              <td className="p-2">
                <span className={`px-2 py-1 rounded text-xs ${
                  device.trust_level === 'trusted' ? 'bg-green-100 text-green-800' :
                  device.trust_level === 'guest' ? 'bg-blue-100 text-blue-800' :
                  'bg-gray-100 text-gray-800'
                }`}>
                  {device.trust_level}
                </span>
              </td>
              <td className="p-2 text-right font-bold">
                {getDeviceScore(device.id).toFixed(1)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
```

#### 4. Main Dashboard

```jsx
// src/App.jsx
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { NetworkHealth } from './components/NetworkHealth';
import { AlertsList } from './components/AlertsList';
import { DeviceList } from './components/DeviceList';

const queryClient = new QueryClient();

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <div className="min-h-screen bg-gray-100">
        <nav className="bg-white shadow-sm">
          <div className="max-w-7xl mx-auto px-4 py-4">
            <h1 className="text-2xl font-bold">SolVX Network Security</h1>
          </div>
        </nav>

        <main className="max-w-7xl mx-auto px-4 py-8">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
            <div className="lg:col-span-1">
              <NetworkHealth />
            </div>
            <div className="lg:col-span-2">
              <AlertsList />
            </div>
          </div>

          <DeviceList />
        </main>
      </div>
    </QueryClientProvider>
  );
}

export default App;
```

## Running the Frontend

```bash
# Start API server (terminal 1)
solvx api start

# Start frontend dev server (terminal 2)
cd solvx_net/web/frontend
npm run dev

# Open http://localhost:5173
```

## Features Implemented

- ✅ Real-time network health monitoring
- ✅ Live alert notifications
- ✅ Device inventory with threat scores
- ✅ Auto-refresh every 10-30 seconds
- ✅ Responsive design with Tailwind CSS

## Future Enhancements

- WebSocket support for instant updates
- Interactive charts (Recharts)
- Device detail modals
- Alert acknowledgment/resolution UI
- Historical trend graphs
- Detection engine controls
- Export functionality
