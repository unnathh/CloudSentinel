import axios from 'axios';

// FastAPI runs on port 8000 by default. Adjust to local configuration if needed.
const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api';

const api = axios.create({
  baseURL: API_URL,
});

// Automatically inject JWT access token into request headers if authenticated
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token && config.headers) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
}, (error) => {
  return Promise.reject(error);
});

// Authentication endpoints
export const authApi = {
  login: async (username: string, password: string) => {
    // FastAPI OAuth2PasswordRequestForm expects Form Urlencoded fields: username & password
    const formData = new URLSearchParams();
    formData.append('username', username);
    formData.append('password', password);
    const response = await api.post('/auth/login', formData, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    });
    return response.data; // returns {access_token, token_type}
  },
  register: async (payload: any) => {
    const response = await api.post('/auth/register', payload);
    return response.data;
  },
  getMe: async () => {
    const response = await api.get('/auth/me');
    return response.data;
  },
  getUsers: async () => {
    const response = await api.get('/auth/users');
    return response.data;
  },
  deleteUser: async (userId: number) => {
    const response = await api.delete(`/auth/users/${userId}`);
    return response.data;
  }
};

// AWS Account endpoints
export const accountsApi = {
  getAccounts: async () => {
    const response = await api.get('/accounts');
    return response.data;
  },
  createAccount: async (payload: any) => {
    const response = await api.post('/accounts', payload);
    return response.data;
  },
  getAccountDetails: async (accountId: number) => {
    const response = await api.get(`/accounts/${accountId}`);
    return response.data;
  },
  deleteAccount: async (accountId: number) => {
    const response = await api.delete(`/accounts/${accountId}`);
    return response.data;
  },
  getScans: async (accountId: number) => {
    const response = await api.get(`/accounts/${accountId}/scans`);
    return response.data;
  },
  triggerScan: async (accountId: number) => {
    const response = await api.post(`/accounts/${accountId}/scan`);
    return response.data;
  }
};

// Findings endpoints
export const findingsApi = {
  getFindings: async (params?: { scan_id?: number; severity?: string; service?: string; status?: string }) => {
    const response = await api.get('/findings', { params });
    return response.data;
  },
  getFindingDetails: async (findingId: number) => {
    const response = await api.get(`/findings/${findingId}`);
    return response.data;
  },
  updateFindingStatus: async (findingId: number, status: string) => {
    const response = await api.patch(`/findings/${findingId}`, { status });
    return response.data;
  }
};

// Resource Inventory endpoints
export const resourcesApi = {
  getResources: async (params?: { scan_id?: number; service?: string }) => {
    const response = await api.get('/resources', { params });
    return response.data;
  },
  getResourceDetails: async (resourceId: string, scanId?: number) => {
    const response = await api.get(`/resources/${resourceId}`, { params: { scan_id: scanId } });
    return response.data;
  }
};

// Security Graph & Attack Paths endpoints
export const graphApi = {
  getSecurityGraph: async (scanId?: number) => {
    const response = await api.get('/graph', { params: { scan_id: scanId } });
    return response.data; // returns Cytoscape formatted {nodes, edges}
  },
  getAttackPaths: async (scanId?: number) => {
    const response = await api.get('/graph/paths', { params: { scan_id: scanId } });
    return response.data;
  }
};

// Reports URLs (to open in new tab or trigger downloads directly)
export const reportsApi = {
  exportJsonUrl: (scanId?: number) => {
    const token = localStorage.getItem('token');
    const param = scanId ? `?scan_id=${scanId}` : '';
    return `${API_URL}/reports/json${param}${scanId ? '&' : '?'}token=${token}`;
  },
  exportCsvUrl: (scanId?: number) => {
    const param = scanId ? `?scan_id=${scanId}` : '';
    return `${API_URL}/reports/csv${param}`;
  },
  exportPdfUrl: (scanId?: number) => {
    const param = scanId ? `?scan_id=${scanId}` : '';
    return `${API_URL}/reports/pdf${param}`;
  },
  // Since reports are standard GET endpoints requiring authorization,
  // we can download them using axios and create blobs in the browser!
  downloadReport: async (type: 'json' | 'csv' | 'pdf', scanId?: number) => {
    const response = await api.get(`/reports/${type}`, {
      params: { scan_id: scanId },
      responseType: 'blob',
    });
    return response.data;
  }
};

export default api;
