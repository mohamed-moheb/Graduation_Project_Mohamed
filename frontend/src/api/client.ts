import axios from 'axios';

export const AUTH_BASE = 'http://localhost:8000';

const api = axios.create({
  baseURL: AUTH_BASE,
  headers: { 'Content-Type': 'application/json' },
});

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('token');
      localStorage.removeItem('attcksmith_user');
      window.location.href = '/';
    }
    return Promise.reject(error);
  }
);

export default api;
