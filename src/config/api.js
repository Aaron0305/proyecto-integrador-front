const normalizeUrl = (url, { removeTrailingSlash = false } = {}) => {
  if (!url) return '';
  let normalized = url.trim();
  if (removeTrailingSlash) {
    normalized = normalized.replace(/\/+$/, '');
  }
  return normalized;
};

const BASE_ORIGIN =
  normalizeUrl(import.meta.env.VITE_BACKEND_URL, { removeTrailingSlash: true }) ||
  'http://localhost:3001';

const API_PREFIX =
  normalizeUrl(import.meta.env.VITE_API_PREFIX) || '/api';

const API_BASE_URL = `${BASE_ORIGIN}${API_PREFIX.startsWith('/') ? API_PREFIX : `/${API_PREFIX}`}`;

const SOCKET_URL =
  normalizeUrl(import.meta.env.VITE_SOCKET_URL, { removeTrailingSlash: true }) ||
  BASE_ORIGIN;

const ASSETS_BASE_URL =
  normalizeUrl(import.meta.env.VITE_ASSETS_URL, { removeTrailingSlash: true }) ||
  BASE_ORIGIN;

// Configuración de API para desarrollo y producción
const API_CONFIG = {
  baseURL: API_BASE_URL,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
  withCredentials: true,
};

export const buildApiUrl = (path = '') =>
  `${API_CONFIG.baseURL}${path.startsWith('/') ? path : `/${path}`}`;

export const getAssetUrl = (path = '') =>
  `${ASSETS_BASE_URL}${path.startsWith('/') ? path : `/${path}`}`;

// Endpoints específicos
export const API_ENDPOINTS = {
  // Autenticación
  LOGIN: '/auth/login',
  REGISTER: '/auth/register',
  LOGOUT: '/auth/logout',
  REFRESH_TOKEN: '/auth/refresh-token',
  VERIFY_TOKEN: '/auth/verify',
  FORGOT_PASSWORD: '/auth/forgot-password',
  RESET_PASSWORD: '/auth/reset-password',
  
  // Biometría / WebAuthn
  BIOMETRIC_STATUS: '/auth/biometric/status',
  BIOMETRIC_REGISTER_OPTIONS: '/auth/biometric/registration-options',
  BIOMETRIC_REGISTER_VERIFY: '/auth/biometric/registration-verify',
  BIOMETRIC_LOGIN_OPTIONS: '/auth/biometric/authentication-options',
  BIOMETRIC_LOGIN_VERIFY: '/auth/biometric/authentication-verify',
  BIOMETRIC_TOGGLE: '/auth/biometric/toggle',
  BIOMETRIC_DELETE: '/auth/biometric/delete',
  BIOMETRIC_DIAGNOSTIC: '/auth/biometric/diagnostic',
  
  // Usuarios
  USERS: '/users',
  USER_PROFILE: '/users/profile',
  
  // Asignaciones
  ASSIGNMENTS: '/assignments',
  
  // Carreras y Semestres
  CARRERAS: '/carreras',
  SEMESTRES: '/semestres',
  
  // Estadísticas
  STATS: '/stats',
  
  // Registros diarios
  DAILY_RECORDS: '/daily-records',
  
  // Operaciones en lote
  BULK_OPERATIONS: '/bulk'
};

export const API_ENV = {
  BASE_ORIGIN,
  API_BASE_URL,
  SOCKET_URL,
  ASSETS_BASE_URL,
  API_PREFIX,
};

export default API_CONFIG;