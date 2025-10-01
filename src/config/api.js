// Configuración de la API
export const API_CONFIG = {
  BASE_URL: 'http://localhost:8000',
  TIMEOUT: 10000,
  ENDPOINTS: {
    AUTH: {
      LOGIN: '/api/auth/login',
      REGISTER: '/api/auth/register',
      VERIFY: '/api/auth/verify'
    },
    PRODUCTS: '/api/productos/',
    LOTES: '/api/lotes/',
    MOVEMENTS: '/api/movimientos/',
    ALERTS: '/api/alertas/'
  }
};

export default API_CONFIG;
