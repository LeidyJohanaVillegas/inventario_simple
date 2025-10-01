import axios from 'axios';
import { API_CONFIG } from '../config/api.js';

// Configuración base de la API
const API_BASE_URL = API_CONFIG.BASE_URL;

// Crear instancia de axios con configuración base
const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: API_CONFIG.TIMEOUT,
});

// Interceptor para manejar errores globalmente
api.interceptors.response.use(
  (response) => response,
  (error) => {
    console.error('API Error:', error);
    return Promise.reject(error);
  }
);

// Servicios de autenticación
export const authService = {
  // Login de usuario
  login: async (documento, password) => {
    try {
      const response = await api.post('/api/auth/login', {
        documento,
        password
      });
      return response.data;
    } catch (error) {
      throw new Error(error.response?.data?.detail || 'Error al iniciar sesión');
    }
  },

  // Registro de usuario
  register: async (userData) => {
    try {
      const response = await api.post('/api/auth/register', userData);
      return response.data;
    } catch (error) {
      throw new Error(error.response?.data?.detail || 'Error al registrar usuario');
    }
  },

  // Verificar token (si implementas JWT)
  verifyToken: async (token) => {
    try {
      const response = await api.get('/api/auth/verify', {
        headers: { Authorization: `Bearer ${token}` }
      });
      return response.data;
    } catch (error) {
      throw new Error('Token inválido');
    }
  }
};

// Servicios de productos
export const productService = {
  // Obtener todos los productos
  getProducts: async () => {
    try {
      const response = await api.get('/api/productos/');
      return response.data;
    } catch (error) {
      throw new Error(error.response?.data?.detail || 'Error al obtener productos');
    }
  },

  // Crear producto
  createProduct: async (productData) => {
    try {
      const response = await api.post('/api/productos/', productData);
      return response.data;
    } catch (error) {
      throw new Error(error.response?.data?.detail || 'Error al crear producto');
    }
  },

  // Actualizar producto
  updateProduct: async (id, productData) => {
    try {
      const response = await api.put(`/api/productos/${id}`, productData);
      return response.data;
    } catch (error) {
      throw new Error(error.response?.data?.detail || 'Error al actualizar producto');
    }
  },

  // Eliminar producto
  deleteProduct: async (id) => {
    try {
      const response = await api.delete(`/api/productos/${id}`);
      return response.data;
    } catch (error) {
      throw new Error(error.response?.data?.detail || 'Error al eliminar producto');
    }
  }
};

// Servicios de lotes
export const lotService = {
  // Obtener todos los lotes
  getLotes: async () => {
    try {
      const response = await api.get('/api/lotes/');
      return response.data;
    } catch (error) {
      throw new Error(error.response?.data?.detail || 'Error al obtener lotes');
    }
  },

  // Crear lote
  createLote: async (loteData) => {
    try {
      const response = await api.post('/api/lotes/', loteData);
      return response.data;
    } catch (error) {
      throw new Error(error.response?.data?.detail || 'Error al crear lote');
    }
  }
};

// Servicios de movimientos
export const movementService = {
  // Obtener todos los movimientos
  getMovements: async () => {
    try {
      const response = await api.get('/api/movimientos/');
      return response.data;
    } catch (error) {
      throw new Error(error.response?.data?.detail || 'Error al obtener movimientos');
    }
  },

  // Crear movimiento
  createMovement: async (movementData) => {
    try {
      const response = await api.post('/api/movimientos/', movementData);
      return response.data;
    } catch (error) {
      throw new Error(error.response?.data?.detail || 'Error al crear movimiento');
    }
  }
};

// Servicios de alertas
export const alertService = {
  // Obtener todas las alertas
  getAlerts: async () => {
    try {
      const response = await api.get('/api/alertas/');
      return response.data;
    } catch (error) {
      throw new Error(error.response?.data?.detail || 'Error al obtener alertas');
    }
  }
};

export default api;
