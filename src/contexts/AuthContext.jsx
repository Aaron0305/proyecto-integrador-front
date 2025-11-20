import React, { createContext, useState, useEffect } from 'react';
import axios from 'axios';
import setupAxiosInterceptors from '../utils/axiosDebugger';
import WebAuthnService from '../services/webauthnService';

export const AuthContext = createContext();

export const AuthProvider = ({ children }) => {
  const [currentUser, setCurrentUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [retryCount, setRetryCount] = useState(0);

  // Configurar interceptors de axios para debugging
  useEffect(() => {
    setupAxiosInterceptors();
  }, []);

  const login = async (email, password) => {
    try {
      const response = await axios.post('http://localhost:3001/api/auth/login', {
        email,
        password
      });

      const { token, user } = response.data;
      if (token) {
        localStorage.setItem('token', token);
        localStorage.setItem('user', JSON.stringify(user));
        setCurrentUser(user);
        setRetryCount(0); // Reset retry count on successful login
        return { success: true, user };
      }
      
      throw new Error('Credenciales inválidas');
    } catch (error) {
      throw new Error(error.response?.data?.message || 'Error al iniciar sesión');
    }
  };

  const register = async (userData) => {
    try {
      const response = await axios.post('http://localhost:3001/api/auth/register', userData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        }
      });

      if (response.data.success) {
        return { success: true, user: response.data.user, message: response.data.message };
      } else {
        throw new Error(response.data.message || 'Error inesperado durante el registro');
      }
    } catch (error) {
      if (error.response?.data?.message) {
        throw new Error(error.response.data.message);
      } else if (error.message) {
        throw new Error(error.message);
      } else {
        throw new Error('Error al registrar usuario. Por favor, intenta de nuevo.');
      }
    }
  };

  const logout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    setCurrentUser(null);
    setRetryCount(0);
  };

  const verifyToken = async () => {
    const token = localStorage.getItem('token');
    const savedUser = localStorage.getItem('user');
    
    if (!token || !savedUser) {
      localStorage.removeItem('token');
      localStorage.removeItem('user');
      setCurrentUser(null);
      setLoading(false);
      return;
    }

    try {
      // Timeout adicional para evitar requests infinitos
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 10000); // 10 segundos timeout

      const response = await axios.get('http://localhost:3001/api/auth/verify', {
        headers: { Authorization: `Bearer ${token}` },
        signal: controller.signal
      });
      
      clearTimeout(timeoutId);
      const userData = response.data.user;
      localStorage.setItem('user', JSON.stringify(userData));
      setCurrentUser(userData);
      setRetryCount(0); // Reset retry count on successful verification
      setLoading(false);
      
    } catch (error) {
      console.error('Error verificando token:', error);
      
      // Si el error es de autenticación y no hemos excedido los reintentos
      if (error.response?.status === 401 && retryCount < 2) { // Reducido a 2 reintentos
        setRetryCount(prev => prev + 1);
        // Reintentamos en 2 segundos
        setTimeout(verifyToken, 2000);
        return;
      }
      
      // Si excedimos los reintentos o es otro tipo de error, limpiamos todo
      localStorage.removeItem('token');
      localStorage.removeItem('user');
      setCurrentUser(null);
      setLoading(false);
    }
  };

  useEffect(() => {
    verifyToken();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // Verificar el token cada 5 minutos
  useEffect(() => {
    const interval = setInterval(verifyToken, 300000); // 5 minutos
    return () => clearInterval(interval);
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const updateUserProfile = async () => {
    await verifyToken(); // Usar la misma función de verificación
    return currentUser;
  };

  const forgotPassword = async (email) => {
    try {
      const response = await axios.post('http://localhost:3001/api/auth/forgot-password', {
        email
      });
      
      return { 
        success: true, 
        message: response.data.message || 'Se ha enviado un enlace de recuperación a tu correo electrónico' 
      };
    } catch (error) {
      throw new Error(error.response?.data?.message || 'Error al procesar la solicitud');
    }
  };

  const resetPassword = async (token, newPassword) => {
    try {
      const response = await axios.post('http://localhost:3001/api/auth/reset-password', {
        token,
        newPassword
      });
      
      return { 
        success: true, 
        message: response.data.message || 'Contraseña restablecida exitosamente' 
      };
    } catch (error) {
      throw new Error(error.response?.data?.message || 'Error al restablecer la contraseña');
    }
  };

  // ===============================
  // FUNCIONES DE WEBAUTHN/BIOMÉTRICO
  // ===============================

  const loginWithBiometric = async () => {
    const result = await WebAuthnService.authenticateWithBiometric();
    
    if (result.success) {
      setCurrentUser(result.user);
      setRetryCount(0);
      return result;
    }
    
    throw new Error('Error en la autenticación biométrica');
  };

  const registerBiometricDevice = async () => {
    return await WebAuthnService.registerDevice();
  };

  const getBiometricDevices = async () => {
    return await WebAuthnService.getRegisteredDevices();
  };

  const removeBiometricDevice = async () => {
    return await WebAuthnService.removeDevice();
  };

  const isBiometricSupported = () => {
    return WebAuthnService.isSupported();
  };

  const checkBiometricAvailable = async () => {
    try {
      return await WebAuthnService.hasAvailableAuthenticator();
    } catch {
      return false;
    }
  };

  const userHasBiometricDevices = async (email) => {
    try {
      return await WebAuthnService.userHasBiometricDevices(email);
    } catch {
      return false;
    }
  };

  return (
    <AuthContext.Provider 
      value={{ 
        currentUser, 
        login, 
        register, 
        logout,
        loading,
        updateUserProfile,
        forgotPassword,
        resetPassword,
        verifyToken, // Exponemos la función de verificación
        // Funciones WebAuthn/Biométricas
        loginWithBiometric,
        registerBiometricDevice,
        getBiometricDevices,
        removeBiometricDevice,
        isBiometricSupported,
        checkBiometricAvailable,
        userHasBiometricDevices
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};