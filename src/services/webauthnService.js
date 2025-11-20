import axios from 'axios';
import { 
  browserSupportsWebAuthn 
} from '@simplewebauthn/browser';
import API_CONFIG from '../config/api';

const API_BASE = API_CONFIG.baseURL;

export class WebAuthnService {
  
  /**
   * Verificar si el navegador soporta WebAuthn
   */
  static isSupported() {
    return browserSupportsWebAuthn();
  }

  /**
   * Verificar si el dispositivo tiene capacidades biométricas
   */
  static async hasAvailableAuthenticator() {
    try {
      if (!browserSupportsWebAuthn()) {
        return false;
      }
      
      // Verificar si PublicKeyCredential está disponible
      if (typeof PublicKeyCredential !== 'undefined' && 
          PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable) {
        return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
      }
      
      return false;
    } catch (error) {
      console.error('Error verificando autenticador:', error);
      return false;
    }
  }

  /**
   * Registrar un nuevo dispositivo biométrico
   * @param {string} authenticatorType - 'platform' | 'cross-platform' | 'both'
   */
  static async registerDevice(authenticatorType = 'both') {
    if (!this.isSupported()) {
      throw new Error('Este navegador no soporta autenticación biométrica');
    }

    try {
      // Paso 1: Obtener challenge del servidor
      const token = localStorage.getItem('token');
      if (!token) {
        throw new Error('Debes estar logueado para registrar un dispositivo biométrico');
      }

      console.log('🔑 Obteniendo opciones de registro...', `Tipo: ${authenticatorType}`);
      const optionsResponse = await axios.post(`${API_BASE}/auth/biometric/registration-options`, {
        authenticatorType
      }, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      
      const { options } = optionsResponse.data;
      console.log('✅ Opciones obtenidas para registro');

      // Paso 2: Crear credencial biométrica usando SimpleWebAuthn
      console.log('👆 Solicitando huella digital...');
      
      // Convertir datos base64 a Uint8Array para WebAuthn
      const publicKeyOptions = {
        ...options,
        challenge: Uint8Array.from(atob(options.challenge), c => c.charCodeAt(0)),
        user: {
          ...options.user,
          id: Uint8Array.from(atob(options.user.id), c => c.charCodeAt(0))
        }
      };

      // Convertir excludeCredentials si existen  
      if (options.excludeCredentials) {
        publicKeyOptions.excludeCredentials = options.excludeCredentials.map(cred => ({
          ...cred,
          id: Uint8Array.from(atob(cred.id), c => c.charCodeAt(0))
        }));
      }
      
      const credential = await navigator.credentials.create({
        publicKey: publicKeyOptions
      });
      
      console.log('✅ Credencial creada:', credential);

      // Paso 3: Enviar credencial al servidor
      console.log('📤 Enviando credencial al servidor...');
      console.log('🔑 Raw Credential ID:', credential.id);
      console.log('🔑 Raw ID length:', credential.rawId.byteLength);
      
      // Convertir rawId a base64url para consistencia
      const credentialIdBase64url = btoa(String.fromCharCode(...new Uint8Array(credential.rawId)))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
      
      console.log('🔑 Credential ID base64url:', credentialIdBase64url);
      
      // Preparar datos para SimpleWebAuthn verificación
      const registrationData = {
        response: {
          id: credential.id,
          rawId: credential.id,
          response: {
            attestationObject: btoa(String.fromCharCode(...new Uint8Array(credential.response.attestationObject))),
            clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(credential.response.clientDataJSON)))
          },
          type: credential.type
        }
      };
      
      const verificationResponse = await axios.post(
        `${API_BASE}/auth/biometric/register`,
        registrationData,
        { headers: { Authorization: `Bearer ${token}` } }
      );

      if (!verificationResponse.data.success) {
        throw new Error(verificationResponse.data.message || 'Error al verificar el registro');
      }

      console.log('🎉 Dispositivo registrado exitosamente');
      return {
        success: true,
        message: 'Dispositivo biométrico registrado exitosamente',
        user: verificationResponse.data.user
      };

    } catch (error) {
      console.error('❌ Error en registro biométrico:', error);
      
      // Manejar errores específicos de WebAuthn
      if (error.name === 'NotAllowedError') {
        throw new Error('Acceso denegado. Es posible que hayas cancelado la operación o el dispositivo esté bloqueado.');
      } else if (error.name === 'NotSupportedError') {
        throw new Error('Tu dispositivo no soporta este tipo de autenticación biométrica.');
      } else if (error.name === 'SecurityError') {
        throw new Error('Error de seguridad. Verifica que estés usando HTTPS en producción.');
      } else if (error.name === 'InvalidStateError') {
        throw new Error('Este dispositivo ya está registrado o hay un conflicto de estado.');
      } else if (error.response?.data?.message) {
        throw new Error(error.response.data.message);
      } else if (error.message) {
        throw new Error(error.message);
      } else {
        throw new Error('Error desconocido durante el registro biométrico');
      }
    }
  }

  /**
   * Autenticarse con dispositivo biométrico (Login con email opcional)
   */
  static async authenticateWithBiometric(userEmail = null) {
    if (!this.isSupported()) {
      throw new Error('Este navegador no soporta autenticación biométrica');
    }

    try {
      // Paso 1: Obtener challenge para login (específico del usuario si es posible)
      console.log('🔑 Obteniendo challenge para autenticación...');
      let challengeResponse;
      
      if (userEmail) {
        // Si tenemos email, usar el endpoint específico del usuario
        console.log('📧 Usando challenge específico para:', userEmail);
        challengeResponse = await axios.post(`${API_BASE}/auth/biometric/login-challenge`, { email: userEmail });
      } else {
        // Fallback al endpoint general para compatibilidad
        console.log('🌐 Usando challenge general (sin email específico)');
        challengeResponse = await axios.post(`${API_BASE}/auth/biometric/quick-login`);
      }
      
      const { challenge, timeout, allowCredentials } = challengeResponse.data;
      console.log('✅ Challenge obtenido:', challenge);

      // Paso 2: Solicitar autenticación biométrica al usuario
      console.log('👆 Solicitando verificación biométrica...');
      
      // Preparar opciones de autenticación
      const publicKeyOptions = {
        challenge: Uint8Array.from(atob(challenge), c => c.charCodeAt(0)),
        timeout: timeout || 60000,
        userVerification: "required"
      };
      
      // Si tenemos credentials específicos del usuario, agregarlos
      if (allowCredentials && allowCredentials.length > 0) {
        console.log('🔐 Usando credenciales específicas del usuario:', allowCredentials.length);
        publicKeyOptions.allowCredentials = allowCredentials.map(cred => ({
          id: Uint8Array.from(atob(cred.id.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0)),
          type: cred.type || 'public-key'
        }));
      }
      
      const assertion = await navigator.credentials.get({
        publicKey: publicKeyOptions
      });
      
      console.log('✅ Assertion obtenida:', assertion);

      // Paso 3: Enviar firma al servidor
      console.log('📤 Verificando credencial...');
      console.log('🔑 Assertion ID:', assertion.id);
      console.log('🔑 Assertion rawId length:', assertion.rawId.byteLength);
      
      // Convertir rawId a base64url para consistencia
      const credentialIdBase64url = btoa(String.fromCharCode(...new Uint8Array(assertion.rawId)))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
      
      console.log('🔑 Credential ID base64url para auth:', credentialIdBase64url);
      
      const authData = {
        signature: btoa(String.fromCharCode(...new Uint8Array(assertion.response.signature))),
        credentialId: credentialIdBase64url, // Usar el formato base64url consistente
        challenge: challenge,
        authenticatorData: btoa(String.fromCharCode(...new Uint8Array(assertion.response.authenticatorData))),
        clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(assertion.response.clientDataJSON)))
      };
      
      const authResponse = await axios.put(`${API_BASE}/auth/biometric/quick-login`, authData);

      if (!authResponse.data.success) {
        throw new Error(authResponse.data.message || 'Error al verificar la autenticación');
      }

      console.log('🎉 Autenticación biométrica exitosa');
      
      // Guardar token y usuario (igual que login normal)
      const { token, user } = authResponse.data;
      localStorage.setItem('token', token);
      localStorage.setItem('user', JSON.stringify(user));

      return {
        success: true,
        message: authResponse.data.message || 'Autenticación biométrica exitosa',
        token,
        user,
        authMethod: 'biometric'
      };

    } catch (error) {
      console.error('❌ Error en autenticación biométrica:', error);
      
      // Manejar errores específicos de WebAuthn
      if (error.name === 'NotAllowedError') {
        throw new Error('Acceso denegado. Es posible que hayas cancelado la operación.');
      } else if (error.name === 'NotSupportedError') {
        throw new Error('Tu dispositivo no soporta este tipo de autenticación biométrica.');
      } else if (error.name === 'SecurityError') {
        throw new Error('Error de seguridad. Verifica que estés usando HTTPS en producción.');
      } else if (error.name === 'InvalidStateError') {
        throw new Error('Estado inválido del autenticador.');
      } else if (error.response?.data?.message) {
        throw new Error(error.response.data.message);
      } else if (error.message) {
        throw new Error(error.message);
      } else {
        throw new Error('Error desconocido durante la autenticación biométrica');
      }
    }
  }

  /**
   * Obtener estado de dispositivos biométricos
   */
  static async getBiometricStatus() {
    try {
      const token = localStorage.getItem('token');
      if (!token) {
        throw new Error('No autenticado');
      }

      const response = await axios.get(`${API_BASE}/auth/biometric/status`, {
        headers: { Authorization: `Bearer ${token}` }
      });

      return response.data;
    } catch (error) {
      console.error('Error obteniendo estado biométrico:', error);
      throw new Error(error.response?.data?.message || 'Error al obtener estado biométrico');
    }
  }

  /**
   * Activar/Desactivar dispositivo biométrico
   */
  static async toggleBiometric(enable) {
    try {
      const token = localStorage.getItem('token');
      if (!token) {
        throw new Error('No autenticado');
      }

      const response = await axios.post(`${API_BASE}/auth/biometric/toggle`, 
        { enable },
        { headers: { Authorization: `Bearer ${token}` } }
      );

      return {
        success: true,
        message: response.data.message,
        enabled: response.data.enabled
      };
    } catch (error) {
      console.error('Error cambiando estado biométrico:', error);
      throw new Error(error.response?.data?.message || 'Error al cambiar estado biométrico');
    }
  }

  /**
   * Ejecutar diagnóstico de autenticadores
   */
  static async runDiagnostic() {
    try {
      const token = localStorage.getItem('token');
      if (!token) {
        throw new Error('No autenticado');
      }

      const response = await axios.get(`${API_BASE}/auth/biometric/diagnostic`, {
        headers: { Authorization: `Bearer ${token}` }
      });

      return response.data;
    } catch (error) {
      console.error('Error en diagnóstico:', error);
      throw new Error(error.response?.data?.message || 'Error en diagnóstico');
    }
  }

  /**
   * Eliminar dispositivo biométrico PERMANENTEMENTE
   */
  static async deleteBiometric() {
    try {
      const token = localStorage.getItem('token');
      if (!token) {
        throw new Error('No autenticado');
      }

      const response = await axios.delete(`${API_BASE}/auth/biometric/delete`, {
        headers: { Authorization: `Bearer ${token}` }
      });

      return {
        success: true,
        message: response.data.message || 'Dispositivo eliminado permanentemente'
      };
    } catch (error) {
      console.error('Error eliminando dispositivo:', error);
      throw new Error(error.response?.data?.message || 'Error al eliminar dispositivo');
    }
  }

  /**
   * Verificar si un usuario tiene dispositivos biométricos registrados
   */
  static async userHasBiometricDevices(email) {
    try {
      // Usar la ruta de verificación de usuario existente o crear una nueva
      const response = await axios.post(`${API_BASE}/auth/biometric/check-user-devices`, {
        email
      });

      console.log('🔍 Verificación dispositivos biométricos:', response.data);
      return response.data.success && !!response.data.hasDevices;
    } catch (error) {
      console.error('❌ Error verificando dispositivos biométricos:', error);
      return false;
    }
  }

  /**
   * Método con email para compatibilidad (utiliza quick-login internamente)
   */
  static async authenticateWithBiometricEmail() {
    return this.authenticateWithBiometric();
  }

  // Métodos de compatibilidad con la implementación anterior
  static async getRegisteredDevices() {
    return this.getBiometricStatus();
  }

  static async removeDevice() {
    return this.deleteBiometric();
  }
}

export default WebAuthnService;