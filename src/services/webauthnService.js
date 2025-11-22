import axios from 'axios';
import {
  browserSupportsWebAuthn,
  startRegistration,
  startAuthentication
} from '@simplewebauthn/browser';
import API_CONFIG from '../config/api';

const API_BASE = API_CONFIG.baseURL;

export class WebAuthnService {

  /**
   * Helper para asegurar formato base64url desde String o ArrayBuffer
   * Maneja la discrepancia entre versiones de simplewebauthn que devuelven JSON vs objetos nativos
   */
  static _toBase64Url(input) {
    if (!input) return '';

    try {
      // Si es ArrayBuffer o Uint8Array - SIEMPRE convertir a string base64 primero
      if (input instanceof ArrayBuffer || input instanceof Uint8Array) {
        const bytes = new Uint8Array(input);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
          binary += String.fromCharCode(bytes[i]);
        }
        const base64 = btoa(binary);
        return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
      }

      // Si es string
      if (typeof input === 'string') {
        // Verificar si ya es base64url válido
        if (/^[A-Za-z0-9_-]*$/.test(input)) {
          return input;
        }
        // Si es base64 normal, convertir a base64url
        return input.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
      }

      // Si es un objeto - intentar extraer propiedades
      if (input && typeof input === 'object') {
        console.warn('_toBase64Url recibió un objeto:', typeof input, Object.prototype.toString.call(input));
        
        // Intentar JSON.stringify si es un objeto serializable
        try {
          const jsonStr = JSON.stringify(input);
          return jsonStr.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
        } catch {
          // Intentar toString
          const str = String(input);
          return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
        }
      }

      // Último recurso - convertir a string
      const result = String(input);
      return result.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    } catch (e) {
      console.error('Error convirtiendo a base64url:', e, 'input:', input);
      return '';
    }
  }

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

      // Usar startRegistration que maneja base64url automáticamente
      const credential = await startRegistration(options);

      console.log('✅ Credencial creada (raw):', credential);
      console.log('📋 Estructura credential:', {
        hasResponse: !!credential.response,
        responseKeys: credential.response ? Object.keys(credential.response) : [],
        hasRawId: !!credential.rawId,
        hasId: !!credential.id,
        type: credential.type,
        idType: typeof credential.id,
        rawIdType: typeof credential.rawId
      });

      // Procesar datos asegurando formato correcto (base64url)
      // SimpleWebAuthn v6+ ya devuelve en base64url
      if (!credential || !credential.response) {
        throw new Error('Respuesta de credencial inválida del navegador');
      }

      // SimpleWebAuthn devuelve credential con response que ya está en base64url
      // Estructura: { id, rawId, response: { attestationObject, clientDataJSON }, type }
      const registrationData = {
        response: credential  // SimpleWebAuthn ya proporciona el formato correcto
      };

      console.log('📤 Datos para enviar al servidor:', {
        hasResponse: !!registrationData.response,
        responseKeys: registrationData.response ? Object.keys(registrationData.response) : [],
        id: registrationData.response?.id?.substring(0, 50),
        attestationObject: registrationData.response?.response?.attestationObject?.substring(0, 50),
        clientDataJSON: registrationData.response?.response?.clientDataJSON?.substring(0, 50)
      });

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

      // Preparar opciones para startAuthentication
      const authOptions = {
        challenge,
        timeout: timeout || 60000,
        userVerification: "required"
      };

      // Si tenemos credentials específicos del usuario, agregarlos
      if (allowCredentials && allowCredentials.length > 0) {
        console.log('🔐 Usando credenciales específicas del usuario:', allowCredentials.length);
        authOptions.allowCredentials = allowCredentials;
      }

      // Usar startAuthentication que maneja base64url automáticamente
      const assertion = await startAuthentication(authOptions);

      console.log('✅ Assertion obtenida (raw):', assertion);

      // Procesar datos asegurando formato correcto (base64url)
      const credentialIdBase64url = this._toBase64Url(assertion.rawId || assertion.id);
      const signatureBase64url = this._toBase64Url(assertion.response.signature);
      const authenticatorDataBase64url = this._toBase64Url(assertion.response.authenticatorData);
      const clientDataJSONBase64url = this._toBase64Url(assertion.response.clientDataJSON);
      const userHandleBase64url = assertion.response.userHandle ? this._toBase64Url(assertion.response.userHandle) : undefined;

      console.log('🔑 Credential ID base64url para auth:', credentialIdBase64url);

      const authData = {
        signature: signatureBase64url,
        credentialId: credentialIdBase64url,
        challenge: challenge,
        authenticatorData: authenticatorDataBase64url,
        clientDataJSON: clientDataJSONBase64url,
        userHandle: userHandleBase64url,
        rawId: credentialIdBase64url,
        id: credentialIdBase64url,
        type: assertion.type,
        clientExtensionResults: assertion.clientExtensionResults || {}
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