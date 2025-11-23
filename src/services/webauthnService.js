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

      console.log('📦 Respuesta recibida del servidor:', optionsResponse.data);
      
      if (!optionsResponse.data.success) {
        throw new Error(optionsResponse.data.message || 'Error del servidor');
      }

      const { options } = optionsResponse.data;
      
      if (!options) {
        throw new Error('Servidor no devolvió opciones de registro');
      }

      console.log('✅ Opciones obtenidas para registro:', {
        hasChallenge: !!options.challenge,
        hasRp: !!options.rp,
        hasUser: !!options.user
      });

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
        rawIdType: typeof credential.rawId,
        responseType: typeof credential.response,
        attestationObjectType: typeof credential.response?.attestationObject,
        clientDataJSONType: typeof credential.response?.clientDataJSON
      });

      // Procesar datos asegurando formato correcto (base64url)
      // SimpleWebAuthn v6+ ya devuelve en base64url
      if (!credential || !credential.response) {
        console.error('❌ Credencial incompleta:', credential);
        throw new Error('Respuesta de credencial inválida del navegador');
      }

      // Validar que todos los campos necesarios existan
      if (!credential.id || !credential.response.attestationObject || !credential.response.clientDataJSON) {
        console.error('❌ Faltan campos en credential:', {
          hasId: !!credential.id,
          hasAttestationObject: !!credential.response.attestationObject,
          hasClientDataJSON: !!credential.response.clientDataJSON
        });
        throw new Error('Campos faltantes en la respuesta de credencial');
      }

      // SimpleWebAuthn devuelve credential con response que ya está en base64url
      // Estructura: { id, rawId, response: { attestationObject, clientDataJSON }, type }
      console.log('✅ Validación de credential exitosa');
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
   * NOTA: Ya no se usa porque la verificación de huella es independiente
   * y usa las huellas del dispositivo directamente
   */
  static async userHasBiometricDevices(email) {
    // Siempre retornar false porque no necesitamos verificar esto
    // La verificación de huella usa las huellas del dispositivo directamente
    return false;
  }

  /**
   * NUEVO: Verificar SOLO la huella del dispositivo (SIN hacer login)
   * Este es un proceso completamente independiente del login
   * Solo verifica que el dispositivo tiene una huella válida registrada
   * @param {string} email - Email del usuario (opcional, solo para logging)
   */
  static async verifyDeviceBiometric(email = null) {
    if (!this.isSupported()) {
      throw new Error('Este navegador no soporta autenticación biométrica');
    }

    try {
      // Paso 1: Obtener challenge del servidor
      console.log('🔑 Obteniendo challenge para verificación de dispositivo...');
      const challengeResponse = await axios.post(`${API_BASE}/auth/biometric/verify-device`, {
        email
      });

      if (!challengeResponse.data.success) {
        throw new Error(challengeResponse.data.message || 'Error al obtener challenge');
      }

      const { challenge, timeout, rpId } = challengeResponse.data;
      console.log('✅ Challenge obtenido para verificación de dispositivo');

      // Paso 2: Solicitar verificación de huella al dispositivo usando API nativa
      console.log('👆 Solicitando verificación de huella del dispositivo...');

      // Asegurar que challenge es un string
      const challengeString = typeof challenge === 'string' ? challenge : String(challenge);
      
      // Convertir challenge de base64url a ArrayBuffer (API nativa)
      const base64UrlToArrayBuffer = (base64url) => {
        const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
          bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
      };

      const challengeBuffer = base64UrlToArrayBuffer(challengeString);

      // Usar API nativa de WebAuthn (más simple y directo)
      const assertion = await navigator.credentials.get({
        publicKey: {
          challenge: challengeBuffer,
          timeout: timeout || 60000,
          userVerification: 'required',
          rpId: rpId || window.location.hostname,
          // No especificamos allowCredentials = permite cualquier credencial del dispositivo
        }
      });

      if (!assertion) {
        throw new Error('Verificación de huella cancelada');
      }

      console.log('✅ Huella del dispositivo verificada correctamente');

      // Paso 3: Enviar respuesta al servidor SOLO para verificar la huella (SIN login)
      console.log('📤 Enviando verificación de huella al servidor...');

      // Convertir datos de ArrayBuffer a base64url
      const arrayBufferToBase64Url = (buffer) => {
        if (!buffer) return '';
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
          binary += String.fromCharCode(bytes[i]);
        }
        const base64 = btoa(binary);
        return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
      };

      const credentialIdBase64url = arrayBufferToBase64Url(assertion.rawId);
      const signatureBase64url = arrayBufferToBase64Url(assertion.response.signature);
      const authenticatorDataBase64url = arrayBufferToBase64Url(assertion.response.authenticatorData);
      const clientDataJSONBase64url = arrayBufferToBase64Url(assertion.response.clientDataJSON);
      const userHandleBase64url = assertion.response.userHandle ? arrayBufferToBase64Url(assertion.response.userHandle) : undefined;

      const verifyData = {
        challenge: challengeString, // Usar el string del challenge
        assertion: {
          id: credentialIdBase64url,
          rawId: credentialIdBase64url,
          type: assertion.type,
          response: {
            authenticatorData: authenticatorDataBase64url,
            clientDataJSON: clientDataJSONBase64url,
            signature: signatureBase64url,
            userHandle: userHandleBase64url
          },
          clientExtensionResults: assertion.clientExtensionResults || {}
        }
      };

      const verifyResponse = await axios.post(`${API_BASE}/auth/biometric/verify-device-response`, verifyData);

      if (!verifyResponse.data.success) {
        throw new Error(verifyResponse.data.message || 'Error en la verificación de huella');
      }

      console.log('🎉 Huella del dispositivo verificada correctamente');

      // NO guardamos token ni usuario aquí - esto es solo verificación de huella
      // El login se hace por separado con email y contraseña

      return {
        success: true,
        message: verifyResponse.data.message || 'Huella del dispositivo verificada correctamente',
        verified: true
      };

    } catch (error) {
      console.error('❌ Error en verificación de dispositivo biométrico:', error);

      // Manejar errores específicos de WebAuthn
      if (error.name === 'NotAllowedError') {
        throw new Error('Acceso denegado. Es posible que hayas cancelado la verificación de huella.');
      } else if (error.name === 'NotSupportedError') {
        throw new Error('Tu dispositivo no soporta verificación biométrica.');
      } else if (error.name === 'SecurityError') {
        throw new Error('Error de seguridad. Verifica que estés usando HTTPS en producción.');
      } else if (error.name === 'InvalidStateError') {
        throw new Error('Estado inválido del autenticador.');
      } else if (error.response?.data?.message) {
        throw new Error(error.response.data.message);
      } else if (error.message) {
        throw new Error(error.message);
      } else {
        throw new Error('Error desconocido durante la verificación biométrica');
      }
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