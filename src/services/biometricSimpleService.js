/**
 * Servicio Biométrico Simple
 * Sin almacenamiento en BD, solo usa la huella del dispositivo
 */

import axios from 'axios';
import API_CONFIG from '../config/api';

const API_BASE = API_CONFIG.baseURL;

export class BiometricSimpleService {
  /**
   * Verificar si el navegador soporta WebAuthn
   */
  static isSupported() {
    return typeof PublicKeyCredential !== 'undefined';
  }

  /**
   * Verificar si el dispositivo tiene huella registrada
   */
  static async hasRegisteredBiometric() {
    try {
      if (!this.isSupported()) {
        return false;
      }

      // Verificar si el dispositivo tiene capacidad biométrica
      if (PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable) {
        return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
      }

      return false;
    } catch (error) {
      console.error('Error verificando biométrica:', error);
      return false;
    }
  }

  /**
   * Registrar/Activar huella del dispositivo
   * Solo verifica que el dispositivo tenga huella, sin guardar nada
   */
  static async activateBiometric() {
    if (!this.isSupported()) {
      throw new Error('Este navegador no soporta autenticación biométrica');
    }

    try {
      console.log('👆 Solicitando verificación de huella...');

      // Simplemente intentar una autenticación dummy para verificar que el dispositivo tiene huella
      const challenge = new Uint8Array(32);
      crypto.getRandomValues(challenge);

      const assertion = await navigator.credentials.get({
        publicKey: {
          challenge: challenge,
          timeout: 60000,
          userVerification: 'required'
        },
        mediation: 'optional'
      });

      if (assertion) {
        console.log('✅ Huella verificada en el dispositivo');
        return {
          success: true,
          message: 'Huella activada correctamente. Usa tu huella para los próximos inicios de sesión.'
        };
      } else {
        throw new Error('No se pudo verificar la huella');
      }
    } catch (error) {
      console.error('❌ Error activando huella:', error);

      if (error.name === 'NotAllowedError') {
        throw new Error('Acceso denegado. Cancelaste la verificación de huella.');
      } else if (error.name === 'NotSupportedError') {
        throw new Error('Tu dispositivo no soporta autenticación biométrica.');
      } else if (error.name === 'SecurityError') {
        throw new Error('Error de seguridad. Verifica que uses HTTPS.');
      } else {
        throw new Error(error.message || 'Error al verificar huella');
      }
    }
  }

  /**
   * Autenticarse con huella del dispositivo
   */
  static async authenticateWithBiometric(userEmail) {
    if (!this.isSupported()) {
      throw new Error('Este navegador no soporta autenticación biométrica');
    }

    try {
      console.log('🔑 Solicitando autenticación biométrica...');

      // Generar challenge aleatorio
      const challenge = new Uint8Array(32);
      crypto.getRandomValues(challenge);

      // Solicitar autenticación biométrica al dispositivo
      const assertion = await navigator.credentials.get({
        publicKey: {
          challenge: challenge,
          timeout: 60000,
          userVerification: 'required'
        },
        mediation: 'optional'
      });

      if (!assertion) {
        throw new Error('Autenticación biométrica cancelada');
      }

      console.log('✅ Huella verificada correctamente');

      // Obtener token del servidor usando email
      console.log('🔐 Obteniendo token del servidor...');
      const response = await axios.post(`${API_BASE}/auth/login`, {
        email: userEmail,
        usedBiometric: true
      });

      if (!response.data.success) {
        throw new Error(response.data.message || 'Error en login');
      }

      const { token, user } = response.data;
      localStorage.setItem('token', token);
      localStorage.setItem('user', JSON.stringify(user));

      console.log('🎉 Login biométrico exitoso');

      return {
        success: true,
        message: 'Login con huella exitoso',
        token,
        user,
        authMethod: 'biometric'
      };
    } catch (error) {
      console.error('❌ Error en autenticación biométrica:', error);

      if (error.name === 'NotAllowedError') {
        throw new Error('Acceso denegado. Cancelaste la verificación de huella.');
      } else if (error.name === 'NotSupportedError') {
        throw new Error('Tu dispositivo no soporta autenticación biométrica.');
      } else if (error.name === 'SecurityError') {
        throw new Error('Error de seguridad.');
      } else {
        throw new Error(error.message || 'Error desconocido');
      }
    }
  }

  /**
   * Desactivar autenticación biométrica (es solo local, no necesita servidor)
   */
  static async deactivateBiometric() {
    return {
      success: true,
      message: 'Autenticación biométrica desactivada'
    };
  }

  /**
   * Obtener estado biométrico (solo verifica si el dispositivo tiene capacidad)
   */
  static async getBiometricStatus() {
    try {
      const hasCapability = await this.hasRegisteredBiometric();
      return {
        success: true,
        enabled: hasCapability,
        registeredAt: hasCapability ? new Date() : null,
        hasDevices: hasCapability,
        totalDevices: hasCapability ? 1 : 0
      };
    } catch (error) {
      console.error('Error obteniendo estado biométrico:', error);
      return {
        success: false,
        enabled: false,
        hasDevices: false,
        totalDevices: 0
      };
    }
  }
}

export default BiometricSimpleService;
