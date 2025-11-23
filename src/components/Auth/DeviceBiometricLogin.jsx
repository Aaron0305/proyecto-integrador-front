import React, { useState, useContext, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { AuthContext } from '../../contexts/AuthContext';
import WebAuthnService from '../../services/webauthnService';
import axios from 'axios';
import API_CONFIG from '../../config/api';
import {
  Box,
  Button,
  Typography,
  Alert,
  CircularProgress,
  Grow,
  Zoom,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  useTheme
} from '@mui/material';
import {
  Fingerprint,
  Security,
  Warning
} from '@mui/icons-material';

/**
 * Componente para verificación de huella del dispositivo (INDEPENDIENTE del login)
 * Flujo: 1) Verificar huella del dispositivo, 2) Mostrar éxito
 * El login con email/contraseña es un proceso completamente separado
 */
const DeviceBiometricLogin = ({ email, onClose, onSuccess, autoStart = false }) => {
  const [step, setStep] = useState('biometric'); // 'biometric' | 'success'
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [isSupported, setIsSupported] = useState(false);
  const [checkingSupport, setCheckingSupport] = useState(true);
  const [autoStarted, setAutoStarted] = useState(false);
  const [biometricVerified, setBiometricVerified] = useState(false);

  const { isBiometricSupported, setCurrentUser } = useContext(AuthContext);
  const navigate = useNavigate();
  const theme = useTheme();

  useEffect(() => {
    const checkBiometricSupport = async () => {
      try {
        setCheckingSupport(true);
        const supported = isBiometricSupported();
        setIsSupported(supported);

        if (!supported) {
          setError('Tu navegador no soporta autenticación biométrica');
        }
      } catch (error) {
        console.error('Error verificando soporte biométrico:', error);
        setError('Error al verificar capacidades biométricas del dispositivo');
      } finally {
        setCheckingSupport(false);
      }
    };

    checkBiometricSupport();
  }, [isBiometricSupported]);

  // Auto-iniciar verificación biométrica si autoStart es true
  useEffect(() => {
    if (autoStart && isSupported && !checkingSupport && !autoStarted && !loading && step === 'biometric') {
      setAutoStarted(true);
      handleBiometricVerification();
    }
  }, [autoStart, isSupported, checkingSupport, autoStarted, loading, step]);

  const handleBiometricVerification = async () => {
    if (!email || !email.includes('@')) {
      setError('Por favor ingresa un correo electrónico válido');
      return;
    }

    setLoading(true);
    setError('');

    try {
      // Solo verificar la huella del dispositivo (sin login aún)
      // Necesitamos obtener el challenge y verificar
      console.log('🔑 Verificando huella del dispositivo...');

      // Obtener challenge
      const challengeResponse = await axios.post(`${API_CONFIG.baseURL}/auth/biometric/verify-device`, {
        email
      });

      if (!challengeResponse.data.success) {
        throw new Error(challengeResponse.data.message || 'Error al obtener challenge');
      }

      const { challenge, timeout, rpId } = challengeResponse.data;

      // Asegurar que challenge es un string
      const challengeString = typeof challenge === 'string' ? challenge : String(challenge);

      // Convertir challenge de base64url a ArrayBuffer (API nativa de WebAuthn)
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
          // No especificamos allowCredentials para permitir cualquier huella del dispositivo
        }
      });

      if (!assertion) {
        throw new Error('Verificación de huella cancelada');
      }

      console.log('✅ Huella del dispositivo verificada correctamente');
      
      // Verificar la huella con el servidor
      const result = await WebAuthnService.verifyDeviceBiometric(email);
      
      if (result.success && result.verified) {
        setBiometricVerified(true);
        setStep('success');
        setError('');
        
        // Cerrar el diálogo después de 2 segundos
        setTimeout(() => {
          if (onClose) {
            onClose();
          }
        }, 2000);
      } else {
        throw new Error('La verificación de huella falló');
      }

    } catch (err) {
      console.error('Error en verificación biométrica:', err);
      
      if (err.name === 'NotAllowedError') {
        setError('Acceso denegado. Es posible que hayas cancelado la verificación de huella.');
      } else if (err.name === 'NotSupportedError') {
        setError('Tu dispositivo no soporta verificación biométrica.');
      } else if (err.message) {
        setError(err.message);
      } else {
        setError('Error en la verificación biométrica. Por favor, intenta de nuevo.');
      }
    } finally {
      setLoading(false);
    }
  };

  // Ya no necesitamos handlePasswordSubmit - el login es completamente separado

  if (checkingSupport) {
    return (
      <Box sx={{ textAlign: 'center', p: 2 }}>
        <CircularProgress size={24} />
        <Typography variant="body2" sx={{ mt: 1 }}>
          Verificando capacidades biométricas...
        </Typography>
      </Box>
    );
  }

  if (!isSupported) {
    return (
      <Alert severity="warning" sx={{ mb: 2 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Warning />
          <Box>
            <Typography variant="body2">
              Tu navegador no soporta autenticación biométrica
            </Typography>
            <Typography variant="caption" color="text.secondary">
              Intenta usar Chrome, Firefox, Safari o Edge actualizados
            </Typography>
          </Box>
        </Box>
      </Alert>
    );
  }

  return (
    <Box sx={{ textAlign: 'center' }}>
      {error && (
        <Grow in={!!error} timeout={500}>
          <Alert severity="error" sx={{ mb: 2, borderRadius: 2 }}>
            {error}
          </Alert>
        </Grow>
      )}

      {/* Paso 1: Verificación Biométrica */}
      {step === 'biometric' && (
        <>
          <Box sx={{ mb: 3 }}>
            <Zoom in={true} timeout={800}>
              <Box
                sx={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  width: 80,
                  height: 80,
                  borderRadius: '50%',
                  background: `linear-gradient(45deg, ${theme.palette.primary.main} 30%, ${theme.palette.secondary.main} 90%)`,
                  color: 'white',
                  mb: 2,
                  boxShadow: theme.shadows[4],
                  animation: loading ? 'pulse 1.5s ease-in-out infinite' : 'none',
                }}
              >
                <Fingerprint sx={{ fontSize: 40 }} />
              </Box>
            </Zoom>

            <Typography variant="h6" gutterBottom>
              Verificar Huella del Dispositivo
            </Typography>

            <Typography variant="body2" color="text.secondary" paragraph>
              {loading 
                ? 'Coloca tu huella digital para continuar...' 
                : 'Primero verifica tu huella digital, Face ID o PIN del dispositivo'}
            </Typography>
          </Box>

          {!loading && (
            <Button
              variant="contained"
              size="large"
              fullWidth
              onClick={handleBiometricVerification}
              disabled={loading || !email || !email.includes('@')}
              startIcon={<Security />}
              sx={{
                py: 1.5,
                borderRadius: 2,
                background: `linear-gradient(45deg, ${theme.palette.primary.main} 30%, ${theme.palette.secondary.main} 90%)`,
                '&:hover': {
                  background: `linear-gradient(45deg, ${theme.palette.primary.dark} 30%, ${theme.palette.secondary.dark} 90%)`,
                  transform: 'translateY(-1px)',
                  boxShadow: theme.shadows[6]
                },
                '&:disabled': {
                  background: theme.palette.action.disabledBackground
                }
              }}
            >
              Verificar Huella
            </Button>
          )}

          {loading && (
            <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', gap: 2 }}>
              <CircularProgress size={24} />
              <Typography variant="body2" color="text.secondary">
                Esperando verificación de huella...
              </Typography>
            </Box>
          )}
        </>
      )}


      {/* Paso 2: Éxito - Huella Verificada */}
      {step === 'success' && (
        <Box>
          <Zoom in={true} timeout={800}>
            <Box
              sx={{
                display: 'inline-flex',
                alignItems: 'center',
                justifyContent: 'center',
                width: 80,
                height: 80,
                borderRadius: '50%',
                background: theme.palette.success.main,
                color: 'white',
                mb: 2,
                boxShadow: theme.shadows[4],
              }}
            >
              <Security sx={{ fontSize: 40 }} />
            </Box>
          </Zoom>

          <Typography variant="h6" gutterBottom color="success.main">
            ¡Huella Verificada!
          </Typography>

          <Typography variant="body2" color="text.secondary" paragraph>
            Tu huella del dispositivo ha sido verificada correctamente.
          </Typography>

          <Typography variant="body2" color="text.secondary">
            Ahora puedes iniciar sesión con tu correo y contraseña.
          </Typography>
        </Box>
      )}

      {onClose && step !== 'success' && !loading && (
        <Button
          variant="text"
          size="small"
          onClick={onClose}
          sx={{ mt: 2, color: theme.palette.text.secondary }}
        >
          Cancelar
        </Button>
      )}
    </Box>
  );
};

// Componente Dialog para usar en el login normal
export const DeviceBiometricLoginDialog = ({ open, onClose, email, autoStart = true }) => {
  const [success, setSuccess] = useState(false);

  const handleSuccess = () => {
    setSuccess(true);
    setTimeout(() => {
      onClose();
    }, 2000);
  };

  return (
    <Dialog
      open={open}
      onClose={onClose}
      maxWidth="sm"
      fullWidth
      PaperProps={{
        sx: {
          borderRadius: 3,
          p: 1
        }
      }}
    >
      <DialogTitle sx={{ textAlign: 'center', pb: 1 }}>
        {success ? (
          <Box sx={{ color: 'success.main' }}>
            <Security sx={{ fontSize: 40, mb: 1 }} />
            <Typography variant="h6">¡Autenticación Exitosa!</Typography>
          </Box>
        ) : (
          'Verificación de Huella del Dispositivo'
        )}
      </DialogTitle>

      <DialogContent sx={{ px: 3, pb: 2 }}>
        {success ? (
          <Box sx={{ textAlign: 'center' }}>
            <Typography color="text.secondary">
              Redirigiendo al dashboard...
            </Typography>
            <CircularProgress size={24} sx={{ mt: 2 }} />
          </Box>
        ) : (
          <DeviceBiometricLogin
            email={email}
            onClose={onClose}
            onSuccess={handleSuccess}
            autoStart={autoStart}
          />
        )}
      </DialogContent>

      {!success && (
        <DialogActions sx={{ px: 3, pb: 2 }}>
          <Typography variant="caption" color="text.secondary" sx={{ flexGrow: 1 }}>
            Tu información biométrica nunca sale de tu dispositivo
          </Typography>
        </DialogActions>
      )}
    </Dialog>
  );
};

export default DeviceBiometricLogin;

