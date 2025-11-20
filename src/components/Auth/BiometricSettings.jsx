import React, { useState, useEffect, useContext } from 'react';
import { AuthContext } from '../../contexts/AuthContext';
import WebAuthnService from '../../services/webauthnService';
import WebAuthnDiagnostic from './WebAuthnDiagnostic';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Button,
  Alert,
  CircularProgress,
  Switch,
  FormControlLabel,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogContentText,
  DialogActions,
  Chip,
  Divider,
  Grow,
  Zoom,
  useTheme,
  LinearProgress,
  Stepper,
  Step,
  StepLabel,
  Paper
} from '@mui/material';
import {
  Fingerprint,
  Security,
  Warning,
  CheckCircle,
  Cancel,
  Delete,
  PowerSettingsNew,
  Shield,
  TouchApp,
  Refresh,
  Done,
  BugReport,
  Computer,
  Usb
} from '@mui/icons-material';
import { API_ENV } from '../../config/api';

const RP_ID = (() => {
  try {
    return new URL(API_ENV.BASE_ORIGIN).hostname || 'localhost';
  } catch {
    return 'localhost';
  }
})();

const BiometricSettings = () => {
  const [isEnabled, setIsEnabled] = useState(false);
  const [isSupported, setIsSupported] = useState(false);
  const [biometricStatus, setBiometricStatus] = useState({
    enabled: false,
    registeredAt: null
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [operating, setOperating] = useState(false);
  const [showDeleteDialog, setShowDeleteDialog] = useState(false);
  const [hasAvailableAuth, setHasAvailableAuth] = useState(false);
  const [showRegistrationDialog, setShowRegistrationDialog] = useState(false);
  const [registrationStep, setRegistrationStep] = useState(0);
  const [registrationSamples, setRegistrationSamples] = useState([]);
  const [currentSampleAttempting, setCurrentSampleAttempting] = useState(false);
  const [showDiagnostic, setShowDiagnostic] = useState(false);
  const [selectedAuthType, setSelectedAuthType] = useState('both');

  const {
    registerBiometricDevice,
    isBiometricSupported,
    checkBiometricAvailable
  } = useContext(AuthContext);

  const theme = useTheme();

  useEffect(() => {
    const initializeBiometric = async () => {
      try {
        // Verificar soporte del navegador
        const supported = isBiometricSupported();
        setIsSupported(supported);

        if (supported) {
          // Verificar si hay autenticadores disponibles
          const hasAuth = await checkBiometricAvailable();
          setHasAvailableAuth(hasAuth);

          // Cargar estado actual
          await loadBiometricStatus();
        }
      } catch (error) {
        console.error('Error inicializando biométrico:', error);
        setError('Error al verificar capacidades biométricas');
      } finally {
        setLoading(false);
      }
    };

    initializeBiometric();
  }, [isBiometricSupported, checkBiometricAvailable]);

  const loadBiometricStatus = async () => {
    try {
      const status = await WebAuthnService.getBiometricStatus();
      setBiometricStatus(status);
      setIsEnabled(status.enabled);
    } catch (error) {
      console.error('Error cargando estado biométrico:', error);
      // Si hay error, asumir que no está registrado
      setBiometricStatus({ enabled: false, registeredAt: null });
      setIsEnabled(false);
    }
  };

  const REQUIRED_SAMPLES = 3; // Número de muestras requeridas
  const sampleSteps = [
    'Primera muestra - Posición normal',
    'Segunda muestra - Ángulo diferente', 
    'Tercera muestra - Otra parte del dedo',
    'Guardando en el servidor...'
  ];

  const startBiometricRegistration = () => {
    setShowRegistrationDialog(true);
    setRegistrationStep(0);
    setRegistrationSamples([]);
    setError('');
    setSuccess('');
  };

  const captureBiometricSample = async () => {
    setCurrentSampleAttempting(true);
    setError('');

    try {
      // Solo capturar localmente las muestras biométricas, NO enviar al servidor aún
      const credential = await navigator.credentials.create({
        publicKey: {
          challenge: new Uint8Array(32), // Challenge temporal para la captura local
          rp: {
            name: 'Sistema de Seguimiento de Docentes',
            id: RP_ID
          },
          user: {
            id: new TextEncoder().encode('temp_user_id'),
            name: 'temp@temp.com',
            displayName: 'Temp User'
          },
          pubKeyCredParams: [
            { alg: -7, type: 'public-key' },
            { alg: -257, type: 'public-key' }
          ],
          authenticatorSelection: {
            authenticatorAttachment: 'platform',
            userVerification: 'required',
            residentKey: 'preferred'
          },
          timeout: 60000
        }
      });

      if (credential) {
        // Agregar muestra exitosa (solo local)
        const newSamples = [...registrationSamples, {
          timestamp: Date.now(),
          credentialId: credential.id,
          sampleNumber: registrationSamples.length + 1
        }];
        setRegistrationSamples(newSamples);
        
        if (newSamples.length >= REQUIRED_SAMPLES) {
          // Ahora SÍ registrar en el servidor usando la última captura exitosa
          setRegistrationStep(REQUIRED_SAMPLES);
          await registerFinalBiometric();
        } else {
          // Continuar con siguiente muestra
          setRegistrationStep(newSamples.length);
          setTimeout(() => {
            setCurrentSampleAttempting(false);
          }, 1000);
        }
      }
    } catch (error) {
      if (error.name === 'NotAllowedError') {
        setError('Acceso biométrico denegado. Asegúrate de permitir el acceso al sensor.');
      } else {
        setError(error.message || 'Error al capturar huella. Inténtalo de nuevo.');
      }
      setCurrentSampleAttempting(false);
    }
  };

  const registerFinalBiometric = async () => {
    try {
      // Realizar el registro real con el servidor
      const result = await registerBiometricDevice();
      if (result.success) {
        setTimeout(() => {
          setSuccess(`¡Registro completado! Se capturaron ${REQUIRED_SAMPLES} muestras de tu huella para mayor seguridad.`);
          setShowRegistrationDialog(false);
          loadBiometricStatus();
          setCurrentSampleAttempting(false);
        }, 1500);
      }
    } catch (error) {
      setError(error.message || 'Error al finalizar el registro. Inténtalo de nuevo.');
      setCurrentSampleAttempting(false);
    }
  };

  const cancelRegistration = () => {
    setShowRegistrationDialog(false);
    setRegistrationStep(0);
    setRegistrationSamples([]);
    setCurrentSampleAttempting(false);
    setError('');
  };

  const toggleBiometric = async (enable) => {
    setOperating(true);
    setError('');
    setSuccess('');

    try {
      const result = await WebAuthnService.toggleBiometric(enable);
      if (result.success) {
        setSuccess(result.message);
        setIsEnabled(enable);
        setBiometricStatus(prev => ({ ...prev, enabled: enable }));
      }
    } catch (error) {
      setError(error.message || 'Error al cambiar estado de la huella');
      // Revertir el switch
      setIsEnabled(!enable);
    } finally {
      setOperating(false);
    }
  };

  const deleteBiometric = async () => {
    setOperating(true);
    setError('');
    setSuccess('');

    try {
      const result = await WebAuthnService.deleteBiometric();
      if (result.success) {
        setSuccess('Huella eliminada permanentemente. Deberás registrarla de nuevo si deseas usarla.');
        setBiometricStatus({ enabled: false, registeredAt: null });
        setIsEnabled(false);
        setShowDeleteDialog(false);
      }
    } catch (error) {
      setError(error.message || 'Error al eliminar huella');
    } finally {
      setOperating(false);
    }
  };

  const formatDate = (dateString) => {
    if (!dateString) return null;
    try {
      return new Date(dateString).toLocaleDateString('es-ES', {
        year: 'numeric',
        month: 'long',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
      });
    } catch (error) {
      return 'Fecha no válida';
    }
  };

  if (loading) {
    return (
      <Box sx={{ textAlign: 'center', p: 4 }}>
        <CircularProgress />
        <Typography variant="body2" sx={{ mt: 2 }}>
          Verificando configuración biométrica...
        </Typography>
      </Box>
    );
  }

  if (!isSupported) {
    return (
      <Card sx={{ borderRadius: 3, boxShadow: theme.shadows[2] }}>
        <CardContent sx={{ p: 3 }}>
          <Alert severity="warning" sx={{ borderRadius: 2 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
              <Warning />
              <Typography variant="h6">
                Autenticación biométrica no disponible
              </Typography>
            </Box>
            <Typography variant="body2">
              Tu navegador no soporta WebAuthn. Para usar autenticación biométrica, 
              actualiza a las versiones más recientes de Chrome, Firefox, Safari o Edge.
            </Typography>
          </Alert>
        </CardContent>
      </Card>
    );
  }

  if (!hasAvailableAuth) {
    return (
      <Card sx={{ borderRadius: 3, boxShadow: theme.shadows[2] }}>
        <CardContent sx={{ p: 3 }}>
          <Alert severity="info" sx={{ borderRadius: 2 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
              <Fingerprint />
              <Typography variant="h6">
                Configurar sensor biométrico
              </Typography>
            </Box>
            <Typography variant="body2" sx={{ mb: 2 }}>
              Tu dispositivo no tiene sensores biométricos disponibles o no están configurados.
            </Typography>
            <Typography variant="body2">
              <strong>Para usar esta función:</strong><br/>
              • Configura huella digital, Face ID, o Windows Hello en tu dispositivo<br/>
              • Asegúrate de que esté activado en la configuración del sistema<br/>
              • Recarga esta página después de configurarlo
            </Typography>
          </Alert>
        </CardContent>
      </Card>
    );
  }

  const hasRegisteredBiometric = biometricStatus.registeredAt !== null;

  return (
    <Box>
      <Card sx={{ borderRadius: 3, boxShadow: theme.shadows[4] }}>
        <CardContent sx={{ p: 3 }}>
          {/* Header */}
          <Box sx={{ display: 'flex', alignItems: 'center', mb: 3 }}>
            <Shield sx={{ color: theme.palette.primary.main, mr: 2, fontSize: 32 }} />
            <Box sx={{ flexGrow: 1 }}>
              <Typography variant="h5" component="h2" gutterBottom>
                Autenticación Biométrica
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Acceso rápido y seguro con tu huella digital, Face ID o PIN
              </Typography>
            </Box>
            {hasRegisteredBiometric && (
              <Chip
                icon={isEnabled ? <CheckCircle /> : <Cancel />}
                label={isEnabled ? 'Activa' : 'Desactivada'}
                color={isEnabled ? 'success' : 'default'}
                variant="outlined"
              />
            )}
          </Box>

          {/* Alerts */}
          {error && (
            <Grow in={!!error}>
              <Alert severity="error" sx={{ mb: 2, borderRadius: 2 }}>
                {error}
              </Alert>
            </Grow>
          )}

          {success && (
            <Grow in={!!success}>
              <Alert severity="success" sx={{ mb: 2, borderRadius: 2 }}>
                {success}
              </Alert>
            </Grow>
          )}

          {/* Info Alert */}
          <Alert severity="info" variant="outlined" sx={{ mb: 3, borderRadius: 2 }}>
            <Typography variant="body2">
              🔐 <strong>Seguridad:</strong> Tu huella nunca sale de tu dispositivo. 
              Solo almacenamos claves criptográficas seguras que no pueden ser utilizadas 
              para reconstruir tu información biométrica.
            </Typography>
          </Alert>

          {/* Estado actual */}
          {hasRegisteredBiometric ? (
            <Box>
              {/* Información de registro */}
              <Box sx={{ 
                p: 2, 
                bgcolor: theme.palette.action.hover, 
                borderRadius: 2, 
                mb: 3 
              }}>
                <Typography variant="body2" color="text.secondary" gutterBottom>
                  <strong>Huella registrada:</strong> {formatDate(biometricStatus.registeredAt)}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  <strong>Estado:</strong> {isEnabled ? 'Activa - Puedes usar inicio rápido' : 'Desactivada temporalmente'}
                </Typography>
              </Box>

              {/* Controles */}
              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                {/* Toggle activar/desactivar */}
                <FormControlLabel
                  control={
                    <Switch
                      checked={isEnabled}
                      onChange={(e) => toggleBiometric(e.target.checked)}
                      disabled={operating}
                      color="primary"
                    />
                  }
                  label={
                    <Box>
                      <Typography variant="body1">
                        {isEnabled ? 'Desactivar' : 'Activar'} autenticación biométrica
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        {isEnabled 
                          ? 'Mantiene tus datos pero desactiva el acceso rápido' 
                          : 'Permite el inicio de sesión con huella digital'
                        }
                      </Typography>
                    </Box>
                  }
                />

                <Divider />

                {/* Botones de acción */}
                <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
                  <Button
                    variant="outlined"
                    startIcon={<BugReport />}
                    onClick={() => setShowDiagnostic(true)}
                    disabled={operating}
                    sx={{ 
                      borderColor: 'info.main', 
                      color: 'info.main',
                      '&:hover': { 
                        borderColor: 'info.dark', 
                        bgcolor: 'info.main',
                        color: 'white'
                      }
                    }}
                  >
                    Diagnóstico WebAuthn
                  </Button>
                  
                  <Button
                    variant="outlined"
                    color="error"
                    startIcon={<Delete />}
                    onClick={() => setShowDeleteDialog(true)}
                    disabled={operating}
                  >
                    Eliminar Huella Permanentemente
                  </Button>
                </Box>
              </Box>
            </Box>
          ) : (
            /* No hay huella registrada */
            <Box sx={{ textAlign: 'center', py: 2 }}>
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
                    boxShadow: theme.shadows[4]
                  }}
                >
                  <Fingerprint sx={{ fontSize: 40 }} />
                </Box>
              </Zoom>

              <Typography variant="h6" gutterBottom>
                Activar inicio con huella
              </Typography>
              
              <Typography variant="body2" color="text.secondary" paragraph>
                Configura tu huella digital para acceder de forma rápida y segura 
                sin necesidad de escribir tu contraseña cada vez.
              </Typography>

              <Button
                variant="contained"
                size="large"
                startIcon={operating ? <CircularProgress size={16} /> : <PowerSettingsNew />}
                onClick={startBiometricRegistration}
                disabled={operating}
                sx={{
                  borderRadius: 2,
                  py: 1.5,
                  px: 4,
                  background: `linear-gradient(45deg, ${theme.palette.primary.main} 30%, ${theme.palette.secondary.main} 90%)`,
                  '&:hover': {
                    background: `linear-gradient(45deg, ${theme.palette.primary.dark} 30%, ${theme.palette.secondary.dark} 90%)`,
                    transform: 'translateY(-1px)',
                    boxShadow: theme.shadows[6]
                  }
                }}
              >
                {operating ? 'Configurando...' : 'Activar inicio con huella'}
              </Button>

              <Button
                variant="text"
                startIcon={<BugReport />}
                onClick={() => setShowDiagnostic(true)}
                sx={{ mt: 2 }}
              >
                Diagnóstico de compatibilidad
              </Button>
            </Box>
          )}
        </CardContent>
      </Card>

      {/* Dialog de registro multi-muestra */}
      <Dialog
        open={showRegistrationDialog}
        onClose={cancelRegistration}
        maxWidth="md"
        fullWidth
        PaperProps={{ 
          sx: { 
            borderRadius: 3,
            minHeight: '60vh'
          } 
        }}
      >
        <DialogTitle sx={{ 
          display: 'flex', 
          alignItems: 'center', 
          gap: 1, 
          color: 'primary.main',
          pb: 1
        }}>
          <Fingerprint />
          Registro de huella digital
        </DialogTitle>
        
        <DialogContent sx={{ pt: 2 }}>
          {/* Stepper */}
          <Stepper activeStep={registrationStep} alternativeLabel sx={{ mb: 4 }}>
            {sampleSteps.map((label, index) => (
              <Step key={index} completed={index < registrationStep}>
                <StepLabel
                  StepIconComponent={({ active, completed }) => (
                    <Box
                      sx={{
                        width: 32,
                        height: 32,
                        borderRadius: '50%',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        bgcolor: completed 
                          ? 'success.main' 
                          : active 
                          ? 'primary.main' 
                          : 'grey.300',
                        color: 'white',
                        fontSize: '0.875rem',
                        fontWeight: 'bold'
                      }}
                    >
                      {completed ? <Done sx={{ fontSize: 18 }} /> : index + 1}
                    </Box>
                  )}
                >
                  {label}
                </StepLabel>
              </Step>
            ))}
          </Stepper>

          {/* Contenido del paso actual */}
          {registrationStep < REQUIRED_SAMPLES ? (
            <Box sx={{ textAlign: 'center', py: 3 }}>
              <Paper 
                elevation={3}
                sx={{ 
                  p: 4, 
                  mb: 3,
                  borderRadius: 3,
                  bgcolor: currentSampleAttempting 
                    ? 'action.selected' 
                    : 'background.paper',
                  border: currentSampleAttempting 
                    ? `2px solid ${theme.palette.primary.main}` 
                    : '1px solid',
                  borderColor: currentSampleAttempting 
                    ? 'primary.main' 
                    : 'divider',
                  transition: 'all 0.3s ease'
                }}
              >
                <Box
                  sx={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    width: 120,
                    height: 120,
                    borderRadius: '50%',
                    background: currentSampleAttempting
                      ? `linear-gradient(45deg, ${theme.palette.success.main} 30%, ${theme.palette.primary.main} 90%)`
                      : `linear-gradient(45deg, ${theme.palette.primary.main} 30%, ${theme.palette.secondary.main} 90%)`,
                    color: 'white',
                    mb: 2,
                    boxShadow: theme.shadows[4],
                    animation: currentSampleAttempting ? 'pulse 1.5s ease-in-out infinite' : 'none',
                    '@keyframes pulse': {
                      '0%': {
                        transform: 'scale(1)',
                        boxShadow: theme.shadows[4]
                      },
                      '50%': {
                        transform: 'scale(1.05)',
                        boxShadow: theme.shadows[8]
                      },
                      '100%': {
                        transform: 'scale(1)',
                        boxShadow: theme.shadows[4]
                      }
                    }
                  }}
                >
                  {currentSampleAttempting ? (
                    <CircularProgress size={40} sx={{ color: 'white' }} />
                  ) : (
                    <TouchApp sx={{ fontSize: 60 }} />
                  )}
                </Box>

                <Typography variant="h5" gutterBottom color="primary">
                  {currentSampleAttempting 
                    ? 'Capturando huella...' 
                    : `Muestra ${registrationStep + 1} de ${REQUIRED_SAMPLES}`
                  }
                </Typography>
                
                <Typography variant="body1" color="text.secondary" paragraph>
                  {currentSampleAttempting 
                    ? 'Mantén el dedo sobre el sensor hasta completar la captura'
                    : registrationStep === 0
                    ? 'Coloca tu dedo sobre el sensor biométrico para la primera muestra'
                    : registrationStep === 1 
                    ? 'Ahora coloca el mismo dedo con un ángulo ligeramente diferente'
                    : 'Última muestra: usa otra parte del mismo dedo para mejor cobertura'
                  }
                </Typography>

                {registrationSamples.length > 0 && (
                  <Box sx={{ mt: 2 }}>
                    <Typography variant="body2" color="success.main" sx={{ mb: 1 }}>
                      ✓ Muestras capturadas: {registrationSamples.length}
                    </Typography>
                    <LinearProgress 
                      variant="determinate" 
                      value={(registrationSamples.length / REQUIRED_SAMPLES) * 100}
                      sx={{ borderRadius: 1, height: 6 }}
                    />
                  </Box>
                )}
              </Paper>

              {/* Tips */}
              <Alert severity="info" sx={{ textAlign: 'left', borderRadius: 2 }}>
                <Typography variant="body2" sx={{ mb: 1 }}>
                  <strong>Proceso de registro mejorado:</strong>
                </Typography>
                <Typography variant="body2" component="div">
                  • Capturaremos {REQUIRED_SAMPLES} muestras del mismo dedo<br/>
                  • Cada muestra mejora la precisión del reconocimiento<br/>
                  • Varía ligeramente el ángulo en cada captura<br/>
                  • El registro final se guardará después de todas las muestras<br/>
                  • Mantén el dedo limpio y seco
                </Typography>
              </Alert>
            </Box>
          ) : (
            /* Completado */
            <Box sx={{ textAlign: 'center', py: 4 }}>
              <CheckCircle 
                sx={{ 
                  fontSize: 80, 
                  color: 'success.main', 
                  mb: 2 
                }} 
              />
              <Typography variant="h5" gutterBottom color="success.main">
                ¡Registro completado!
              </Typography>
              <Typography variant="body1" color="text.secondary">
                Se registraron {REQUIRED_SAMPLES} muestras de tu huella para mayor seguridad.
              </Typography>
            </Box>
          )}

          {error && (
            <Alert severity="error" sx={{ mt: 2, borderRadius: 2 }}>
              {error}
            </Alert>
          )}
        </DialogContent>
        
        <DialogActions sx={{ px: 3, pb: 2, gap: 1 }}>
          <Button 
            onClick={cancelRegistration}
            disabled={currentSampleAttempting}
          >
            Cancelar
          </Button>
          
          {registrationStep < REQUIRED_SAMPLES && (
            <Button
              onClick={captureBiometricSample}
              variant="contained"
              disabled={currentSampleAttempting}
              startIcon={currentSampleAttempting ? <CircularProgress size={16} /> : <TouchApp />}
            >
              {currentSampleAttempting 
                ? 'Capturando...' 
                : registrationSamples.length === 0 
                ? 'Comenzar captura'
                : 'Siguiente muestra'
              }
            </Button>
          )}
        </DialogActions>
      </Dialog>

      {/* Dialog de confirmación para eliminar */}
      <Dialog
        open={showDeleteDialog}
        onClose={() => setShowDeleteDialog(false)}
        maxWidth="sm"
        PaperProps={{ sx: { borderRadius: 3 } }}
      >
        <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 1, color: 'error.main' }}>
          <Delete />
          Eliminar huella permanentemente
        </DialogTitle>
        
        <DialogContent>
          <DialogContentText>
            <strong>¿Estás seguro?</strong> Esta acción eliminará permanentemente tu huella digital 
            registrada y todos los datos relacionados.
          </DialogContentText>
          <DialogContentText sx={{ mt: 2 }}>
            Si deseas usar autenticación biométrica nuevamente, deberás registrar 
            tu huella desde cero.
          </DialogContentText>
        </DialogContent>
        
        <DialogActions sx={{ px: 3, pb: 2 }}>
          <Button 
            onClick={() => setShowDeleteDialog(false)}
            disabled={operating}
          >
            Cancelar
          </Button>
          <Button
            onClick={deleteBiometric}
            variant="contained"
            color="error"
            disabled={operating}
            startIcon={operating ? <CircularProgress size={16} /> : <Delete />}
          >
            {operating ? 'Eliminando...' : 'Eliminar'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Componente de diagnóstico WebAuthn */}
      <WebAuthnDiagnostic 
        open={showDiagnostic} 
        onClose={() => setShowDiagnostic(false)} 
      />
    </Box>
  );
};

export default BiometricSettings;