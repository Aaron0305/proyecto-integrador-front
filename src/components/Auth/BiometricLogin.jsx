import React, { useState, useContext, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { AuthContext } from '../../contexts/AuthContext';
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

const BiometricLogin = ({ email, onClose, onSuccess, autoStart = false }) => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [isSupported, setIsSupported] = useState(false);
  const [checkingSupport, setCheckingSupport] = useState(true);
  const [autoStarted, setAutoStarted] = useState(false);

  const { loginWithBiometric, isBiometricSupported } = useContext(AuthContext);
  const navigate = useNavigate();
  const theme = useTheme();

  useEffect(() => {
    const checkBiometricSupport = async () => {
      try {
        setCheckingSupport(true);

        // Verificar si el navegador soporta WebAuthn
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

  // Auto-iniciar autenticación biométrica si autoStart es true
  useEffect(() => {
    if (autoStart && isSupported && !checkingSupport && !autoStarted && !loading) {
      setAutoStarted(true);
      handleBiometricLogin();
    }
  }, [autoStart, isSupported, checkingSupport, autoStarted, loading]);

  const handleBiometricLogin = async () => {
    setLoading(true);
    setError('');

    try {
      const result = await loginWithBiometric();

      if (result.success) {
        onSuccess && onSuccess(result);
        setTimeout(() => {
          navigate('/', { replace: true });
        }, 1000);
      }
    } catch (err) {
      console.error('Error en login biométrico:', err);
      setError(err.message || 'Error en la autenticación biométrica');
    } finally {
      setLoading(false);
    }
  };

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
          Autenticación Biométrica
        </Typography>

        <Typography variant="body2" color="text.secondary" paragraph>
          {loading ? 'Coloca tu huella digital para continuar...' : 'Usa tu huella digital, Face ID o PIN para acceder de forma segura'}
        </Typography>
      </Box>

      {!loading && (
        <Button
          variant="contained"
          size="large"
          fullWidth
          onClick={handleBiometricLogin}
          disabled={loading}
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
          Iniciar con Biométrico
        </Button>
      )}

      {loading && (
        <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', gap: 2 }}>
          <CircularProgress size={24} />
          <Typography variant="body2" color="text.secondary">
            Esperando autenticación...
          </Typography>
        </Box>
      )}

      {onClose && !loading && (
        <Button
          variant="text"
          size="small"
          onClick={onClose}
          sx={{ mt: 2, color: theme.palette.text.secondary }}
        >
          Usar contraseña en su lugar
        </Button>
      )}
    </Box>
  );
};

// Componente Dialog para usar en el login normal
export const BiometricLoginDialog = ({ open, onClose, email, autoStart = true }) => {
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
          'Acceso Biométrico'
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
          <BiometricLogin
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

export default BiometricLogin;