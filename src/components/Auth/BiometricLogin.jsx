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
  TextField,
  useTheme
} from '@mui/material';
import {
  Fingerprint,
  Security,
  Smartphone,
  Warning
} from '@mui/icons-material';

const BiometricLogin = ({ email, onClose, onSuccess }) => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [isSupported, setIsSupported] = useState(false);
  const [hasDevices, setHasDevices] = useState(false);
  const [checkingSupport, setCheckingSupport] = useState(true);
  
  const { loginWithBiometric, isBiometricSupported, checkBiometricAvailable, userHasBiometricDevices } = useContext(AuthContext);
  const navigate = useNavigate();
  const theme = useTheme();

  useEffect(() => {
    const checkBiometricSupport = async () => {
      try {
        setCheckingSupport(true);
        
        // Verificar si el navegador soporta WebAuthn
        const supported = isBiometricSupported();
        setIsSupported(supported);
        
        if (supported && email) {
          // Verificar si el usuario tiene dispositivos registrados
          const userHasDevices = await userHasBiometricDevices(email);
          setHasDevices(userHasDevices);
          
          // Verificar si hay autenticadores disponibles en el dispositivo
          const hasAuth = await checkBiometricAvailable();
          if (!hasAuth && !userHasDevices) {
            setError('Tu dispositivo no tiene sensores biométricos disponibles');
          }
        }
      } catch (error) {
        console.error('Error verificando soporte biométrico:', error);
        setError('Error al verificar capacidades biométricas del dispositivo');
      } finally {
        setCheckingSupport(false);
      }
    };

    checkBiometricSupport();
  }, [email, isBiometricSupported, checkBiometricAvailable, userHasBiometricDevices]);

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

  if (!hasDevices) {
    return (
      <Alert severity="info" sx={{ mb: 2 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Smartphone />
          <Box>
            <Typography variant="body2">
              No tienes dispositivos biométricos registrados
            </Typography>
            <Typography variant="caption" color="text.secondary">
              Inicia sesión normalmente y ve a tu perfil para configurar la autenticación biométrica
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
          Usa tu huella digital, Face ID o PIN para acceder de forma segura
        </Typography>
      </Box>

      <Button
        variant="contained"
        size="large"
        fullWidth
        onClick={handleBiometricLogin}
        disabled={loading}
        startIcon={loading ? <CircularProgress size={20} /> : <Security />}
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
        {loading ? 'Verificando...' : 'Iniciar con Biométrico'}
      </Button>

      {onClose && (
        <Button
          variant="text"
          size="small"
          onClick={onClose}
          sx={{ mt: 1, color: theme.palette.text.secondary }}
        >
          Cancelar
        </Button>
      )}
    </Box>
  );
};

// Componente Dialog para usar en el login normal
export const BiometricLoginDialog = ({ open, onClose, email }) => {
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