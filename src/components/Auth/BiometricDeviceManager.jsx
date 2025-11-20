import React, { useState, useEffect, useContext } from 'react';
import { AuthContext } from '../../contexts/AuthContext';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Button,
  Alert,
  CircularProgress,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  ListItemSecondaryAction,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogContentText,
  DialogActions,
  TextField,
  Chip,
  Divider,
  Grow,
  Zoom,
  useTheme
} from '@mui/material';
import {
  Fingerprint,
  Smartphone,
  Delete,
  Add,
  Security,
  Warning,
  CheckCircle,
  DeviceUnknown,
  Laptop,
  Watch
} from '@mui/icons-material';

const BiometricDeviceManager = () => {
  const [devices, setDevices] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [registering, setRegistering] = useState(false);
  const [removing, setRemoving] = useState(null);
  const [showAddDialog, setShowAddDialog] = useState(false);
  const [deviceName, setDeviceName] = useState('');
  const [isSupported, setIsSupported] = useState(false);
  const [hasAuthenticator, setHasAuthenticator] = useState(false);

  const {
    getBiometricDevices,
    registerBiometricDevice,
    removeBiometricDevice,
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
          setHasAuthenticator(hasAuth);

          // Cargar dispositivos registrados
          await loadDevices();
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

  const loadDevices = async () => {
    try {
      const deviceList = await getBiometricDevices();
      setDevices(deviceList);
    } catch (error) {
      setError('Error al cargar dispositivos: ' + error.message);
    }
  };

  const handleAddDevice = async () => {
    if (!deviceName.trim()) {
      setError('Por favor ingresa un nombre para el dispositivo');
      return;
    }

    setRegistering(true);
    setError('');
    setSuccess('');

    try {
      const result = await registerBiometricDevice(deviceName);
      if (result.success) {
        setSuccess('Dispositivo biométrico registrado exitosamente');
        setShowAddDialog(false);
        setDeviceName('');
        await loadDevices();
      }
    } catch (error) {
      setError(error.message || 'Error al registrar dispositivo biométrico');
    } finally {
      setRegistering(false);
    }
  };

  const handleRemoveDevice = async (credentialId) => {
    setRemoving(credentialId);
    setError('');
    setSuccess('');

    try {
      const result = await removeBiometricDevice(credentialId);
      if (result.success) {
        setSuccess('Dispositivo eliminado exitosamente');
        await loadDevices();
      }
    } catch (error) {
      setError('Error al eliminar dispositivo: ' + error.message);
    } finally {
      setRemoving(null);
    }
  };

  const getDeviceIcon = (transports) => {
    if (!transports || transports.length === 0) return <DeviceUnknown />;
    
    if (transports.includes('internal')) return <Fingerprint />;
    if (transports.includes('usb')) return <Laptop />;
    if (transports.includes('ble')) return <Watch />;
    if (transports.includes('nfc')) return <Smartphone />;
    
    return <DeviceUnknown />;
  };

  const formatDate = (dateString) => {
    try {
      return new Date(dateString).toLocaleDateString('es-ES', {
        year: 'numeric',
        month: 'short',
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
          Cargando dispositivos biométricos...
        </Typography>
      </Box>
    );
  }

  if (!isSupported) {
    return (
      <Alert severity="warning" sx={{ m: 2 }}>
        <Typography variant="h6" gutterBottom>
          Autenticación biométrica no disponible
        </Typography>
        <Typography variant="body2">
          Tu navegador no soporta WebAuthn. Para usar autenticación biométrica, 
          actualiza a las versiones más recientes de Chrome, Firefox, Safari o Edge.
        </Typography>
      </Alert>
    );
  }

  if (!hasAuthenticator) {
    return (
      <Alert severity="info" sx={{ m: 2 }}>
        <Typography variant="h6" gutterBottom>
          Sin sensores biométricos
        </Typography>
        <Typography variant="body2">
          Tu dispositivo no tiene sensores biométricos disponibles (huella digital, Face ID, etc.) 
          o no están configurados en tu sistema operativo.
        </Typography>
      </Alert>
    );
  }

  return (
    <Box sx={{ p: 2 }}>
      <Card sx={{ borderRadius: 3, boxShadow: theme.shadows[4] }}>
        <CardContent sx={{ p: 3 }}>
          {/* Header */}
          <Box sx={{ display: 'flex', alignItems: 'center', mb: 3 }}>
            <Security sx={{ color: theme.palette.primary.main, mr: 2, fontSize: 32 }} />
            <Box sx={{ flexGrow: 1 }}>
              <Typography variant="h5" component="h2" gutterBottom>
                Dispositivos Biométricos
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Gestiona los dispositivos que pueden acceder a tu cuenta usando autenticación biométrica
              </Typography>
            </Box>
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
              🔐 <strong>Seguridad:</strong> Tu información biométrica nunca sale de tu dispositivo. 
              Solo se almacenan claves criptográficas seguras en nuestros servidores.
            </Typography>
          </Alert>

          {/* Add Device Button */}
          <Box sx={{ mb: 3 }}>
            <Button
              variant="contained"
              startIcon={<Add />}
              onClick={() => setShowAddDialog(true)}
              disabled={registering}
              sx={{
                borderRadius: 2,
                py: 1,
                background: `linear-gradient(45deg, ${theme.palette.primary.main} 30%, ${theme.palette.secondary.main} 90%)`,
                '&:hover': {
                  background: `linear-gradient(45deg, ${theme.palette.primary.dark} 30%, ${theme.palette.secondary.dark} 90%)`,
                }
              }}
            >
              Añadir Dispositivo Biométrico
            </Button>
          </Box>

          {/* Devices List */}
          {devices.length === 0 ? (
            <Box sx={{ textAlign: 'center', py: 4 }}>
              <Smartphone sx={{ fontSize: 64, color: theme.palette.action.disabled, mb: 2 }} />
              <Typography variant="h6" color="text.secondary" gutterBottom>
                No hay dispositivos registrados
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Añade tu primer dispositivo biométrico para acceder de forma rápida y segura
              </Typography>
            </Box>
          ) : (
            <List sx={{ bgcolor: 'background.paper', borderRadius: 2, border: `1px solid ${theme.palette.divider}` }}>
              {devices.map((device, index) => (
                <React.Fragment key={device.id}>
                  <Zoom in={true} style={{ transitionDelay: `${index * 100}ms` }}>
                    <ListItem sx={{ py: 2 }}>
                      <ListItemIcon>
                        {getDeviceIcon(device.transports)}
                      </ListItemIcon>
                      
                      <ListItemText
                        primary={
                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                            <Typography variant="body1" fontWeight="medium">
                              {device.deviceName}
                            </Typography>
                            <Chip
                              size="small"
                              label="Activo"
                              color="success"
                              variant="outlined"
                              icon={<CheckCircle />}
                            />
                          </Box>
                        }
                        secondary={
                          <Box sx={{ mt: 0.5 }}>
                            <Typography variant="body2" color="text.secondary">
                              Registrado: {formatDate(device.registeredAt)}
                            </Typography>
                            <Typography variant="body2" color="text.secondary">
                              Último uso: {formatDate(device.lastUsed)}
                            </Typography>
                          </Box>
                        }
                      />
                      
                      <ListItemSecondaryAction>
                        <IconButton
                          edge="end"
                          onClick={() => handleRemoveDevice(device.id)}
                          disabled={removing === device.id}
                          color="error"
                          sx={{
                            '&:hover': {
                              bgcolor: 'error.light',
                              color: 'error.contrastText'
                            }
                          }}
                        >
                          {removing === device.id ? (
                            <CircularProgress size={20} />
                          ) : (
                            <Delete />
                          )}
                        </IconButton>
                      </ListItemSecondaryAction>
                    </ListItem>
                  </Zoom>
                  
                  {index < devices.length - 1 && <Divider />}
                </React.Fragment>
              ))}
            </List>
          )}
        </CardContent>
      </Card>

      {/* Add Device Dialog */}
      <Dialog
        open={showAddDialog}
        onClose={() => setShowAddDialog(false)}
        maxWidth="sm"
        fullWidth
        PaperProps={{ sx: { borderRadius: 3 } }}
      >
        <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Fingerprint />
          Registrar Dispositivo Biométrico
        </DialogTitle>
        
        <DialogContent>
          <DialogContentText sx={{ mb: 2 }}>
            Dale un nombre a este dispositivo para identificarlo fácilmente. 
            Luego usarás tu huella digital, Face ID o PIN para completar el registro.
          </DialogContentText>
          
          <TextField
            autoFocus
            fullWidth
            label="Nombre del dispositivo"
            placeholder="Ej: Mi iPhone, Laptop del trabajo..."
            value={deviceName}
            onChange={(e) => setDeviceName(e.target.value)}
            variant="outlined"
            sx={{ mt: 1 }}
            disabled={registering}
          />
        </DialogContent>
        
        <DialogActions sx={{ px: 3, pb: 2 }}>
          <Button 
            onClick={() => setShowAddDialog(false)}
            disabled={registering}
          >
            Cancelar
          </Button>
          <Button
            onClick={handleAddDevice}
            variant="contained"
            disabled={registering || !deviceName.trim()}
            startIcon={registering ? <CircularProgress size={16} /> : <Fingerprint />}
            sx={{ borderRadius: 2 }}
          >
            {registering ? 'Registrando...' : 'Registrar'}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default BiometricDeviceManager;