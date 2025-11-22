import React, { useState, useContext, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { AuthContext } from '../../contexts/AuthContext';
import {
  TextField,
  Button,
  Typography,
  Container,
  Paper,
  Box,
  Alert,
  InputAdornment,
  IconButton,
  CircularProgress,
  ThemeProvider,
  Grow,
  Zoom,
  Fade,
  Divider,
  Chip
} from '@mui/material';
import {
  Visibility,
  VisibilityOff,
  Email,
  Lock,
  KeyboardArrowRight,
  Fingerprint
} from '@mui/icons-material';
import { theme } from '../../theme/palette';
import ForgotPasswordLink from './ForgotPasswordLink';
import { BiometricLoginDialog } from './BiometricLogin';

// Componente de campo de entrada animado
const AnimatedTextField = ({ label, type, value, onChange, icon, endAdornment, ...props }) => {
  return (
    <Grow in={true} style={{ transformOrigin: '0 0 0' }} timeout={700}>
      <TextField
        label={label}
        type={type}
        fullWidth
        variant="outlined"
        value={value}
        onChange={onChange}
        InputProps={{
          startAdornment: (
            <InputAdornment position="start">
              {icon}
            </InputAdornment>
          ),
          endAdornment: endAdornment,
          sx: {
            '&:hover': {
              '& .MuiOutlinedInput-notchedOutline': {
                borderColor: theme.palette.secondary.main,
              },
            },
            '&.Mui-focused': {
              '& .MuiOutlinedInput-notchedOutline': {
                borderColor: theme.palette.primary.main,
                borderWidth: 2,
              },
            },
            transition: 'all 0.3s ease-in-out',
          }
        }}
        sx={{
          '& label.Mui-focused': {
            color: theme.palette.primary.main,
          },
          '& .MuiOutlinedInput-root': {
            '&.Mui-focused fieldset': {
              borderColor: theme.palette.primary.main,
            },
          },
          mb: 2,
        }}
        {...props}
      />
    </Grow>
  );
};

export default function Login() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [showBiometricDialog, setShowBiometricDialog] = useState(false);
  const [biometricSupported, setBiometricSupported] = useState(false);
  const [userHasBiometric, setUserHasBiometric] = useState(false);
  const [biometricAttempted, setBiometricAttempted] = useState(false);

  // Obtenemos currentUser del contexto para verificar si ya hay una sesión activa
  const { login, currentUser, isBiometricSupported, userHasBiometricDevices } = useContext(AuthContext);
  const navigate = useNavigate();

  // Redirigir si ya hay una sesión activa
  useEffect(() => {
    if (currentUser) {
      navigate('/', { replace: true });
    }
  }, [currentUser, navigate]);

  // Verificar soporte biométrico y abrir diálogo automáticamente
  useEffect(() => {
    const checkAndShowBiometric = async () => {
      const supported = isBiometricSupported();
      setBiometricSupported(supported);

      // Si el navegador soporta biometría y aún no se ha intentado, mostrar el diálogo automáticamente
      if (supported && !biometricAttempted) {
        setBiometricAttempted(true);
        // Pequeño delay para que la UI se renderice primero
        setTimeout(() => {
          setShowBiometricDialog(true);
        }, 500);
      }
    };

    checkAndShowBiometric();
  }, [isBiometricSupported, biometricAttempted]);

  // Verificar si el usuario tiene dispositivos biométricos cuando ingresa email
  useEffect(() => {
    const checkUserBiometric = async () => {
      if (email && email.includes('@')) {
        try {
          const hasBiometric = await userHasBiometricDevices(email);
          setUserHasBiometric(hasBiometric);
        } catch (error) {
          setUserHasBiometric(false);
        }
      } else {
        setUserHasBiometric(false);
      }
    };

    const timeoutId = setTimeout(checkUserBiometric, 500); // Debounce
    return () => clearTimeout(timeoutId);
  }, [email, userHasBiometricDevices]);

  const handleShowPassword = () => {
    setShowPassword(!showPassword);
  };

  const handleBiometricLogin = () => {
    if (!email || !email.includes('@')) {
      setError('Por favor ingresa tu correo electrónico primero');
      return;
    }
    setShowBiometricDialog(true);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    setSuccess(false);

    // Validación básica
    if (!email || !password) {
      setError('Por favor ingresa tu correo y contraseña');
      setLoading(false);
      return;
    }

    try {
      // login debe lanzar error si falla, o devolver usuario/token si es correcto
      const result = await login(email, password);
      if (result) {
        setSuccess(true);
        setTimeout(() => {
          navigate('/', { replace: true });
        }, 1000);
      } else {
        setError('Usuario o contraseña incorrectos');
      }
    } catch (err) {
      // Mejor manejo del error
      let msg = 'Usuario o contraseña incorrectos';
      if (err && err.response && err.response.data && err.response.data.message) {
        msg = err.response.data.message;
      } else if (err && err.message) {
        msg = err.message;
      }
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  return (
    <ThemeProvider theme={theme}>
      <Container
        maxWidth="sm"
        sx={{
          mt: 12,
          mb: 8,
          minHeight: '80vh',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center'
        }}
      >
        <Zoom in={true} style={{ transitionDelay: '100ms' }}>
          <Paper
            elevation={6}
            sx={{
              borderRadius: 3,
              overflow: 'hidden',
              width: '100%',
              background: `linear-gradient(145deg, ${theme.palette.background.paper} 0%, ${theme.palette.background.paper} 80%, rgba(0, 251, 250, 0.1) 100%)`,
              position: 'relative',
              '&::before': {
                content: '""',
                position: 'absolute',
                top: 0,
                left: 0,
                width: '100%',
                height: '5px',
                background: `linear-gradient(90deg, ${theme.palette.primary.main} 0%, ${theme.palette.primary.light} 100%)`,
              }
            }}
          >
            <Box sx={{
              p: 4,
              bgcolor: theme.palette.primary.main,
              color: 'white',
              textAlign: 'center',
              position: 'relative',
              overflow: 'hidden',
              '&::after': {
                content: '""',
                position: 'absolute',
                bottom: '-15px',
                right: '-15px',
                width: '100px',
                height: '100px',
                borderRadius: '50%',
                background: `radial-gradient(circle, ${theme.palette.secondary.light} 0%, transparent 0%)`,
                opacity: 0.3,
              },
            }}>
              <Fade in={true} timeout={1000}>
                <Typography
                  variant="h4"
                  component="h1"
                  gutterBottom
                  sx={{
                    fontWeight: 600,
                    letterSpacing: '1px',
                    textShadow: '0px 2px 4px rgb(0, 0, 0)'
                  }}
                >
                  Bienvenido
                </Typography>
              </Fade>
              <Fade in={true} timeout={1500}>
                <Typography variant="body1" sx={{ opacity: 0.9 }}>
                  Inicia sesión para continuar
                </Typography>
              </Fade>
            </Box>

            <Box
              component="form"
              onSubmit={handleSubmit}
              sx={{
                p: 4,
                display: 'flex',
                flexDirection: 'column',
                gap: 2
              }}
            >
              {error && (
                <Grow in={!!error} timeout={500}>
                  <Alert
                    severity="error"
                    variant="filled"
                    sx={{
                      borderRadius: 2,
                      bgcolor: '#f44336',
                      mb: 2,
                      '& .MuiAlert-message': {
                        fontWeight: 500
                      }
                    }}
                  >
                    {error}
                  </Alert>
                </Grow>
              )}

              {success && (
                <Grow in={success} timeout={500}>
                  <Alert
                    severity="success"
                    variant="filled"
                    sx={{
                      borderRadius: 2,
                      bgcolor: theme.palette.secondary.main,
                      color: theme.palette.common.white,
                      mb: 2,
                      '& .MuiAlert-message': {
                        fontWeight: 500
                      }
                    }}
                  >
                    Iniciando sesión correctamente...
                  </Alert>
                </Grow>
              )}

              <AnimatedTextField
                label="Correo electrónico"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                icon={<Email sx={{ color: theme.palette.primary.main }} />}
              />

              <AnimatedTextField
                label="Contraseña"
                type={showPassword ? 'text' : 'password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                icon={<Lock sx={{ color: theme.palette.primary.main }} />}
                endAdornment={
                  <InputAdornment position="end">
                    <IconButton
                      aria-label="toggle password visibility"
                      onClick={handleShowPassword}
                      edge="end"
                      sx={{
                        color: showPassword ? theme.palette.secondary.main : 'inherit',
                        transition: 'color 0.3s ease'
                      }}
                    >
                      {showPassword ? <VisibilityOff /> : <Visibility />}
                    </IconButton>
                  </InputAdornment>
                }
              />

              <ForgotPasswordLink />

              <Zoom in={true} style={{ transitionDelay: '600ms' }}>
                <Button
                  type="submit"
                  fullWidth
                  variant="contained"
                  size="large"
                  disableElevation
                  disabled={loading || success}
                  endIcon={loading ? null : <KeyboardArrowRight />}
                  sx={{
                    py: 1.5,
                    fontSize: '1rem',
                    borderRadius: 2,
                    background: '#041c6c',
                    color: '#fff',
                    fontWeight: 500,
                    mt: 1,
                    transition: 'all 0.3s ease',
                    '&:hover': {
                      background: '#041c6c',
                      transform: 'translateY(-2px)',
                      boxShadow: '0 4px 8px rgba(0,0,0,0.1)'
                    },
                    '&:active': {
                      transform: 'translateY(0)',
                    }
                  }}
                >
                  {loading ? (
                    <CircularProgress size={24} sx={{ color: '#fff' }} />
                  ) : (
                    'Iniciar Sesión'
                  )}
                </Button>
              </Zoom>

              {/* Opción de login biométrico */}
              {biometricSupported && userHasBiometric && (
                <Fade in={true} style={{ transitionDelay: '800ms' }}>
                  <Box sx={{ mt: 2 }}>
                    <Divider sx={{ mb: 2 }}>
                      <Chip
                        label="O usa"
                        size="small"
                        sx={{
                          bgcolor: 'background.paper',
                          color: 'text.secondary',
                          border: 'none'
                        }}
                      />
                    </Divider>

                    <Button
                      fullWidth
                      variant="outlined"
                      size="large"
                      onClick={handleBiometricLogin}
                      disabled={loading || success || !email || !email.includes('@')}
                      startIcon={<Fingerprint />}
                      sx={{
                        py: 1.5,
                        borderRadius: 2,
                        borderColor: theme.palette.secondary.main,
                        color: theme.palette.secondary.main,
                        fontWeight: 500,
                        transition: 'all 0.3s ease',
                        '&:hover': {
                          borderColor: theme.palette.secondary.main,
                          backgroundColor: theme.palette.secondary.main,
                          color: 'white',
                          transform: 'translateY(-1px)',
                          boxShadow: '0 3px 6px rgba(0,0,0,0.1)'
                        },
                        '&:disabled': {
                          borderColor: theme.palette.action.disabled,
                          color: theme.palette.action.disabled
                        }
                      }}
                    >
                      Acceso Biométrico
                    </Button>
                  </Box>
                </Fade>
              )}

              {/* Mostrar aviso si el navegador soporta biométrico pero el usuario no lo ha configurado */}
              {biometricSupported && !userHasBiometric && email && email.includes('@') && (
                <Fade in={true} style={{ transitionDelay: '900ms' }}>
                  <Alert
                    severity="info"
                    variant="outlined"
                    sx={{
                      mt: 2,
                      borderRadius: 2,
                      fontSize: '0.875rem',
                      '& .MuiAlert-icon': {
                        fontSize: '1rem'
                      }
                    }}
                  >
                    💡 Después de iniciar sesión puedes configurar acceso biométrico en tu perfil
                  </Alert>
                </Fade>
              )}

              <Fade in={true} style={{ transitionDelay: '900ms' }}>
                <Box sx={{ textAlign: 'center', mt: 4 }}>
                  <Typography variant="body1">
                    ¿No tienes cuenta?{' '}
                    <Link to="/register" style={{ textDecoration: 'none' }}>
                      <Typography
                        component="span"
                        fontWeight="bold"
                        sx={{
                          color: '#041c6c',
                          position: 'relative',
                          '&:hover': {
                            '&::after': {
                              width: '100%',
                            }
                          },
                          '&::after': {
                            content: '""',
                            position: 'absolute',
                            bottom: '-2px',
                            left: 0,
                            width: '0%',
                            height: '2px',
                            backgroundColor: '#041c6c',
                            transition: 'width 0.3s ease'
                          }
                        }}
                      >
                        Regístrate
                      </Typography>
                    </Link>
                  </Typography>
                </Box>
              </Fade>
            </Box>
          </Paper>
        </Zoom>

        {/* Dialog de login biométrico */}
        <BiometricLoginDialog
          open={showBiometricDialog}
          onClose={() => setShowBiometricDialog(false)}
          email={email}
        />
      </Container>
    </ThemeProvider>
  );
}