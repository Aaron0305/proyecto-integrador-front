import React, { useState, useEffect, useContext } from 'react';
import { AuthContext } from '../../contexts/AuthContext';
import TeacherAssignments from './TeacherAssignments';
import {
  Box,
  Card,
  CardContent,
  Avatar,
  Typography,
  Grid,
  Container,
  Chip,
  Paper,
  Alert,
  Fade,
  LinearProgress,
  useTheme,
  useMediaQuery,
  IconButton,
  Divider,
  Badge,
  Skeleton,
  Grow,
  Slide
} from '@mui/material';
import {
  School,
  Email,
  Person,
  Assignment,
  Close,
  FiberManualRecord,
  Dashboard,
  AccountCircle
} from '@mui/icons-material';
import { styled, keyframes } from '@mui/material/styles';

// Animaciones avanzadas
const gradientShift = keyframes`
  0% { background-position: 0% 50%; }
  50% { background-position: 100% 50%; }
  100% { background-position: 0% 50%; }
`;

const floatingAnimation = keyframes`
  0%, 100% { transform: translateY(0px); }
  50% { transform: translateY(-10px); }
`;

// Removed unused animations to clean up the code

// Componente principal responsive con margen superior agregado
const ResponsiveContainer = styled(Container)(({ theme }) => ({
  padding: theme.spacing(2),
  maxWidth: 'none !important',
  width: '100%',
  // AGREGADO: Margen superior para separar del navbar
  marginTop: theme.spacing(3),
  
  [theme.breakpoints.up('sm')]: {
    padding: theme.spacing(3),
    maxWidth: '600px !important',
    marginTop: theme.spacing(4), // Más espacio en tablets
  },
  
  [theme.breakpoints.up('md')]: {
    padding: theme.spacing(4),
    maxWidth: '960px !important',
    marginTop: theme.spacing(5), // Más espacio en desktop
  },
  
  [theme.breakpoints.up('lg')]: {
    padding: theme.spacing(4),
    maxWidth: '1200px !important',
    marginTop: theme.spacing(6), // Máximo espacio en pantallas grandes
  },
  
  [theme.breakpoints.up('xl')]: {
    padding: theme.spacing(5),
    maxWidth: '1400px !important',
    marginTop: theme.spacing(7), // Espacio extra en pantallas muy grandes
  },
}));

// Card principal con diseño adaptativo
const MainProfileCard = styled(Card)(({ theme }) => ({
  background: 'linear-gradient(145deg, rgba(255,255,255,0.95) 0%, rgba(255,255,255,0.9) 100%)',
  backdropFilter: 'blur(25px)',
  borderRadius: '20px',
  border: '1px solid rgba(255,255,255,0.3)',
  boxShadow: '0 20px 40px rgba(0,0,0,0.1)',
  position: 'relative',
  overflow: 'hidden',
  transition: 'all 0.4s cubic-bezier(0.4, 0, 0.2, 1)',
  // REDUCIDO: Margen superior más pequeño para la tarjeta principal
  marginTop: theme.spacing(1),
  
  '&:hover': {
    transform: 'translateY(-8px)',
    boxShadow: '0 30px 60px rgba(0,0,0,0.15)',
  },
  
  [theme.breakpoints.down('sm')]: {
    borderRadius: '16px',
    margin: `${theme.spacing(1)} ${theme.spacing(1)} ${theme.spacing(0.5)}`,
  },
  
  [theme.breakpoints.up('sm')]: {
    marginTop: theme.spacing(1.5),
  },
  
  [theme.breakpoints.up('md')]: {
    marginTop: theme.spacing(2),
  }
}));

// Barra de gradiente animada
const AnimatedGradientBar = styled(Box)(({ theme }) => ({
  position: 'absolute',
  top: 0,
  left: 0,
  right: 0,
  height: '4px',
  background: 'linear-gradient(90deg, #667eea, #764ba2, #f093fb, #f5576c, #4facfe, #00f2fe)',
  backgroundSize: '300% 100%',
  animation: `${gradientShift} 6s ease infinite`,
  
  [theme.breakpoints.up('md')]: {
    height: '6px',
  }
}));

// Avatar responsive con animaciones
const ResponsiveAvatar = styled(Avatar)(({ theme }) => ({
  width: 120,
  height: 120,
  border: '3px solid white',
  boxShadow: '0 15px 30px rgba(102, 126, 234, 0.3)',
  transition: 'all 0.4s cubic-bezier(0.4, 0, 0.2, 1)',
  animation: `${floatingAnimation} 6s ease-in-out infinite`,
  objectFit: 'cover',
  backgroundPosition: 'center',
  backgroundSize: 'cover',
  
  '&:hover': {
    transform: 'scale(1.1) rotate(5deg)',
    boxShadow: '0 25px 50px rgba(102, 126, 234, 0.4)',
  },
  
  [theme.breakpoints.up('sm')]: {
    width: 140,
    height: 140,
    border: '4px solid white',
  },
  
  [theme.breakpoints.up('md')]: {
    width: 160,
    height: 160,
    border: '5px solid white',
  },
  
  [theme.breakpoints.up('lg')]: {
    width: 180,
    height: 180,
  }
}));

// Eliminar el OnlineStatusIndicator ya que no lo usaremos

// Tarjetas de información adaptativas
const InfoCardAdaptive = styled(Paper)(({ theme }) => ({
  padding: theme.spacing(1.5),
  borderRadius: '12px',
  background: 'rgba(248, 250, 252, 0.8)',
  border: '1px solid rgba(226, 232, 240, 0.6)',
  transition: 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)',
  position: 'relative',
  overflow: 'hidden',
  cursor: 'pointer',
  
  '&:hover': {
    transform: 'translateY(-4px) scale(1.02)',
    boxShadow: '0 12px 30px rgba(0, 0, 0, 0.15)',
    background: 'rgba(255, 255, 255, 0.95)',
    
    '& .info-shimmer': {
      transform: 'translateX(100%)',
    }
  },
  
  [theme.breakpoints.up('sm')]: {
    padding: theme.spacing(2),
    borderRadius: '16px',
  },
  
  [theme.breakpoints.up('md')]: {
    padding: theme.spacing(2.5),
  }
}));

// Efecto shimmer para las tarjetas
const ShimmerEffect = styled(Box)(() => ({
  position: 'absolute',
  top: 0,
  left: '-100%',
  width: '100%',
  height: '100%',
  background: 'linear-gradient(90deg, transparent, rgba(255,255,255,0.6), transparent)',
  transition: 'transform 0.6s ease',
  pointerEvents: 'none',
}));

// Contenedor del icono adaptativo
const IconContainer = styled(Box)(({ theme }) => ({
  width: 32,
  height: 32,
  borderRadius: '8px',
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  color: 'white',
  flexShrink: 0,
  transition: 'all 0.3s ease',
  
  [theme.breakpoints.up('sm')]: {
    width: 40,
    height: 40,
    borderRadius: '12px',
  },
  
  [theme.breakpoints.up('md')]: {
    width: 48,
    height: 48,
    borderRadius: '16px',
  }
}));

// Alert de bienvenida mejorado con margen superior
const WelcomeAlertStyled = styled(Alert)(({ theme }) => ({
  borderRadius: '16px',
  marginBottom: theme.spacing(2),
  // AGREGADO: Margen superior para separar del navbar
  marginTop: theme.spacing(1),
  boxShadow: '0 8px 32px rgba(0, 0, 0, 0.1)',
  background: 'linear-gradient(135deg, #667eea, #764ba2)',
  color: 'white',
  
  '& .MuiAlert-icon': {
    color: 'white',
  },
  
  [theme.breakpoints.up('sm')]: {
    marginBottom: theme.spacing(3),
    marginTop: theme.spacing(2),
    borderRadius: '20px',
  },
  
  [theme.breakpoints.up('md')]: {
    marginTop: theme.spacing(3),
  }
}));

// Componente de título responsive
const ResponsiveTitle = styled(Typography)(({ theme }) => ({
  fontSize: '1.5rem',
  fontWeight: 'bold',
  textAlign: 'center',
  background: 'linear-gradient(135deg, #667eea, #764ba2)',
  WebkitBackgroundClip: 'text',
  WebkitTextFillColor: 'transparent',
  backgroundClip: 'text',
  marginBottom: theme.spacing(1),
  
  [theme.breakpoints.up('sm')]: {
    fontSize: '1.75rem',
    textAlign: 'left',
  },
  
  [theme.breakpoints.up('md')]: {
    fontSize: '2rem',
  },
  
  [theme.breakpoints.up('lg')]: {
    fontSize: '2.5rem',
  }
}));

// Componente de loading mejorado
const LoadingContainer = styled(Box)(({ theme }) => ({
  display: 'flex',
  flexDirection: 'column',
  justifyContent: 'center',
  alignItems: 'center',
  minHeight: '100vh',
  textAlign: 'center',
  padding: theme.spacing(2),
  // AGREGADO: Margen superior para el loading
  marginTop: theme.spacing(3),
  
  [theme.breakpoints.up('sm')]: {
    padding: theme.spacing(3),
    marginTop: theme.spacing(4),
  },
  
  [theme.breakpoints.up('md')]: {
    marginTop: theme.spacing(5),
  }
}));

const ActiveSession = () => {
  const { currentUser, loading } = useContext(AuthContext);
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('sm'));
  const isTablet = useMediaQuery(theme.breakpoints.down('md'));
  const [error, setError] = useState('');
  const [openWelcome, setOpenWelcome] = useState(true);
  const [showContent, setShowContent] = useState(false);

  useEffect(() => {
    if (!loading && currentUser) {
      console.log('✅ Usuario completamente cargado:', currentUser);
      console.log('📁 Foto de perfil disponible:', currentUser.fotoPerfil);
      
      // Eliminamos la lógica de recarga automática que causa problemas
      setTimeout(() => setShowContent(true), 300);
      
    } else if (!loading && !currentUser) {
      console.log('❌ No hay usuario autenticado');
      setTimeout(() => setShowContent(true), 300);
    }
  }, [loading, currentUser]);

  useEffect(() => {
    const timer = setTimeout(() => {
      setOpenWelcome(false);
    }, 5000);

    return () => clearTimeout(timer);
  }, []);

  // Pantalla de loading optimizada
  if (loading && !currentUser) {
    return (
      <LoadingContainer>
        <Box sx={{ width: '100%', maxWidth: 400, mb: 3 }}>
          <LinearProgress 
            sx={{ 
              width: '100%', 
              height: 6,
              borderRadius: 3,
              backgroundColor: 'rgba(102, 126, 234, 0.1)',
              '& .MuiLinearProgress-bar': {
                background: 'linear-gradient(90deg, #667eea, #764ba2)',
                borderRadius: 3,
              }
            }} 
          />
        </Box>
        
        <Skeleton variant="circular" width={80} height={80} sx={{ mb: 2 }} />
        
        <Skeleton variant="text" width={250} height={32} sx={{ mb: 1 }} />
        <Skeleton variant="text" width={180} height={24} />
        
        <Box sx={{ mt: 3, display: 'flex', gap: 2, flexWrap: 'wrap', justifyContent: 'center' }}>
          <Skeleton variant="rectangular" width={120} height={60} sx={{ borderRadius: 2 }} />
          <Skeleton variant="rectangular" width={120} height={60} sx={{ borderRadius: 2 }} />
          <Skeleton variant="rectangular" width={120} height={60} sx={{ borderRadius: 2 }} />
        </Box>
      </LoadingContainer>
    );
  }

  // Configuración de información del usuario
  const userInfo = [
    {
      icon: <Person />,
      label: 'Número de Control',
      value: currentUser?.numeroControl || 'N/A',
      color: { primary: '#3b82f6', secondary: '#1d4ed8' }
    },
    {
      icon: <Email />,
      label: 'Correo',
      value: currentUser?.email || 'N/A',
      color: { primary: '#ef4444', secondary: '#dc2626' }
    },
    {
      icon: <School />,
      label: 'Carrera',
      value: currentUser?.carrera?.nombre || 'N/A',
      color: { primary: '#10b981', secondary: '#059669' }
    }
  ];

  return (
    <ResponsiveContainer>
      <Fade in={showContent} timeout={800}>
        <Box>
          {/* Mensaje de bienvenida */}
          {openWelcome && currentUser && (
            <Slide direction="down" in={openWelcome} timeout={600}>
              <WelcomeAlertStyled
                severity="success"
                action={
                  <IconButton
                    color="inherit"
                    size="small"
                    onClick={() => setOpenWelcome(false)}
                  >
                    <Close />
                  </IconButton>
                }
              >
                <Typography 
                  variant={isMobile ? "body2" : "body1"} 
                  fontWeight="medium"
                >
                  ¡Bienvenido(a) {`${currentUser.nombre} ${currentUser.apellidoPaterno}`}! 
                  {!isMobile && " Iniciaste sesión correctamente."}
                </Typography>
              </WelcomeAlertStyled>
            </Slide>
          )}

          {/* Mensaje de error */}
          {error && (
            <Slide direction="down" in={!!error} timeout={400}>
              <Alert 
                severity="error" 
                sx={{ 
                  mb: { xs: 2, sm: 3 }, 
                  borderRadius: { xs: '12px', sm: '16px' }
                }}
                action={
                  <IconButton
                    color="inherit"
                    size="small"
                    onClick={() => setError('')}
                  >
                    <Close />
                  </IconButton>
                }
              >
                {error}
              </Alert>
            </Slide>
          )}

          {/* Perfil del usuario */}
          <Grow in={showContent} timeout={1000}>
            <MainProfileCard sx={{ mb: { xs: 1, sm: 1.5, md: 2 } }}>
              <AnimatedGradientBar />
              <CardContent 
                sx={{ 
                  p: { xs: 1.5, sm: 2, md: 2.5 },
                  '&:last-child': { pb: { xs: 1.5, sm: 2, md: 2.5 } }
                }}
              >
                <Grid container spacing={{ xs: 1.5, sm: 2, md: 2.5 }} alignItems="center">
                  {/* Avatar */}
                  <Grid 
                    item 
                    xs={12} 
                    sm={12} 
                    md={4} 
                    display="flex" 
                    justifyContent="center"
                    alignItems="center"
                  >
                    <Box>
                      <ResponsiveAvatar
                        src={currentUser?.fotoPerfil && currentUser.fotoPerfil !== ''
                          ? `http://localhost:3001/uploads/perfiles/${currentUser.fotoPerfil}?t=${Date.now()}`
                          : 'http://localhost:3001/uploads/perfiles/2138822222222_1749571359362.png'
                        }
                        alt={`Foto de perfil de ${currentUser?.nombre || 'Usuario'}`}
                        sx={{ 
                          background: 'linear-gradient(135deg, #667eea, #764ba2)',
                          fontSize: { xs: '1.5rem', sm: '1.75rem', md: '2rem' },
                          display: 'flex',
                          justifyContent: 'center',
                          alignItems: 'center'
                        }}
                      >
                        {currentUser?.nombre?.charAt(0) || 'U'}
                      </ResponsiveAvatar>
                    </Box>
                  </Grid>

                  {/* Información del usuario */}
                  <Grid item xs={12} sm={12} md={8}>
                    <Box textAlign={{ xs: 'center', md: 'left' }}>
                      <ResponsiveTitle>
                        {`${currentUser?.nombre || ''} ${currentUser?.apellidoPaterno || ''} ${currentUser?.apellidoMaterno || ''}`}
                      </ResponsiveTitle>
                      
                      <Box 
                        display="flex" 
                        justifyContent={{ xs: 'center', md: 'flex-start' }} 
                        mb={{ xs: 1, sm: 1.5 }}
                      >
                        <Badge 
                        >
                          <Chip
                            icon={<AccountCircle />}
                            label="Docente"
                            color="primary"
                            size={isMobile ? "small" : "medium"}
                            sx={{ 
                              fontSize: { xs: '0.75rem', sm: '0.875rem' },
                              fontWeight: 'medium',
                              px: { xs: 1, sm: 2 }
                            }}
                          />
                        </Badge>
                      </Box>

                      <Grid container spacing={{ xs: 1, sm: 1.5 }}>
                        {userInfo.map((info, index) => (
                          <Grid item xs={12} sm={6} key={index}>
                            <Grow in={showContent} timeout={1200 + (index * 200)}>
                              <InfoCardAdaptive elevation={0}>
                                <ShimmerEffect className="info-shimmer" />
                                <Box display="flex" alignItems="center" gap={{ xs: 1, sm: 2 }}>
                                  <IconContainer
                                    sx={{
                                      background: `linear-gradient(135deg, ${info.color.primary}, ${info.color.secondary})`,
                                    }}
                                  >
                                    {info.icon}
                                  </IconContainer>
                                  <Box flex={1} minWidth={0}>
                                    <Typography 
                                      variant="caption" 
                                      color="text.secondary"
                                      sx={{ 
                                        textTransform: 'uppercase',
                                        fontWeight: 'bold',
                                        letterSpacing: '0.5px',
                                        fontSize: { xs: '0.6rem', sm: '0.75rem' }
                                      }}
                                    >
                                      {info.label}
                                    </Typography>
                                    <Typography 
                                      variant={isMobile ? "body2" : "body1"}
                                      color="text.primary"
                                      fontWeight="medium"
                                      sx={{ 
                                        wordBreak: 'break-word',
                                        mt: 0.5,
                                        fontSize: { xs: '0.875rem', sm: '1rem' }
                                      }}
                                    >
                                      {info.value}
                                    </Typography>
                                  </Box>
                                </Box>
                              </InfoCardAdaptive>
                            </Grow>
                          </Grid>
                        ))}
                      </Grid>
                    </Box>
                  </Grid>
                </Grid>
              </CardContent>
            </MainProfileCard>
          </Grow>

          {/* Sección de asignaciones */}
          <Grow in={showContent} timeout={1400}>
            <Box>
              <Typography 
                variant={isMobile ? "h5" : isTablet ? "h4" : "h3"}
                fontWeight="bold" 
                sx={{ 
                  mb: { xs: 2, sm: 3 },
                  display: 'flex',
                  alignItems: 'center',
                  gap: 1,
                  fontSize: { xs: '1.25rem', sm: '1.5rem', md: '1.75rem', lg: '2rem' }
                }}
              >
                <Dashboard sx={{ fontSize: 'inherit' }} />
                Mis Asignaciones
              </Typography>
              
              <Divider sx={{ mb: { xs: 2, sm: 3 } }} />
              
              <Paper 
                elevation={0} 
                sx={{ 
                  borderRadius: { xs: '12px', sm: '16px' },
                  overflow: 'hidden',
                  border: '1px solid rgba(0, 0, 0, 0.05)',
                  boxShadow: '0 4px 20px rgba(0, 0, 0, 0.08)'
                }}
              >
                <TeacherAssignments />
              </Paper>
            </Box>
          </Grow>
        </Box>
      </Fade>
    </ResponsiveContainer>
  );
};

export default ActiveSession;