import React, { useContext, useState, useEffect } from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import {
  AppBar,
  Toolbar,
  Typography,
  Button,
  Box,
  IconButton,
  Menu,
  MenuItem,
  Container,
  Fade,
  Divider,
  Badge
} from '@mui/material';
import MenuIcon from '@mui/icons-material/Menu';
import AdminPanelSettingsIcon from '@mui/icons-material/AdminPanelSettings';
import NotificationsIcon from '@mui/icons-material/Notifications';
import PersonIcon from '@mui/icons-material/Person';
import { AuthContext } from '../../contexts/AuthContext';
import AdminAccessDialog from '../Admin/AdminAccessDialog';
import { io } from 'socket.io-client';
import useSound from 'use-sound';
import notificationSound from '../../assets/notification.mp3';
import { API_ENV } from '../../config/api';

import { styled } from '@mui/material/styles';

// Importamos la imagen directamente para asegurarnos que se cargue correctamente
import tesjoLogo from '../image/tesjo.png';

// Estilo personalizado para el AppBar con transición - paleta institucional mejorada
const TransparentAppBar = styled(AppBar)(() => ({
  background: `radial-gradient(circle at center,
    #174baa  0%,
    #1d71c8  25%,
    #1d5a8e  50%,
    #174baa  75%,
    #041c6c 100%)`,
  boxShadow: '0 4px 20px rgba(0, 0, 0, 0.25)',
  transition: 'all 0.5s ease',
  borderBottom: '1px solid rgba(255, 255, 255, 0.15)',
}));

// Botón personalizado con efecto hover - mejorado para mayor visibilidad
const NavButton = styled(Button)(() => ({
  color: '#ffffff',
  fontWeight: 500,
  fontSize: '1rem',
  '&::after': {
    content: '""',
    position: 'absolute',
    width: '0%',
    height: '2px',
    bottom: '5px',
    left: '50%',
    backgroundColor: '#00f5ef',
    transform: 'translateX(-50%)',
    transition: 'width 0.3s ease',
  },
  '&:hover::after': {
    width: '80%',
  },
  '&:hover': {
    backgroundColor: 'rgba(0, 245, 239, 0.1)',
  }
}));

// Botón especial para administrador
const AdminButton = styled(Button)(() => ({
  color: '#ffffff',
  fontWeight: 600,
  fontSize: '0.95rem',
  backgroundColor: 'rgba(255, 215, 0, 0.15)',
  border: '1px solid rgba(255, 215, 0, 0.4)',
  borderRadius: '6px',
  transition: 'all 0.3s ease',
  '&:hover': {
    backgroundColor: 'rgba(255, 215, 0, 0.25)',
    transform: 'translateY(-1px)',
    boxShadow: '0 4px 12px rgba(255, 215, 0, 0.3)',
  }
}));

export default function Navbar() {
  const { currentUser, logout } = useContext(AuthContext);
  const navigate = useNavigate();
  const location = useLocation();
  const [anchorEl, setAnchorEl] = useState(null);
  const [adminMenuAnchor, setAdminMenuAnchor] = useState(null);
  const [scrollTrigger, setScrollTrigger] = useState(false);
  const [adminDialogOpen, setAdminDialogOpen] = useState(false);
  
  // Agregando estados para notificaciones
  const [notificationAnchorEl, setNotificationAnchorEl] = useState(null);
  const [notifications, setNotifications] = useState([]);
  const [unreadCount, setUnreadCount] = useState(0);
  const [playNotification] = useSound(notificationSound);
  
  // Efecto para detectar el scroll y cambiar el estado del navbar
  useEffect(() => {
    const handleScroll = () => {
      if (window.scrollY > 50) {
        setScrollTrigger(true);
      } else {
        setScrollTrigger(false);
      }
    };
    
    window.addEventListener('scroll', handleScroll);
    return () => {
      window.removeEventListener('scroll', handleScroll);
    };
  }, []);

  // Efecto para las notificaciones
  useEffect(() => {
    if (!currentUser) return;

    const socket = io(API_ENV.SOCKET_URL);
    socket.emit('authenticate', currentUser._id);

    socket.on('notification', (notification) => {
      setNotifications(prev => [notification, ...prev]);
      setUnreadCount(prev => prev + 1);
      playNotification();
    });

    return () => socket.disconnect();
  }, [currentUser, playNotification]);
  
  const handleMenu = (event) => {
    setAnchorEl(event.currentTarget);
  };
  
  const handleClose = () => {
    setAnchorEl(null);
  };

  const handleAdminMenu = (event) => {
    setAdminMenuAnchor(event.currentTarget);
  };

  const handleAdminMenuClose = () => {
    setAdminMenuAnchor(null);
  };

  // Funciones para manejar el diálogo de administrador
  const handleAdminDialogOpen = () => {
    setAdminDialogOpen(true);
    handleAdminMenuClose(); // Cerrar el menú si está abierto
  };

  const handleAdminDialogClose = () => {
    setAdminDialogOpen(false);
  };

  const handleAdminSuccess = () => {
    setAdminDialogOpen(false);
    navigate('/admin-access');
  };
  
  const handleLogout = async () => {
    try {
      await logout();
      handleClose();
      navigate('/login');
    } catch (error) {
      console.error(error);
    }
  };
  
  // Manejadores para notificaciones
  const handleNotificationMenu = (event) => {
    setNotificationAnchorEl(event.currentTarget);
    setUnreadCount(0);
  };

  const handleNotificationClose = () => {
    setNotificationAnchorEl(null);
  };

  const handleNotificationClick = (notification) => {
    if (notification.type === 'NEW_ASSIGNMENT') {
      navigate(`/dashboard/assignments/${notification.data.assignmentId}`);
    }
    handleNotificationClose();
  };
  
  // Función para verificar si una ruta está activa
  const isActive = (path) => {
    return location.pathname === path;
  };

  // Función para verificar si estamos en una ruta de admin
  const isAdminRoute = () => {
    return location.pathname.includes('/admin');
  };
  
  return (
    <TransparentAppBar position="fixed">
      <Container maxWidth="xl">
        <Toolbar disableGutters>
          <Fade in={true} timeout={800}>
            <Box sx={{ display: 'flex', alignItems: 'center', mr: 2 }}>
              {/* Logo con estilo institucional */}
              <Box sx={{ 
                display: 'flex', 
                alignItems: 'center',
                position: 'relative',
                '&::after': {
                  content: '""',
                  position: 'absolute',
                  width: '120%',
                  height: '110%',
                  top: '-5%',
                  left: '-10%',
                  borderRadius: '50%',
                  backgroundColor: 'rgba(255, 255, 255, 0.05)',
                  zIndex: -1
                }
              }}>
                <img 
                  src={tesjoLogo}
                  alt="Logo TESJo" 
                  style={{ 
                    height: '70px', 
                    transition: 'all 0.4s ease',
                    transform: scrollTrigger ? 'scale(0.9)' : 'scale(1)',
                    filter: 'drop-shadow(0 4px 6px rgba(0, 0, 0, 0.2))'
                  }} 
                />
              </Box>
              
              <Box sx={{ 
                ml: 2, 
                borderLeft: '2px solid rgba(255, 215, 0, 0.6)', 
                pl: 2,
                display: { xs: 'none', sm: 'block' } 
              }}>
                <Typography 
                  variant="h6" 
                  component="div" 
                  sx={{ 
                    fontWeight: 600,
                    fontSize: { xs: '0.9rem', sm: '1rem', md: '1.1rem' },
                    color: '#ffffff',
                    textShadow: '0px 1px 3px rgba(0,0,0,0.3)',
                    letterSpacing: '0.5px'
                  }}
                >
                  Sistema de Seguimiento de Docentes
                </Typography>
                <Typography 
                  variant="subtitle2" 
                  sx={{ 
                    fontSize: { xs: '0.7rem', sm: '0.8rem' },
                    color: 'rgba(255, 255, 255, 0.85)',
                    fontWeight: 400,
                    mt: 0.2
                  }}
                >
                  Tecnológico de Estudios Superiores de Jocotitlán
                </Typography>
              </Box>
            </Box>
          </Fade>
          
          <Box sx={{ flexGrow: 1 }} />
          
          {/* Mostrar botones cuando el usuario NO está autenticado */}
          {!currentUser ? (
            <Box sx={{ display: 'flex', gap: 1 }}>
              <Fade in={true} timeout={1000}>
                <NavButton 
                  onClick={() => navigate('/login')}
                  sx={{ 
                    backgroundColor: isActive('/login') ? 'rgba(255, 255, 255, 0.15)' : 'transparent',
                    '&::after': isActive('/login') ? { width: '90%', backgroundColor: '#FFD700' } : {},
                  }}
                >
                  Iniciar Sesión
                </NavButton>
              </Fade>
              
              <Fade in={true} timeout={1200}>
                <NavButton 
                  onClick={() => navigate('/register')}
                  sx={{ 
                    backgroundColor: isActive('/register') ? 'rgba(255, 255, 255, 0.15)' : 'transparent',
                    '&::after': isActive('/register') ? { width: '90%', backgroundColor: '#FFD700' } : {},
                  }}
                >
                  Registro
                </NavButton>
              </Fade>
            </Box>
          ) : (
            /* Mostrar navegación cuando el usuario SÍ está autenticado */
            <>
              <Box sx={{ display: { xs: 'none', md: 'flex' }, gap: 1 }}>
                <Fade in={true} timeout={1000}>
                  <NavButton 
                    sx={{ 
                      backgroundColor: isActive('/') ? 'rgba(255, 255, 255, 0.15)' : 'transparent',
                      '&::after': isActive('/') ? { width: '90%', backgroundColor: '#FFD700' } : {},
                    }}
                    onClick={() => navigate('/')}
                  >
                    Inicio
                  </NavButton>
                </Fade>

                {/* Botón de notificaciones */}
                <Fade in={true} timeout={1100}>
                  <IconButton
                    size="large"
                    onClick={handleNotificationMenu}
                    sx={{ 
                      color: '#ffffff',
                      backgroundColor: 'rgba(255, 255, 255, 0.1)',
                      border: '1px solid rgba(255, 255, 255, 0.2)',
                      '&:hover': {
                        backgroundColor: 'rgba(255, 255, 255, 0.2)',
                      }
                    }}
                  >
                    <Badge badgeContent={unreadCount} color="error">
                      <NotificationsIcon />
                    </Badge>
                  </IconButton>
                </Fade>

                {/* Menú de notificaciones */}
                <Menu
                  anchorEl={notificationAnchorEl}
                  open={Boolean(notificationAnchorEl)}
                  onClose={handleNotificationClose}
                  PaperProps={{
                    sx: {
                      bgcolor: 'rgba(0, 51, 102, 0.95)',
                      backgroundImage: 'linear-gradient(135deg, rgba(0, 51, 102, 0.95) 0%, rgba(0, 76, 153, 0.95) 100%)',
                      color: '#ffffff',
                      boxShadow: '0 8px 32px rgba(0,0,0,0.3)',
                      mt: 1,
                      border: '1px solid rgba(255, 215, 0, 0.3)',
                      borderRadius: '8px',
                      backdropFilter: 'blur(8px)',
                      maxHeight: 300,
                      width: 320,
                    }
                  }}
                >
                  {notifications.length === 0 ? (
                    <MenuItem disabled sx={{ color: 'rgba(255, 255, 255, 0.7)' }}>
                      No hay notificaciones
                    </MenuItem>
                  ) : (
                    notifications.map((notification, index) => (
                      <MenuItem
                        key={index}
                        onClick={() => handleNotificationClick(notification)}
                        sx={{
                          whiteSpace: 'normal',
                          display: 'block',
                          py: 1,
                          '&:hover': { bgcolor: 'rgba(255, 215, 0, 0.1)' },
                        }}
                      >
                        <Typography variant="subtitle2" fontWeight="bold" sx={{ color: '#FFD700' }}>
                          {notification.title}
                        </Typography>
                        <Typography variant="body2">
                          {notification.message}
                        </Typography>
                        <Typography variant="caption" sx={{ color: 'rgba(255, 255, 255, 0.7)' }}>
                          {new Date(notification.timestamp).toLocaleString()}
                        </Typography>
                      </MenuItem>
                    ))
                  )}
                </Menu>

                <Fade in={true} timeout={1200}>
                  <AdminButton
                    onClick={handleAdminMenu}
                    startIcon={<AdminPanelSettingsIcon />}
                  >
                    Administración
                  </AdminButton>
                </Fade>

                <Fade in={true} timeout={1300}>
                  <Button 
                    component={Link}
                    to="/profile"
                    startIcon={<PersonIcon />}
                    sx={{
                      color: '#ffffff',
                      fontWeight: 500,
                      mr: 1,
                      transition: 'all 0.3s ease',
                      '&:hover': {
                        backgroundColor: 'rgba(255, 255, 255, 0.15)',
                        transform: 'translateY(-2px)',
                      }
                    }}
                  >
                    Perfil
                  </Button>
                </Fade>

                <Fade in={true} timeout={1400}>
                  <Button 
                    onClick={handleLogout}
                    variant="contained"
                    sx={{ 
                      backgroundColor: 'rgba(255, 255, 255, 0.15)',
                      backdropFilter: 'blur(10px)',
                      color: '#ffffff',
                      fontWeight: 500,
                      border: '1px solid rgba(255, 255, 255, 0.3)',
                      transition: 'all 0.3s ease',
                      boxShadow: '0 2px 5px rgba(0, 0, 0, 0.1)',
                      '&:hover': {
                        backgroundColor: 'rgba(255, 255, 255, 0.25)',
                        transform: 'translateY(-2px)',
                        boxShadow: '0 4px 8px rgba(0, 0, 0, 0.15)',
                      }
                    }}
                  >
                    Cerrar Sesión
                  </Button>
                </Fade>
              </Box>
              
              {/* Menú desplegable para administrador */}
              <Menu
                anchorEl={adminMenuAnchor}
                open={Boolean(adminMenuAnchor)}
                onClose={handleAdminMenuClose}
                TransitionComponent={Fade}
                PaperProps={{
                  sx: {
                    bgcolor: 'rgba(0, 51, 102, 0.95)',
                    backgroundImage: 'linear-gradient(135deg, rgba(0, 51, 102, 0.95) 0%, rgba(0, 76, 153, 0.95) 100%)',
                    color: '#ffffff',
                    boxShadow: '0 8px 32px rgba(0,0,0,0.3)',
                    mt: 1,
                    border: '1px solid rgba(255, 215, 0, 0.3)',
                    borderRadius: '8px',
                    backdropFilter: 'blur(8px)',
                    minWidth: '180px',
                  }
                }}
              >
                <MenuItem 
                  onClick={handleAdminDialogOpen}
                  sx={{
                    my: 0.5,
                    mx: 1,
                    borderRadius: '4px',
                    '&:hover': { bgcolor: 'rgba(255, 215, 0, 0.1)' },
                    fontWeight: 500,
                  }}
                >
                  Acceso Administrativo
                </MenuItem>
              </Menu>
              
              {/* Menú móvil para usuarios autenticados */}
              <Box sx={{ display: { xs: 'flex', md: 'none' } }}>
                <IconButton
                  size="large"
                  edge="end"
                  aria-label="menu"
                  onClick={handleMenu}
                  sx={{ 
                    color: '#ffffff',
                    backgroundColor: 'rgba(255, 255, 255, 0.1)',
                    border: '1px solid rgba(255, 255, 255, 0.2)',
                    '&:hover': {
                      backgroundColor: 'rgba(255, 255, 255, 0.2)',
                    }
                  }}
                >
                  <MenuIcon />
                </IconButton>
                <Menu
                  id="menu-appbar"
                  anchorEl={anchorEl}
                  anchorOrigin={{
                    vertical: 'top',
                    horizontal: 'right',
                  }}
                  keepMounted
                  transformOrigin={{
                    vertical: 'top',
                    horizontal: 'right',
                  }}
                  open={Boolean(anchorEl)}
                  onClose={handleClose}
                  TransitionComponent={Fade}
                  PaperProps={{
                    sx: {
                      bgcolor: 'rgba(0, 51, 102, 0.95)',
                      backgroundImage: 'linear-gradient(135deg, rgba(0, 51, 102, 0.95) 0%, rgba(0, 76, 153, 0.95) 100%)',
                      color: '#ffffff',
                      boxShadow: '0 8px 32px rgba(0,0,0,0.3)',
                      mt: 1,
                      border: '1px solid rgba(255, 255, 255, 0.2)',
                      borderRadius: '8px',
                      backdropFilter: 'blur(8px)',
                      minWidth: '200px',
                    }
                  }}
                >
                  <MenuItem 
                    onClick={() => { navigate('/'); handleClose(); }}
                    sx={{
                      my: 0.5,
                      mx: 1,
                      borderRadius: '4px',
                      backgroundColor: isActive('/') ? 'rgba(255, 255, 255, 0.15)' : 'transparent',
                      '&:hover': { bgcolor: 'rgba(255, 255, 255, 0.1)' },
                      borderLeft: isActive('/') ? '4px solid #FFD700' : 'none',
                      pl: isActive('/') ? 2 : 3,
                      fontWeight: isActive('/') ? 600 : 400,
                    }}
                  >
                    Inicio
                  </MenuItem>

                  <MenuItem 
                    onClick={handleAdminDialogOpen}
                    sx={{
                      my: 0.5,
                      mx: 1,
                      borderRadius: '4px',
                      backgroundColor: isAdminRoute() ? 'rgba(255, 255, 255, 0.15)' : 'transparent',
                      '&:hover': { bgcolor: 'rgba(255, 255, 255, 0.1)' },
                      borderLeft: isAdminRoute() ? '4px solid #FFD700' : 'none',
                      pl: isAdminRoute() ? 2 : 3,
                      fontWeight: isAdminRoute() ? 600 : 400,
                    }}
                  >
                    Administración
                  </MenuItem>
                  
                  <MenuItem 
                    component={Link}
                    to="/profile"
                    sx={{
                      my: 0.5,
                      mx: 1,
                      borderRadius: '4px',
                      backgroundColor: location.pathname === '/profile' ? 'rgba(255, 255, 255, 0.15)' : 'transparent',
                      '&:hover': { bgcolor: 'rgba(255, 255, 255, 0.1)' },
                      borderLeft: location.pathname === '/profile' ? '4px solid #FFD700' : 'none',
                      pl: location.pathname === '/profile' ? 2 : 3,
                      fontWeight: location.pathname === '/profile' ? 600 : 400,
                    }}
                  >
                    Perfil
                  </MenuItem>

                  <Divider sx={{ bgcolor: 'rgba(255,255,255,0.2)', my: 1 }} />
                  
                  <MenuItem 
                    onClick={handleLogout}
                    sx={{
                      my: 0.5,
                      mx: 1,
                      borderRadius: '4px',
                      backgroundColor: 'rgba(255, 255, 255, 0.1)',
                      '&:hover': { bgcolor: 'rgba(255, 255, 255, 0.2)' },
                      fontWeight: 'bold',
                      color: '#ffffff',
                      textAlign: 'center',
                      py: 1,
                    }}
                  >
                    Cerrar Sesión
                  </MenuItem>
                </Menu>
              </Box>
            </>
          )}
        </Toolbar>
      </Container>

      {/* Diálogo de acceso administrativo */}
      <AdminAccessDialog 
        open={adminDialogOpen}
        onClose={handleAdminDialogClose}
        onSuccess={handleAdminSuccess}
      />
    </TransparentAppBar>
  );
}