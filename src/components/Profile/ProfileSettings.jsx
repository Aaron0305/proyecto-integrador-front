import React, { useState, useContext } from 'react';
import { useNavigate } from 'react-router-dom';
import { AuthContext } from '../../contexts/AuthContext';
import BiometricSettings from '../Auth/BiometricSettings';
import {
  Container,
  Paper,
  Typography,
  Box,
  Tabs,
  Tab,
  Grid,
  Card,
  CardContent,
  Avatar,
  Button,
  Divider,
  Alert,
  useTheme
} from '@mui/material';
import {
  Person,
  Security,
  Settings,
  ArrowBack,
  Fingerprint
} from '@mui/icons-material';

const TabPanel = ({ children, value, index, ...other }) => (
  <div
    role="tabpanel"
    hidden={value !== index}
    id={`profile-tabpanel-${index}`}
    aria-labelledby={`profile-tab-${index}`}
    {...other}
  >
    {value === index && <Box sx={{ pt: 3 }}>{children}</Box>}
  </div>
);

const ProfileSettings = () => {
  const [activeTab, setActiveTab] = useState(0);
  const { currentUser, logout } = useContext(AuthContext);
  const navigate = useNavigate();
  const theme = useTheme();

  const handleTabChange = (event, newValue) => {
    setActiveTab(newValue);
  };

  const handleBack = () => {
    navigate(-1);
  };

  if (!currentUser) {
    return (
      <Container maxWidth="sm" sx={{ mt: 4 }}>
        <Alert severity="error">
          Debes estar logueado para acceder a la configuración
        </Alert>
      </Container>
    );
  }

  return (
    <Container maxWidth="lg" sx={{ mt: 4, mb: 4 }}>
      {/* Header */}
      <Box sx={{ mb: 3, display: 'flex', alignItems: 'center', gap: 2 }}>
        <Button
          variant="outlined"
          startIcon={<ArrowBack />}
          onClick={handleBack}
          sx={{ borderRadius: 2 }}
        >
          Volver
        </Button>
        <Typography variant="h4" component="h1" sx={{ flexGrow: 1 }}>
          Configuración de Perfil
        </Typography>
      </Box>

      <Grid container spacing={3}>
        {/* Sidebar con información del usuario */}
        <Grid size={{xs: 12, md: 4}}>
          <Paper sx={{ p: 3, borderRadius: 3, height: 'fit-content' }}>
            <Box sx={{ textAlign: 'center', mb: 3 }}>
              <Avatar
                src={currentUser?.fotoPerfil 
                  ? `http://localhost:3001/uploads/perfiles/${currentUser.fotoPerfil}?t=${Date.now()}`
                  : undefined
                }
                sx={{
                  width: 100,
                  height: 100,
                  mx: 'auto',
                  mb: 2,
                  background: 'linear-gradient(135deg, #667eea, #764ba2)',
                  fontSize: '2rem'
                }}
              >
                {currentUser?.nombre?.charAt(0) || 'U'}
              </Avatar>
              
              <Typography variant="h6" gutterBottom>
                {currentUser?.nombre} {currentUser?.apellidoPaterno}
              </Typography>
              
              <Typography variant="body2" color="text.secondary" gutterBottom>
                {currentUser?.email}
              </Typography>
              
              <Typography variant="caption" color="text.secondary">
                {currentUser?.role === 'admin' ? 'Administrador' : 'Docente'}
              </Typography>
            </Box>

            <Divider sx={{ my: 2 }} />

            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
              <Typography variant="body2" color="text.secondary">
                <strong>Número de Control:</strong> {currentUser?.numeroControl}
              </Typography>
              
              <Typography variant="body2" color="text.secondary">
                <strong>Carrera:</strong> {currentUser?.carrera?.nombre || 'No especificada'}
              </Typography>
              
              <Typography variant="body2" color="text.secondary">
                <strong>Semestre:</strong> {currentUser?.semestre || 'No especificado'}
              </Typography>
            </Box>
          </Paper>
        </Grid>

        {/* Panel principal */}
        <Grid size={{xs: 12, md: 8}}>
          <Paper sx={{ borderRadius: 3, overflow: 'hidden' }}>
            {/* Tabs */}
            <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
              <Tabs
                value={activeTab}
                onChange={handleTabChange}
                aria-label="configuración de perfil"
                variant="scrollable"
                scrollButtons="auto"
              >
                <Tab
                  icon={<Person />}
                  label="Información Personal"
                  id="profile-tab-0"
                  aria-controls="profile-tabpanel-0"
                />
                <Tab
                  icon={<Fingerprint />}
                  label="Autenticación Biométrica"
                  id="profile-tab-1"
                  aria-controls="profile-tabpanel-1"
                />
                <Tab
                  icon={<Settings />}
                  label="Configuración"
                  id="profile-tab-2"
                  aria-controls="profile-tabpanel-2"
                />
              </Tabs>
            </Box>

            {/* Panel de Información Personal */}
            <TabPanel value={activeTab} index={0}>
              <Box sx={{ p: 3 }}>
                <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <Person />
                  Información Personal
                </Typography>
                
                <Alert severity="info" sx={{ mb: 3, borderRadius: 2 }}>
                  La información personal se gestiona a través del administrador del sistema. 
                  Si necesitas hacer cambios, contacta al administrador.
                </Alert>

                <Grid container spacing={2}>
                  <Grid size={{xs: 12, sm: 6}}>
                    <Card variant="outlined">
                      <CardContent>
                        <Typography variant="subtitle2" color="text.secondary">
                          Nombre Completo
                        </Typography>
                        <Typography variant="body1">
                          {currentUser?.nombre} {currentUser?.apellidoPaterno} {currentUser?.apellidoMaterno}
                        </Typography>
                      </CardContent>
                    </Card>
                  </Grid>

                  <Grid size={{xs: 12, sm: 6}}>
                    <Card variant="outlined">
                      <CardContent>
                        <Typography variant="subtitle2" color="text.secondary">
                          Correo Electrónico
                        </Typography>
                        <Typography variant="body1">
                          {currentUser?.email}
                        </Typography>
                      </CardContent>
                    </Card>
                  </Grid>

                  <Grid size={{xs: 12, sm: 6}}>
                    <Card variant="outlined">
                      <CardContent>
                        <Typography variant="subtitle2" color="text.secondary">
                          Número de Control
                        </Typography>
                        <Typography variant="body1">
                          {currentUser?.numeroControl}
                        </Typography>
                      </CardContent>
                    </Card>
                  </Grid>

                  <Grid size={{xs: 12, sm: 6}}>
                    <Card variant="outlined">
                      <CardContent>
                        <Typography variant="subtitle2" color="text.secondary">
                          Rol en el Sistema
                        </Typography>
                        <Typography variant="body1">
                          {currentUser?.role === 'admin' ? 'Administrador' : 'Docente'}
                        </Typography>
                      </CardContent>
                    </Card>
                  </Grid>
                </Grid>
              </Box>
            </TabPanel>

            {/* Panel de Autenticación Biométrica */}
            <TabPanel value={activeTab} index={1}>
              <Box sx={{ p: 3 }}>
                <BiometricSettings />
              </Box>
            </TabPanel>

            {/* Panel de Configuración */}
            <TabPanel value={activeTab} index={2}>
              <Box sx={{ p: 3 }}>
                <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <Settings />
                  Configuración General
                </Typography>
                
                <Alert severity="warning" sx={{ mb: 3, borderRadius: 2 }}>
                  ⚠️ Esta acción cerrará tu sesión actual en todos los dispositivos.
                </Alert>

                <Card variant="outlined">
                  <CardContent>
                    <Typography variant="subtitle1" gutterBottom>
                      Cerrar Sesión
                    </Typography>
                    <Typography variant="body2" color="text.secondary" paragraph>
                      Cierra tu sesión actual y vuelve a la pantalla de inicio de sesión.
                    </Typography>
                    <Button
                      variant="contained"
                      color="error"
                      onClick={logout}
                      sx={{ borderRadius: 2 }}
                    >
                      Cerrar Sesión
                    </Button>
                  </CardContent>
                </Card>
              </Box>
            </TabPanel>
          </Paper>
        </Grid>
      </Grid>
    </Container>
  );
};

export default ProfileSettings;