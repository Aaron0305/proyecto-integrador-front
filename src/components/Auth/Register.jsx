import React, { useState, useContext, useEffect, useRef } from 'react';
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
  MenuItem,
  CircularProgress,
  ThemeProvider,
  Grow,
  Zoom,
  Fade,
  Stepper,
  Step,
  StepLabel,
  Avatar,
  Grid,
  FormControl,
  InputLabel,
  Select,
  FormHelperText
} from '@mui/material';
import {
  Visibility,
  VisibilityOff,
  Email,
  Lock,
  Badge,
  Person,
  School,
  MenuBook,
  KeyboardArrowRight,
  KeyboardArrowLeft,
  PhotoCamera,
  Save
} from '@mui/icons-material';
import { theme } from '../../theme/palette';
import API_CONFIG, { API_ENDPOINTS, buildApiUrl } from '../../config/api';

// Componente de campo de entrada animado
const AnimatedTextField = ({ label, type, value, onChange, icon, endAdornment, select, children, ...props }) => {
  return (
    <Grow in={true} style={{ transformOrigin: '0 0 0' }} timeout={700}>
      <TextField
        label={label}
        type={type}
        fullWidth
        variant="outlined"
        value={value}
        onChange={onChange}
        select={select}
        InputProps={{
          startAdornment: icon && (
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
      >
        {children}
      </TextField>
    </Grow>
  );
};

export default function Register() {
  const [activeStep, setActiveStep] = useState(0);
  const [foto, setFoto] = useState(null);
  const [fotoPreview, setFotoPreview] = useState(null);
  const fileInputRef = useRef(null);
  const [carreras, setCarreras] = useState([]);
  const [isLoadingCarreras, setIsLoadingCarreras] = useState(true);
  const [formData, setFormData] = useState({
    numeroControl: '',
    nombre: '',
    apellidoPaterno: '',
    apellidoMaterno: '',
    carrera: '',
    role: '',  // Quitamos el valor por defecto para que el usuario deba seleccionar
    email: '',
    password: '',
    confirmPassword: ''
  });
  
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const { register, checkEmailExists, checkNumeroControlExists } = useContext(AuthContext);
  const navigate = useNavigate();

  // Efecto para cargar carreras
  useEffect(() => {
    const fetchCarreras = async () => {
      setIsLoadingCarreras(true);
      try {
        const response = await fetch(buildApiUrl(API_ENDPOINTS.CARRERAS), {
          credentials: API_CONFIG.withCredentials ? 'include' : 'same-origin',
        });
        if (!response.ok) {
          throw new Error('Error al cargar carreras');
        }
        const data = await response.json();
        console.log('Carreras recibidas:', data);
        if (Array.isArray(data)) {
          setCarreras(data);
        } else {
          throw new Error('Formato de datos inválido');
        }
      } catch (error) {
        console.error('Error:', error);
        setError('Error al cargar las carreras');
      } finally {
        setIsLoadingCarreras(false);
      }
    };

    fetchCarreras();
  }, []);

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData({
      ...formData,
      [name]: value
    });
    setError('');
  };

  // Verificación de email al perder el foco
  const handleEmailBlur = async () => {
    if (formData.email.trim() !== '') {
      const emailRegex = /^[a-zA-Z0-9._%+-]+@tesjo\.edu\.mx$/;
      if (!emailRegex.test(formData.email)) {
        setError('Por favor, introduce un correo válido (ejemplo: usuario@tesjo.edu.mx)');
        return;
      }
      try {
        const emailExists = await checkEmailExists(formData.email);
        if (emailExists) {
          setError('Este correo electrónico ya está registrado');
        }
      } catch (err) {
        console.error('Error al verificar email:', err);
      }
    }
  };

  // Verificación de número de control al perder el foco
  const handleNumeroControlBlur = async () => {
    if (formData.numeroControl.trim() !== '') {
      const numeroControlRegex = /^[0-9A-Z]{10,15}$/; 
      if (!numeroControlRegex.test(formData.numeroControl)) {
        setError('El número de empleado debe tener entre 10-15 dígitos');
        return;
      }
      try {
        const numeroControlExists = await checkNumeroControlExists(formData.numeroControl);
        if (numeroControlExists) {
          setError('Este número de control ya está registrado');
        }
      } catch (err) {
        console.error('Error al verificar número de control:', err);
      }
    }
  };

  const handleShowPassword = (field) => {
    if (field === 'password') {
      setShowPassword(!showPassword);
    } else {
      setShowConfirmPassword(!showConfirmPassword);
    }
  };

  const handleNumeroControlChange = (e) => {
    const { value } = e.target;
    // Solo permitir números
    const numeroControl = value.replace(/[^0-9A-Z]/g, '');
    if (numeroControl.length <= 15) {
      setFormData({ 
        ...formData,
        numeroControl
      });
      setError('');
    }
  };

  const handleFotoChange = (event) => {
    const file = event.target.files[0];
    if (file) {
      if (file.size > 5000000) { // 5MB limit
        setError('La imagen no debe superar los 5MB');
        return;
      }
      setFoto(file);
      const reader = new FileReader();
      reader.onloadend = () => {
        setFotoPreview(reader.result);
      };
      reader.readAsDataURL(file);
    }
  };

  const handleNext = () => {
    setActiveStep((prevStep) => prevStep + 1);
  };

  const handleBack = () => {
    setActiveStep((prevStep) => prevStep - 1);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (activeStep !== steps.length - 1) {
      handleNext();
      return;
    }
    
    setLoading(true);
    setError('');
    
    try {
      if (!formData.role) {
        throw new Error('Por favor selecciona un rol (Docente o Administrador)');
      }

      const formDataToSend = new FormData();
      
      // Asegurarnos que el role se envía correctamente
      Object.keys(formData).forEach(key => {
        if (key !== 'confirmPassword') {
          formDataToSend.append(key, formData[key]);
        }
      });
      
      if (foto) {
        const fileExtension = foto.name.split('.').pop();
        const uniqueFileName = `${formData.numeroControl}_${Date.now()}.${fileExtension}`;
        formDataToSend.append('fotoPerfil', foto, uniqueFileName);
      }

      console.log('Datos de registro a enviar:', Object.fromEntries(formDataToSend));
      
      const response = await register(formDataToSend);
      console.log('Respuesta del registro:', response);
      
      if (!response.success) {
        throw new Error(response.message || 'Error en el registro');
      }
      
      setSuccess(true);
      setTimeout(() => navigate('/login'), 1500);
      
    } catch (err) {
      console.error('Error en el registro:', err);
      setError(err.message || 'Error al registrar usuario');
    } finally {
      setLoading(false);
    }
  };

  const steps = ['Información Personal', 'Información Académica', 'Cuenta'];

  const renderStepContent = (step) => {
    switch (step) {
      case 0:
        return (
          <Box sx={{ mt: 2 }}>
            <Box sx={{ display: 'flex', justifyContent: 'center', mb: 3 }}>
              <Box
                sx={{
                  position: 'relative',
                  width: 150,
                  height: 150,
                  borderRadius: '50%',
                  overflow: 'hidden',
                  border: '3px solid',
                  borderColor: theme.palette.primary.main,
                  boxShadow: '0 4px 8px rgba(0,0,0,0.1)'
                }}
              >
                <Avatar
                  src={fotoPreview}
                  sx={{
                    width: '100%',
                    height: '100%',
                    cursor: 'pointer'
                  }}
                  onClick={() => fileInputRef.current.click()}
                >
                  <PhotoCamera sx={{ fontSize: 40 }} />
                </Avatar>
                <input
                  type="file"
                  hidden
                  ref={fileInputRef}
                  accept="image/*"
                  onChange={handleFotoChange}
                />
                <IconButton
                  sx={{
                    position: 'absolute',
                    bottom: 0,
                    right: 0,
                    backgroundColor: theme.palette.primary.main,
                    '&:hover': {
                      backgroundColor: theme.palette.primary.dark,
                    },
                  }}
                  onClick={() => fileInputRef.current.click()}
                >
                  <PhotoCamera sx={{ color: 'white' }} />
                </IconButton>
              </Box>
            </Box>
            
            <AnimatedTextField
              label="Número de Empleado"
              name="numeroControl"
              value={formData.numeroControl}
              onChange={handleNumeroControlChange}
              onBlur={handleNumeroControlBlur}
              required
              icon={<Badge />}
              inputProps={{
                maxLength: 15,
                pattern: '[^0-9A-Z]*'
              }}
              helperText="Ingresa tu Empleado (10-15 caracteres)"
            />
            <AnimatedTextField
              label="Nombre"
              name="nombre"
              value={formData.nombre}
              onChange={handleChange}
              required
              icon={<Person />}
            />
            <AnimatedTextField
              label="Apellido Paterno"
              name="apellidoPaterno"
              value={formData.apellidoPaterno}
              onChange={handleChange}
              required
              icon={<Person />}
            />
            <AnimatedTextField
              label="Apellido Materno"
              name="apellidoMaterno"
              value={formData.apellidoMaterno}
              onChange={handleChange}
              required
              icon={<Person />}
            />
          </Box>
        );
      case 1:
        return (
          <Box sx={{ mt: 2 }}>
            <AnimatedTextField
              select
              label="Carrera"
              name="carrera"
              value={formData.carrera}
              onChange={handleChange}
              required
              icon={<School />}
              disabled={isLoadingCarreras}
            >
              {isLoadingCarreras ? (
                <MenuItem disabled>Cargando carreras...</MenuItem>
              ) : carreras.length > 0 ? (
                carreras.map((carrera) => (
                  <MenuItem key={carrera._id} value={carrera._id}>
                    {carrera.nombre}
                  </MenuItem>
                ))
              ) : (
                <MenuItem disabled>No hay carreras disponibles</MenuItem>
              )}
            </AnimatedTextField>

            <FormControl fullWidth required sx={{ mt: 2 }}>
              <InputLabel>Rol de Usuario</InputLabel>
              <Select
                name="role"
                value={formData.role}
                onChange={handleChange}
                label="Rol de Usuario"
              >
                <MenuItem value="docente">Docente</MenuItem>
                <MenuItem value="admin">Administrador</MenuItem>
              </Select>
              <FormHelperText>
                {!formData.role ? 'Por favor selecciona un rol' : 
                 formData.role === 'admin' ? 'Rol de administrador seleccionado' : 'Rol de docente seleccionado'}
              </FormHelperText>
            </FormControl>
          </Box>
        );
      case 2:
        return (
          <Box sx={{ mt: 2 }}>
            <AnimatedTextField
              label="Correo Electrónico"
              type="email"
              name="email"
              value={formData.email}
              onChange={handleChange}
              onBlur={handleEmailBlur}
              required
              icon={<Email />}
              helperText="Ingresa tu correo (ejemplo: usuario@tesjo.edu.mx)"
            />
            <AnimatedTextField
              label="Contraseña"
              type={showPassword ? 'text' : 'password'}
              name="password"
              value={formData.password}
              onChange={handleChange}
              required
              icon={<Lock />}
              endAdornment={
                <InputAdornment position="end">
                  <IconButton
                    onClick={() => handleShowPassword('password')}
                    edge="end"
                  >
                    {showPassword ? <VisibilityOff /> : <Visibility />}
                  </IconButton>
                </InputAdornment>
              }
            />
            <AnimatedTextField
              label="Confirmar Contraseña"
              type={showConfirmPassword ? 'text' : 'password'}
              name="confirmPassword"
              value={formData.confirmPassword}
              onChange={handleChange}
              required
              icon={<Lock />}
              endAdornment={
                <InputAdornment position="end">
                  <IconButton
                    onClick={() => handleShowPassword('confirm')}
                    edge="end"
                  >
                    {showConfirmPassword ? <VisibilityOff /> : <Visibility />}
                  </IconButton>
                </InputAdornment>
              }
            />
            <FormControl fullWidth required sx={{ mt: 2 }}>
              <InputLabel>Rol</InputLabel>
              <Select
                name="role"
                value={formData.role}
                onChange={handleChange}
                required
              >
                <MenuItem value="docente">Docente</MenuItem>
                <MenuItem value="admin">Administrador</MenuItem>
              </Select>
              <FormHelperText>
                {!formData.role ? 'Por favor selecciona un rol' : ''}
              </FormHelperText>
            </FormControl>
          </Box>
        );
      default:
        return null;
    }
  };

  return (
    <ThemeProvider theme={theme}>
      <Container maxWidth="md" sx={{ py: 12 }}>
        <Zoom in={true} style={{ transitionDelay: '100ms' }}>
          <Paper
            elevation={6}
            sx={{
              borderRadius: 3,
              overflow: 'hidden',
              backgroundColor: 'background.paper'
            }}
          >
            <Box
              sx={{
                p: 3,
                bgcolor: theme.palette.primary.main,
                color: 'white',
                textAlign: 'center'
              }}
            >
              <Typography variant="h4" gutterBottom fontWeight="bold">
                Registro de Docentes
              </Typography>
              <Typography variant="subtitle1">
                Completa el formulario para crear tu cuenta
              </Typography>
            </Box>

            <Box sx={{ width: '100%', p: 4 }}>
              <Stepper activeStep={activeStep} alternativeLabel>
                {steps.map((label) => (
                  <Step key={label}>
                    <StepLabel>{label}</StepLabel>
                  </Step>
                ))}
              </Stepper>

              <Box component="form" onSubmit={handleSubmit} sx={{ mt: 3 }}>
                {renderStepContent(activeStep)}

                {error && (
                  <Grow in={!!error} timeout={500}>
                    <Alert
                      severity="error"
                      variant="filled"
                      sx={{ mt: 2 }}
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
                      sx={{ mt: 2 }}
                    >
                      ¡Registro exitoso! Redirigiendo al inicio de sesión...
                    </Alert>
                  </Grow>
                )}

                <Box sx={{ display: 'flex', justifyContent: 'space-between', mt: 4 }}>
                  <Button
                    disabled={activeStep === 0}
                    onClick={handleBack}
                    startIcon={<KeyboardArrowLeft />}
                  >
                    Anterior
                  </Button>
                  <Button
                    variant="contained"
                    onClick={handleSubmit}
                    endIcon={activeStep === steps.length - 1 ? <Save /> : <KeyboardArrowRight />}
                    disabled={loading}
                  >
                    {loading ? (
                      <CircularProgress size={24} sx={{ color: '#fff' }} />
                    ) : activeStep === steps.length - 1 ? (
                      'Registrarse'
                    ) : (
                      'Siguiente'
                    )}
                  </Button>
                </Box>
              </Box>
            </Box>
          </Paper>
        </Zoom>
      </Container>
    </ThemeProvider>
  );
}