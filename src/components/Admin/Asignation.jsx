import React, { useState, useContext, useEffect } from 'react';
import {
    Dialog,
    DialogTitle,
    DialogContent,
    DialogActions,
    TextField,
    Button,
    FormControl,
    InputLabel,
    Select,
    MenuItem,
    Box,
    Typography,
    Switch,
    FormControlLabel,
    Chip,
    IconButton,
    Alert,
    CircularProgress,
    Collapse,
    Fade,
    Slide,
    Paper,
    Avatar,
    List,
    ListItem,
    ListItemAvatar,
    ListItemText,
    Divider,
    Badge
} from '@mui/material';
import { 
    Close as CloseIcon, 
    AttachFile, 
    Delete,
    CheckCircle,
    Person,
    Groups,
    CalendarToday,
    EventAvailable,
    Description,
    Title as TitleIcon,
    AccessTime
} from '@mui/icons-material';
import { styled } from '@mui/material/styles';
import { AuthContext } from '../../contexts/AuthContext';
import { DatePicker, TimePicker, LocalizationProvider } from '@mui/x-date-pickers';
import { AdapterDateFns } from '@mui/x-date-pickers/AdapterDateFns';
import { es } from 'date-fns/locale';
import { motion } from 'framer-motion';
import API_CONFIG, { API_ENV, buildApiUrl } from '../../config/api';

const StyledDialog = styled(Dialog)(({ theme }) => ({
    '& .MuiDialog-paper': {
        borderRadius: theme.spacing(2),
        overflow: 'hidden',
        boxShadow: theme.shadows[10]
    }
}));

const Input = styled('input')({
    display: 'none',
});

const FilePreview = styled(Paper)(({ theme }) => ({
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    gap: theme.spacing(1),
    padding: theme.spacing(1.5),
    borderRadius: theme.spacing(1),
    marginTop: theme.spacing(1),
    transition: 'all 0.3s ease',
    '&:hover': {
        boxShadow: theme.shadows[2],
        transform: 'translateY(-2px)'
    }
}));

const SectionHeader = styled(Typography)(({ theme }) => ({
    display: 'flex',
    alignItems: 'center',
    gap: theme.spacing(1),
    margin: `${theme.spacing(2)} 0 ${theme.spacing(1)} 0`,
    color: theme.palette.text.secondary,
    '& svg': {
        fontSize: '1.2rem'
    }
}));

const AnimatedButton = motion(Button);

export default function Asignation({ open, onClose, users = [] }) {
    const { verifyToken } = useContext(AuthContext) || {};
    const backendOrigin = API_ENV.BASE_ORIGIN;
    
    const [form, setForm] = useState({
        title: '',
        description: '',
        dueDate: null,
        dueTime: null,
        closeDate: null,
        closeTime: null,
        isGeneral: false,
        assignedTo: [],
        attachments: []
    });
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);
    const [success, setSuccess] = useState(false);
    const [expandedSection, setExpandedSection] = useState('details');
    const [touched, setTouched] = useState({
        title: false,
        description: false,
        dueDate: false,
        closeDate: false
    });

    // Efecto para validar fechas cuando cambian
    useEffect(() => {
        if (form.dueDate && form.closeDate && new Date(form.closeDate) < new Date(form.dueDate)) {
            setError('La fecha de cierre debe ser posterior o igual a la fecha de entrega');
        } else if (error && error.includes('fecha de cierre')) {
            setError('');
        }
    }, [form.dueDate, form.closeDate, error]);

    const handleChange = (e) => {
        const { name, value } = e.target;
        setForm(prev => ({
            ...prev,
            [name]: value
        }));
        setTouched(prev => ({ ...prev, [name]: true }));
    };

    const handleDateChange = (name, date) => {
        setForm(prev => ({
            ...prev,
            [name]: date
        }));
        setTouched(prev => ({ ...prev, [name]: true }));
    };

    const handleTimeChange = (name, time) => {
        setForm(prev => ({
            ...prev,
            [name]: time
        }));
        setTouched(prev => ({ ...prev, [name === 'dueTime' ? 'dueDate' : 'closeDate']: true }));
    };

    const combineDateTime = (date, time) => {
        if (!date) return null;
        
        const combined = new Date(date);
        
        if (time) {
            const timeDate = new Date(time);
            combined.setHours(timeDate.getHours());
            combined.setMinutes(timeDate.getMinutes());
        } else {
            // Si no hay hora específica, usar la hora actual
            const now = new Date();
            combined.setHours(now.getHours());
            combined.setMinutes(now.getMinutes());
        }
        
        return combined;
    };

    const handleToggleGeneral = () => {
        setForm(prev => ({
            ...prev,
            isGeneral: !prev.isGeneral,
            assignedTo: []
        }));
    };

    const handleFileChange = (e) => {
        const files = Array.from(e.target.files);
        setForm(prev => ({
            ...prev,
            attachments: [...prev.attachments, ...files]
        }));
    };

    const handleRemoveFile = (index) => {
        setForm(prev => ({
            ...prev,
            attachments: prev.attachments.filter((_, i) => i !== index)
        }));
    };

    const handleUserSelect = (userId) => {
        setForm(prev => {
            const isSelected = prev.assignedTo.includes(userId);
            return {
                ...prev,
                assignedTo: isSelected 
                    ? prev.assignedTo.filter(id => id !== userId)
                    : [...prev.assignedTo, userId]
            };
        });
    };

    const resetForm = () => {
        setForm({
            title: '',
            description: '',
            dueDate: null,
            closeDate: null,
            isGeneral: false,
            assignedTo: [],
            attachments: []
        });
        setError('');
        setSuccess(false);
        setTouched({
            title: false,
            description: false,
            dueDate: false,
            closeDate: false
        });
    };

    const handleClose = () => {
        resetForm();
        onClose();
    };

    const validateForm = () => {
        const errors = [];
        
        if (!form.title.trim()) errors.push('El título es requerido');
        if (!form.description.trim()) errors.push('La descripción es requerida');
        if (!form.dueDate) errors.push('La fecha de entrega es requerida');
        if (!form.closeDate) errors.push('La fecha de cierre es requerida');
        if (form.closeDate && form.dueDate && new Date(form.closeDate) < new Date(form.dueDate)) {
            errors.push('La fecha de cierre debe ser posterior o igual a la fecha de entrega');
        }
        if (!form.isGeneral && form.assignedTo.length === 0) {
            errors.push('Debe seleccionar al menos un docente para asignaciones individuales');
        }
        
        return errors;
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        setLoading(true);
        setError('');
        setSuccess(false);

        const errors = validateForm();
        if (errors.length > 0) {
            setError(errors[0]);
            setLoading(false);
            return;
        }

        try {
            console.log('🔄 Verificando token...');
            
            const token = localStorage.getItem('token');
            if (!token) {
                throw new Error('No se encontró el token de autenticación. Por favor, inicia sesión nuevamente.');
            }

            // Verificar que el token sea válido
            console.log('🛡️ Verificando estado de autenticación...');
            const authCheckResponse = await fetch(buildApiUrl('/assignments/auth-status'), {
                headers: {
                    'Authorization': `Bearer ${token}`
                },
                credentials: API_CONFIG.withCredentials ? 'include' : 'same-origin',
            });
            
            const authCheck = await authCheckResponse.json();
            console.log('Estado de autenticación:', authCheck);
            
            if (!authCheck.success) {
                console.warn('Verificación de auth-status falló, continuando con la creación...');
                // throw new Error(authCheck.message || 'Token de autenticación inválido');
            }

            // Intentar verificar token usando el contexto
            if (verifyToken) {
                await verifyToken();
            }

            console.log('📅 Procesando fechas...');
            const dueDateWithTime = combineDateTime(form.dueDate, form.dueTime);
            const closeDateWithTime = combineDateTime(form.closeDate, form.closeTime);

            if (!dueDateWithTime || !closeDateWithTime) {
                throw new Error('Error al procesar las fechas. Verifique que estén correctamente establecidas.');
            }

            console.log('📦 Preparando datos del formulario...');
            const formData = new FormData();
            formData.append('title', form.title.trim());
            formData.append('description', form.description.trim());
            formData.append('dueDate', dueDateWithTime.toISOString());
            formData.append('closeDate', closeDateWithTime.toISOString());
            formData.append('isGeneral', form.isGeneral);
            
            if (!form.isGeneral && form.assignedTo.length > 0) {
                form.assignedTo.forEach(userId => {
                    formData.append('assignedTo[]', userId);
                });
            }

            if (form.attachments.length > 0) {
                form.attachments.forEach(file => {
                    formData.append('attachments', file);
                });
            }

            console.log('🚀 Enviando petición al servidor...');
            console.log('URL:', buildApiUrl('/assignments'));
            console.log('Token presente:', !!token);
            console.log('FormData entries:');
            for (let [key, value] of formData.entries()) {
                console.log(`  ${key}:`, typeof value === 'object' && value instanceof File ? `File: ${value.name}` : value);
            }
            
            const response = await fetch(buildApiUrl('/assignments'), {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`
                },
                body: formData,
                credentials: API_CONFIG.withCredentials ? 'include' : 'same-origin',
            });
            
            console.log('📡 Respuesta del servidor:', response.status, response.statusText);
            
            if (!response.ok) {
                let errorMessage = `Error ${response.status}: ${response.statusText}`;
                
                try {
                    const errorData = await response.json();
                    errorMessage = errorData.error || errorData.message || errorMessage;
                    console.log('Error data:', errorData);
                } catch (parseError) {
                    console.error('Error al parsear respuesta de error:', parseError);
                    const errorText = await response.text();
                    console.log('Respuesta de error como texto:', errorText);
                    errorMessage = errorText || errorMessage;
                }
                
                throw new Error(errorMessage);
            }

            const data = await response.json();
            console.log('✅ Asignación creada exitosamente:', data);

            setSuccess(true);
            setTimeout(() => {
                handleClose();
                if (window.location.pathname.includes('/admin')) {
                    window.location.reload();
                }
            }, 1500);

        } catch (err) {
            console.error('❌ Error al crear la asignación:', err);
            
            let errorMessage = err.message;
            
            // Mejorar mensajes de error comunes
            if (err.message.includes('Failed to fetch')) {
                errorMessage = `No se pudo conectar con el servidor. Verifique que el servidor esté ejecutándose en ${backendOrigin}`;
            } else if (err.message.includes('NetworkError')) {
                errorMessage = 'Error de red. Verifique su conexión a internet y que el servidor esté disponible.';
            } else if (err.message.includes('401')) {
                errorMessage = 'Su sesión ha expirado. Por favor, cierre sesión e inicie sesión nuevamente.';
            } else if (err.message.includes('403')) {
                errorMessage = 'No tiene permisos para realizar esta acción.';
            } else if (err.message.includes('500')) {
                errorMessage = 'Error interno del servidor. Por favor, intente nuevamente más tarde.';
            }
            
            setError(errorMessage);
        } finally {
            setLoading(false);
        }
    };

    // Verificaciones de seguridad después de todos los hooks
    if (!open) return null;
    if (!verifyToken) {
        console.error('AuthContext not available in Asignation component');
        return null;
    }

    return (
        <StyledDialog 
            open={open} 
            onClose={handleClose}
            maxWidth="md"
            fullWidth
            TransitionComponent={Slide}
            transitionDuration={300}
        >
            <DialogTitle sx={{ 
                backgroundColor: 'primary.main', 
                color: 'primary.contrastText',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                py: 2
            }}>
                <Box display="flex" alignItems="center" gap={1}>
                    <Description fontSize="medium" />
                    <Typography variant="h6">Nueva Asignación</Typography>
                </Box>
                <IconButton 
                    onClick={handleClose} 
                    size="small"
                    sx={{ color: 'primary.contrastText' }}
                >
                    <CloseIcon />
                </IconButton>
            </DialogTitle>

            <form onSubmit={handleSubmit}>
                <DialogContent sx={{ py: 3 }}>
                    <Collapse in={!!error}>
                        <Alert 
                            severity="error" 
                            sx={{ mb: 2 }}
                            action={
                                <IconButton
                                    aria-label="close"
                                    color="inherit"
                                    size="small"
                                    onClick={() => setError('')}
                                >
                                    <CloseIcon fontSize="inherit" />
                                </IconButton>
                            }
                        >
                            {error}
                        </Alert>
                    </Collapse>
                    
                    <Fade in={success}>
                        <Alert 
                            severity="success" 
                            sx={{ mb: 2 }}
                            icon={<CheckCircle fontSize="inherit" />}
                        >
                            Asignación creada exitosamente
                        </Alert>
                    </Fade>

                    <Box sx={{ display: 'flex', gap: 2, mb: 3 }}>
                        <Button
                            variant={expandedSection === 'details' ? 'contained' : 'outlined'}
                            onClick={() => setExpandedSection('details')}
                            startIcon={<TitleIcon />}
                            sx={{ flex: 1 }}
                        >
                            Detalles
                        </Button>
                        <Button
                            variant={expandedSection === 'dates' ? 'contained' : 'outlined'}
                            onClick={() => setExpandedSection('dates')}
                            startIcon={<CalendarToday />}
                            sx={{ flex: 1 }}
                        >
                            Fechas
                        </Button>
                        <Button
                            variant={expandedSection === 'assignees' ? 'contained' : 'outlined'}
                            onClick={() => setExpandedSection('assignees')}
                            startIcon={form.isGeneral ? <Groups /> : <Person />}
                            sx={{ flex: 1 }}
                        >
                            {form.isGeneral ? 'General' : 'Docentes'}
                        </Button>
                        <Button
                            variant={expandedSection === 'files' ? 'contained' : 'outlined'}
                            onClick={() => setExpandedSection('files')}
                            startIcon={<AttachFile />}
                            sx={{ flex: 1 }}
                        >
                            Archivos
                        </Button>
                    </Box>

                    <Box sx={{ minHeight: '300px' }}>
                        {expandedSection === 'details' && (
                            <motion.div
                                initial={{ opacity: 0, x: -20 }}
                                animate={{ opacity: 1, x: 0 }}
                                transition={{ duration: 0.3 }}
                            >
                                <SectionHeader variant="subtitle1">
                                    <TitleIcon /> Información básica
                                </SectionHeader>
                                <TextField
                                    fullWidth
                                    label="Título"
                                    name="title"
                                    value={form.title}
                                    onChange={handleChange}
                                    margin="normal"
                                    required
                                    error={touched.title && !form.title}
                                    helperText={touched.title && !form.title ? 'Este campo es requerido' : ''}
                                    InputProps={{
                                        startAdornment: (
                                            <TitleIcon color="action" sx={{ mr: 1 }} />
                                        )
                                    }}
                                />

                                <TextField
                                    fullWidth
                                    label="Descripción"
                                    name="description"
                                    value={form.description}
                                    onChange={handleChange}
                                    margin="normal"
                                    multiline
                                    rows={4}
                                    required
                                    error={touched.description && !form.description}
                                    helperText={touched.description && !form.description ? 'Este campo es requerido' : ''}
                                    InputProps={{
                                        startAdornment: (
                                            <Description color="action" sx={{ mr: 1, alignSelf: 'flex-start', mt: 1 }} />
                                        )
                                    }}
                                />
                            </motion.div>
                        )}

                        {expandedSection === 'dates' && (
                            <motion.div
                                initial={{ opacity: 0, x: 20 }}
                                animate={{ opacity: 1, x: 0 }}
                                transition={{ duration: 0.3 }}
                            >
                                <SectionHeader variant="subtitle1">
                                    <CalendarToday /> Fechas y horas importantes
                                </SectionHeader>
                                <LocalizationProvider dateAdapter={AdapterDateFns} adapterLocale={es}>
                                    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2, mt: 2 }}>
                                        <Box sx={{ display: 'flex', gap: 2 }}>
                                            <DatePicker
                                                label="Fecha de Entrega"
                                                value={form.dueDate}
                                                onChange={(date) => handleDateChange('dueDate', date)}
                                                renderInput={(params) => (
                                                    <TextField 
                                                        {...params} 
                                                        fullWidth 
                                                        required
                                                        error={touched.dueDate && !form.dueDate}
                                                        helperText={touched.dueDate && !form.dueDate ? 'Este campo es requerido' : ''}
                                                        InputProps={{
                                                            ...params.InputProps,
                                                            startAdornment: (
                                                                <CalendarToday color="action" sx={{ mr: 1 }} />
                                                            )
                                                        }}
                                                    />
                                                )}
                                            />
                                            <TimePicker
                                                label="Hora de Entrega"
                                                value={form.dueTime}
                                                onChange={(time) => handleTimeChange('dueTime', time)}
                                                renderInput={(params) => (
                                                    <TextField 
                                                        {...params} 
                                                        fullWidth 
                                                        required
                                                        error={touched.dueDate && !form.dueTime}
                                                        helperText={touched.dueDate && !form.dueTime ? 'Este campo es requerido' : ''}
                                                        InputProps={{
                                                            ...params.InputProps,
                                                            startAdornment: (
                                                                <AccessTime color="action" sx={{ mr: 1 }} />
                                                            )
                                                        }}
                                                    />
                                                )}
                                            />
                                        </Box>
                                        <Box sx={{ display: 'flex', gap: 2 }}>
                                            <DatePicker
                                                label="Fecha de Cierre"
                                                value={form.closeDate}
                                                onChange={(date) => handleDateChange('closeDate', date)}
                                                minDate={form.dueDate}
                                                renderInput={(params) => (
                                                    <TextField 
                                                        {...params} 
                                                        fullWidth 
                                                        required
                                                        error={touched.closeDate && !form.closeDate}
                                                        helperText={touched.closeDate && !form.closeDate ? 'Este campo es requerido' : ''}
                                                        InputProps={{
                                                            ...params.InputProps,
                                                            startAdornment: (
                                                                <CalendarToday color="action" sx={{ mr: 1 }} />
                                                            )
                                                        }}
                                                    />
                                                )}
                                            />
                                            <TimePicker
                                                label="Hora de Cierre"
                                                value={form.closeTime}
                                                onChange={(time) => handleTimeChange('closeTime', time)}
                                                renderInput={(params) => (
                                                    <TextField 
                                                        {...params} 
                                                        fullWidth 
                                                        required
                                                        error={touched.closeDate && !form.closeTime}
                                                        helperText={touched.closeDate && !form.closeTime ? 'Este campo es requerido' : ''}
                                                        InputProps={{
                                                            ...params.InputProps,
                                                            startAdornment: (
                                                                <AccessTime color="action" sx={{ mr: 1 }} />
                                                            )
                                                        }}
                                                    />
                                                )}
                                            />
                                        </Box>
                                    </Box>
                                </LocalizationProvider>
                            </motion.div>
                        )}

                        {expandedSection === 'assignees' && (
                            <motion.div
                                initial={{ opacity: 0, y: 20 }}
                                animate={{ opacity: 1, y: 0 }}
                                transition={{ duration: 0.3 }}
                            >
                                <SectionHeader variant="subtitle1">
                                    {form.isGeneral ? <Groups /> : <Person />} 
                                    {form.isGeneral ? ' Asignación General' : ' Asignar a Docentes'}
                                </SectionHeader>
                                <FormControlLabel
                                    control={
                                        <Switch
                                            checked={form.isGeneral}
                                            onChange={handleToggleGeneral}
                                            name="isGeneral"
                                            color="primary"
                                        />
                                    }
                                    label="Asignación General (para todos los docentes)"
                                    sx={{ mb: 2 }}
                                />

                                {!form.isGeneral && (
                                    <>
                                        <Typography variant="body2" color="textSecondary" sx={{ mb: 1 }}>
                                            Seleccione los docentes a asignar ({form.assignedTo.length} seleccionados)
                                        </Typography>
                                        <Paper variant="outlined" sx={{ p: 1, maxHeight: '300px', overflow: 'auto' }}>
                                            <List dense>
                                                {users.map((user) => (
                                                    <React.Fragment key={user._id}>
                                                        <ListItem 
                                                            button 
                                                            onClick={() => handleUserSelect(user._id)}
                                                            selected={form.assignedTo.includes(user._id)}
                                                        >
                                                            <ListItemAvatar>
                                                                <Badge
                                                                    overlap="circular"
                                                                    anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
                                                                    badgeContent={
                                                                        form.assignedTo.includes(user._id) ? (
                                                                            <CheckCircle color="primary" fontSize="small" />
                                                                        ) : null
                                                                    }
                                                                >
                                                                    <Avatar 
                                                                        alt={`${user.nombre} ${user.apellidoPaterno}`}
                                                                        src={user.avatar}
                                                                        sx={{ width: 40, height: 40 }}
                                                                    />
                                                                </Badge>
                                                            </ListItemAvatar>
                                                            <ListItemText
                                                                primary={`${user.nombre} ${user.apellidoPaterno}`}
                                                                secondary={user.email}
                                                            />
                                                        </ListItem>
                                                        <Divider variant="inset" component="li" />
                                                    </React.Fragment>
                                                ))}
                                            </List>
                                        </Paper>
                                    </>
                                )}
                            </motion.div>
                        )}

                        {expandedSection === 'files' && (
                            <motion.div
                                initial={{ opacity: 0, y: -20 }}
                                animate={{ opacity: 1, y: 0 }}
                                transition={{ duration: 0.3 }}
                            >
                                <SectionHeader variant="subtitle1">
                                    <AttachFile /> Archivos adjuntos
                                </SectionHeader>
                                <label htmlFor="file-upload">
                                    <Input
                                        id="file-upload"
                                        type="file"
                                        multiple
                                        onChange={handleFileChange}
                                    />
                                    <AnimatedButton
                                        component="span"
                                        variant="outlined"
                                        startIcon={<AttachFile />}
                                        whileHover={{ scale: 1.02 }}
                                        whileTap={{ scale: 0.98 }}
                                    >
                                        Adjuntar Archivos
                                    </AnimatedButton>
                                </label>

                                <Box mt={2}>
                                    {form.attachments.length === 0 ? (
                                        <Typography variant="body2" color="textSecondary">
                                            No hay archivos adjuntos
                                        </Typography>
                                    ) : (
                                        form.attachments.map((file, index) => (
                                            <FilePreview 
                                                key={index}
                                                elevation={1}
                                                component={motion.div}
                                                initial={{ opacity: 0 }}
                                                animate={{ opacity: 1 }}
                                                transition={{ duration: 0.2 }}
                                            >
                                                <Box display="flex" alignItems="center" gap={1}>
                                                    <AttachFile color="action" />
                                                    <Typography noWrap sx={{ maxWidth: '300px' }}>
                                                        {file.name}
                                                    </Typography>
                                                </Box>
                                                <IconButton
                                                    size="small"
                                                    onClick={() => handleRemoveFile(index)}
                                                    color="error"
                                                >
                                                    <Delete />
                                                </IconButton>
                                            </FilePreview>
                                        ))
                                    )}
                                </Box>
                            </motion.div>
                        )}
                    </Box>
                </DialogContent>

                <DialogActions sx={{ px: 3, py: 2, borderTop: '1px solid rgba(0, 0, 0, 0.12)' }}>
                    <Button 
                        onClick={handleClose}
                        variant="outlined"
                        color="inherit"
                    >
                        Cancelar
                    </Button>
                    
                    <AnimatedButton
                        type="submit"
                        variant="contained"
                        disabled={loading}
                        whileHover={{ scale: 1.02 }}
                        whileTap={{ scale: 0.98 }}
                        endIcon={loading ? <CircularProgress size={24} /> : null}
                    >
                        {loading ? 'Creando...' : 'Crear Asignación'}
                    </AnimatedButton>
                </DialogActions>
            </form>
        </StyledDialog>
    );
}