import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { Box, Typography, Button, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Paper, IconButton, Dialog, DialogTitle, DialogContent, DialogActions, TextField, CircularProgress, Avatar, Chip, Card, CardContent, Grid, Fade, Slide, Zoom } from '@mui/material';
import { Edit, Delete, Menu as MenuIcon, Close as CloseIcon, PersonAdd, Refresh, FilterList, Visibility, MoreVert, Assignment, Assessment } from '@mui/icons-material';
import Drawer from '@mui/material/Drawer';
import { styled, keyframes } from '@mui/material/styles';
import Asignation from './Asignation';
import AdminAssignments from './AdminAssignmentsFixed';
import AdminErrorBoundary from './AdminErrorBoundary';

// Animaciones personalizadas
const pulse = keyframes`
  0% { transform: scale(1); }
  50% { transform: scale(1.05); }
  100% { transform: scale(1); }
`;

const glow = keyframes`
  0% { box-shadow: 0 0 5px rgba(25, 118, 210, 0.3); }
  50% { box-shadow: 0 0 20px rgba(25, 118, 210, 0.8); }
  100% { box-shadow: 0 0 5px rgba(25, 118, 210, 0.3); }
`;

const slideIn = keyframes`
  from { transform: translateX(-100%); opacity: 0; }
  to { transform: translateX(0); opacity: 1; }
`;

// Componentes estilizados
const StyledCard = styled(Card)(({ theme }) => ({
  background: 'linear-gradient(145deg, #ffffff 0%, #f5f7fa 100%)',
  borderRadius: '16px',
  boxShadow: '0 8px 32px rgba(0, 0, 0, 0.12)',
  border: '1px solid rgba(255, 255, 255, 0.2)',
  transition: 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)',
  '&:hover': {
    transform: 'translateY(-4px)',
    boxShadow: '0 12px 40px rgba(0, 0, 0, 0.15)',
  },
}));

const GlowButton = styled(Button)(({ theme }) => ({
  borderRadius: '12px',
  padding: '12px 24px',
  background: 'linear-gradient(45deg, #1976d2 30%, #42a5f5 90%)',
  transition: 'all 0.3s ease',
  '&:hover': {
    animation: `${glow} 2s infinite`,
    transform: 'translateY(-2px)',
  },
}));

const AnimatedTableRow = styled(TableRow)(({ theme }) => ({
  transition: 'all 0.3s ease',
  '&:hover': {
    backgroundColor: 'rgba(25, 118, 210, 0.04)',
    transform: 'scale(1.01)',
  },
}));

const HeaderBox = styled(Box)(({ theme }) => ({
  background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
  borderRadius: '20px',
  padding: '20px',
  marginBottom: '24px',
  color: 'white',
  position: 'relative',
  overflow: 'hidden',
  '&::before': {
    content: '""',
    position: 'absolute',
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    background: 'linear-gradient(45deg, transparent 30%, rgba(255,255,255,0.1) 50%, transparent 70%)',
    animation: `${slideIn} 3s infinite`,
  },
}));

const StyledAvatar = styled(Avatar)(({ theme }) => ({
  width: 56,
  height: 56,
  border: '3px solid #fff',
  boxShadow: '0 4px 12px rgba(0, 0, 0, 0.15)',
  transition: 'all 0.3s ease',
  '&:hover': {
    animation: `${pulse} 1s infinite`,
  },
}));

// Componente principal
export default function Structure() {
    const [users, setUsers] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    const [mobileDrawerOpen, setMobileDrawerOpen] = useState(false);
    const [asignationOpen, setAsignationOpen] = useState(false);
    const [adminAssignmentsOpen, setAdminAssignmentsOpen] = useState(false);
    const [scoreCardOpen, setScoreCardOpen] = useState(false);
    // Función para abrir Score Card
    const handleOpenScoreCard = useCallback(() => {
        setScoreCardOpen(true);
        setMobileDrawerOpen(false);
    }, []);

    // Función para cerrar Score Card
    const handleCloseScoreCard = useCallback(() => {
        setScoreCardOpen(false);
    }, []);
    const [teacherStats, setTeacherStats] = useState({});

    // Función optimizada para obtener usuarios con cache
    const fetchUsers = useCallback(async (force = false) => {
        if (users.length > 0 && !force) return; // Evita recargas innecesarias
        
        try {
            setLoading(true);
            const response = await fetch('http://localhost:3001/api/users', {
                headers: {
                    'Cache-Control': force ? 'no-cache' : 'max-age=300', // Cache por 5 minutos
                    'Pragma': force ? 'no-cache' : 'cache'
                }
            });
            
            if (!response.ok) {
                const errorData = await response.json().catch(() => null);
                throw new Error(errorData?.message || 'Error al obtener los usuarios');
            }
            
            const data = await response.json();
            
            if (!data.users || !Array.isArray(data.users)) {
                throw new Error('Formato de respuesta inválido');
            }
            
            setUsers(data.users);
            setError(null);
        } catch (err) {
            console.error('Error detallado:', err);
            setError(err.message);
        } finally {
            setLoading(false);
        }
    }, [users.length]);

    // Función para obtener estadísticas
    const fetchTeacherStats = useCallback(async () => {
        console.log('Iniciando fetchTeacherStats');
        try {
            const token = localStorage.getItem('token');
            if (!token) {
                throw new Error('No hay token de autenticación');
            }
            
            console.log('Realizando petición a la API de estadísticas');
            const response = await fetch('http://localhost:3001/api/stats/teachers', {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                }
            });

            console.log('Respuesta de la API:', response.status);
            const responseData = await response.text();
            console.log('Respuesta completa:', responseData);

            if (!response.ok) {
                throw new Error(`Error ${response.status}: ${responseData}`);
            }

            const data = JSON.parse(responseData);
            console.log('Datos recibidos:', data);
            
            if (!Array.isArray(data)) {
                throw new Error('Los datos recibidos no son un array');
            }

            // Convertir array de estadísticas a objeto para fácil acceso
            const statsMap = {};
            data.forEach(stat => {
                if (stat && stat.teacherId) {
                    statsMap[stat.teacherId] = {
                        teacherName: stat.teacherName,
                        email: stat.email,
                        total: stat.total || 0,
                        completed: stat.completed || 0,
                        pending: stat.pending || 0,
                        overdue: stat.overdue || 0
                    };
                }
            });
            
            console.log('StatsMap procesado:', statsMap);
            setTeacherStats(statsMap);
        } catch (error) {
            console.error('Error al obtener estadísticas:', error);
        }
    }, []);



    // Cargar usuarios y estadísticas junto con los usuarios
    useEffect(() => {
        const loadData = async () => {
            try {
                await fetchUsers();
                await fetchTeacherStats();
            } catch (error) {
                console.error('Error cargando datos:', error);
            }
        };
        loadData();
    }, [fetchUsers, fetchTeacherStats]);

    // Función de búsqueda mejorada
    const filteredUsers = useMemo(() => {
        return users;
    }, [users]);

    // Memoizar los detalles del estudiante
    // Función para refrescar datos
    const handleRefresh = useCallback(async () => {
        setLoading(true);
        try {
            await Promise.all([
                fetchUsers(true),
                fetchTeacherStats()
            ]);
        } catch (error) {
            console.error('Error al refrescar datos:', error);
        } finally {
            setLoading(false);
        }
    }, [fetchUsers, fetchTeacherStats]);

    const handleOpenAsignation = useCallback(() => {
        setAsignationOpen(true);
        setMobileDrawerOpen(false);
    }, []);

    const handleCloseAsignation = useCallback(() => {
        setAsignationOpen(false);
    }, []);

    const handleOpenAdminAssignments = useCallback(() => {
        setAdminAssignmentsOpen(true);
        setMobileDrawerOpen(false);
    }, []);

    const handleCloseAdminAssignments = useCallback(() => {
        setAdminAssignmentsOpen(false);
    }, []);

    // Renderizar las estadísticas en la tabla
    const renderStats = useCallback((user) => {
        console.log('Renderizando estadísticas para usuario:', user.numeroControl);
        console.log('Stats disponibles:', teacherStats);
        const stats = teacherStats[user.numeroControl] || {
            total: 0,
            completed: 0,
            pending: 0,
            overdue: 0
        };
        console.log('Stats para este usuario:', stats);

        return (
            <>
                <TableCell align="center">
                    <Chip 
                        label={stats.total} 
                        color="primary" 
                        variant="outlined"
                        size="small"
                    />
                </TableCell>
                <TableCell align="center">
                    <Chip 
                        label={stats.completed} 
                        color="success" 
                        variant="outlined"
                        size="small"
                    />
                </TableCell>
                <TableCell align="center">
                    <Chip 
                        label={stats.pending} 
                        color="warning" 
                        variant="outlined"
                        size="small"
                    />
                </TableCell>
                <TableCell align="center">
                    <Chip 
                        label={stats.overdue} 
                        color="error" 
                        variant="outlined"
                        size="small"
                    />
                </TableCell>
            </>
        );
    }, [teacherStats]);

    const renderScoreCard = useCallback(() => {
        return (
            <Dialog open={scoreCardOpen} onClose={handleCloseScoreCard} maxWidth="lg" fullWidth>
                <DialogTitle sx={{ background: 'linear-gradient(135deg, #ff9800 0%, #ffc107 100%)', color: 'white', fontWeight: 'bold' }}>
                    Score Card de Docentes
                </DialogTitle>
                <DialogContent>
                    <TableContainer>
                        <Table>
                            <TableHead>
                                <TableRow>
                                    <TableCell>Docente</TableCell>
                                    <TableCell align="center">Total</TableCell>
                                    <TableCell align="center">Pendientes</TableCell>
                                    <TableCell align="center">Completadas</TableCell>
                                    <TableCell align="center">No Entregado</TableCell>
                                    <TableCell align="center">Vencidas</TableCell>
                                    <TableCell align="center">Entregadas con Retraso</TableCell>
                                    <TableCell align="center">% Cumplimiento</TableCell>
                                </TableRow>
                            </TableHead>
                            <TableBody>
                                {users.map((user) => {
                                    const stats = teacherStats[user.numeroControl] || {
                                        total: 0,
                                        pending: 0,
                                        completed: 0,
                                        notDelivered: 0,
                                        overdue: 0,
                                        completedLate: 0
                                    };
                                    // Calcular porcentaje de cumplimiento correcto
                                    const correct = stats.completed || 0;
                                    const total = stats.total || 0;
                                    const percent = total > 0 ? Math.round((correct / total) * 100) : 0;
                                    return (
                                        <TableRow key={user._id}>
                                            <TableCell>{`${user.nombre} ${user.apellidoPaterno} ${user.apellidoMaterno}`}</TableCell>
                                            <TableCell align="center">{stats.total}</TableCell>
                                            <TableCell align="center">{stats.pending}</TableCell>
                                            <TableCell align="center">{stats.completed}</TableCell>
                                            <TableCell align="center">{stats.notDelivered || 0}</TableCell>
                                            <TableCell align="center">{stats.overdue || 0}</TableCell>
                                            <TableCell align="center">{stats.completedLate || 0}</TableCell>
                                            <TableCell align="center">{percent}%</TableCell>
                                        </TableRow>
                                    );
                                })}
                            </TableBody>
                        </Table>
                    </TableContainer>
                    <Box sx={{ mt: 2 }}>
                        <Typography variant="body2" color="text.secondary">
                            El porcentaje de cumplimiento corresponde a las asignaciones entregadas correctamente sobre el total asignado.
                        </Typography>
                    </Box>
                </DialogContent>
                <DialogActions>
                    <Button onClick={handleCloseScoreCard} variant="outlined">Cerrar</Button>
                </DialogActions>
            </Dialog>
        );
    }, [users, teacherStats, scoreCardOpen, handleCloseScoreCard]);

    return (
        <Box sx={{ display: 'flex', flexDirection: 'column', minHeight: '100vh', bgcolor: '#f8fafc' }}>
            {/* Contenido principal */}
            <Box sx={{ 
                flex: 1, 
                padding: 3, 
                pt: 10, // Aumentado el padding top para dar más espacio después del navbar
                mx: 'auto', // Centrar el contenido
                width: '100%',
                maxWidth: '1400px', // Limitar el ancho máximo para mejor legibilidad
            }}>
                {/* Header futurista */}
                <Fade in={true} timeout={1000}>
                    <HeaderBox sx={{
                        background: 'linear-gradient(135deg, #1976d2 0%, #1565c0 100%)', // Cambiado a tonos de azul más profesionales
                        boxShadow: '0 4px 20px rgba(0, 0, 0, 0.1)',
                        borderRadius: '16px',
                        mb: 4, // Aumentado el margen inferior
                    }}>
                        <Box sx={{ 
                            display: 'flex', 
                            alignItems: 'center', 
                            gap: 2, 
                            mb: 2,
                            px: 2, // Añadido padding horizontal
                        }}>
                            <IconButton
                                color="inherit"
                                onClick={() => setMobileDrawerOpen(true)}
                                sx={{ 
                                    backgroundColor: 'rgba(255, 255, 255, 0.2)',
                                    backdropFilter: 'blur(10px)',
                                    '&:hover': {
                                        backgroundColor: 'rgba(255, 255, 255, 0.3)',
                                        transform: 'scale(1.1)',
                                    },
                                    transition: 'all 0.3s ease',
                                }}
                            >
                                <MenuIcon />
                            </IconButton>
                            <Typography 
                                variant="h4" 
                                component="h1" 
                                sx={{ 
                                    fontWeight: 600,
                                    flexGrow: 1,
                                    letterSpacing: '0.5px',
                                    textShadow: '2px 2px 4px rgba(0,0,0,0.2)'
                                }}
                            >
                                Panel de Administración
                            </Typography>
                        </Box>
                        <Typography 
                            variant="subtitle1" 
                            sx={{ 
                                opacity: 0.9, 
                                fontWeight: 300,
                                px: 2,
                                pb: 2
                            }}
                        >
                            Gestiona docentes, consulta registros y administra el sistema
                        </Typography>
                    </HeaderBox>
                </Fade>

                {/* Tabla de usuarios */}
                <Zoom in={true} timeout={1000}>
                    <StyledCard sx={{
                        borderRadius: '16px',
                        overflow: 'hidden',
                        boxShadow: '0 4px 20px rgba(0, 0, 0, 0.08)',
                    }}>
                        <TableContainer>
                            <Table>
                                <TableHead>
                                    <TableRow sx={{ 
                                        backgroundColor: '#f5f7fa',
                                        '& th': { 
                                            fontWeight: 600,
                                            color: '#1976d2',
                                            fontSize: '0.95rem',
                                            py: 2
                                        }
                                    }}>
                                        <TableCell sx={{ fontWeight: 'bold', color: 'primary.main' }}>Foto</TableCell>
                                        <TableCell sx={{ fontWeight: 'bold', color: 'primary.main' }}>Número de Control</TableCell>
                                        <TableCell sx={{ fontWeight: 'bold', color: 'primary.main' }}>Nombre Completo</TableCell>
                                        <TableCell sx={{ fontWeight: 'bold', color: 'primary.main' }}>Carrera</TableCell>
                                        <TableCell sx={{ fontWeight: 'bold', color: 'primary.main' }}>Email</TableCell>
                                        <TableCell align="center" sx={{ fontWeight: 'bold', color: 'primary.main' }}>Total</TableCell>
                                        <TableCell align="center" sx={{ fontWeight: 'bold', color: 'primary.main' }}>Completadas</TableCell>
                                        <TableCell align="center" sx={{ fontWeight: 'bold', color: 'primary.main' }}>Pendientes</TableCell>
                                        <TableCell align="center" sx={{ fontWeight: 'bold', color: 'primary.main' }}>Vencidas</TableCell>
                                        <TableCell align="center" sx={{ fontWeight: 'bold', color: 'primary.main' }}>ScoreCard</TableCell>
                                    </TableRow>
                                </TableHead>
                                <TableBody>
                                    {loading ? (
                                        <TableRow>
                                            <TableCell colSpan={10} align="center" sx={{ py: 8 }}>
                                                <CircularProgress size={60} thickness={4} />
                                                <Typography sx={{ mt: 2, fontSize: '1.1rem' }}>
                                                    Cargando usuarios...
                                                </Typography>
                                            </TableCell>
                                        </TableRow>
                                    ) : error ? (
                                        <TableRow>
                                            <TableCell colSpan={10} align="center" sx={{ py: 8 }}>
                                                <Typography color="error" variant="h6">
                                                    ⚠️ Error: {error}
                                                </Typography>
                                                <Button 
                                                    onClick={handleRefresh} 
                                                    sx={{ mt: 2 }}
                                                    variant="outlined"
                                                >
                                                    Reintentar
                                                </Button>
                                            </TableCell>
                                        </TableRow>
                                    ) : filteredUsers.length === 0 ? (
                                        <TableRow>
                                            <TableCell colSpan={10} align="center" sx={{ py: 8 }}>
                                                <Typography variant="h6" color="text.secondary">
                                                    {/* searchTerm ? '🔍 No se encontraron usuarios' : '👥 No hay usuarios registrados' */}
                                                    No hay usuarios registrados
                                                </Typography>
                                            </TableCell>
                                        </TableRow>
                                    ) : (
                                        filteredUsers.map((user) => {
                                            return (
                                                <Fade in={true} timeout={300} key={user._id}>
                                                    <AnimatedTableRow>
                                                        <TableCell>
                                                            <StyledAvatar
                                                                src={user.fotoPerfil 
                                                                    ? `http://localhost:3001/uploads/perfiles/${user.fotoPerfil}?t=${Date.now()}`
                                                                    : 'http://localhost:3001/uploads/perfiles/2138822222222_1749571359362.png'
                                                                }
                                                                alt={`Foto de perfil de ${user.nombreCompleto}`}
                                                                onError={(e) => {
                                                                    if (!e.target.src.includes('2138822222222_1749571359362.png')) {
                                                                        e.target.onerror = null;
                                                                        e.target.src = `http://localhost:3001/uploads/perfiles/2138822222222_1749571359362.png?t=${Date.now()}`;
                                                                    }
                                                                }}
                                                            />
                                                        </TableCell>
                                                        <TableCell>
                                                            <Typography variant="body1" sx={{ fontWeight: 'bold', color: 'primary.main' }}>
                                                                {user.numeroControl}
                                                            </Typography>
                                                        </TableCell>
                                                        <TableCell>
                                                            <Typography variant="body1" sx={{ fontWeight: 500 }}>
                                                                {`${user.nombre} ${user.apellidoPaterno} ${user.apellidoMaterno}`}
                                                            </Typography>
                                                        </TableCell>
                                                        <TableCell>
                                                            <Chip 
                                                                label={typeof user.carrera === 'object' ? user.carrera.nombre : user.carrera} 
                                                                size="small" 
                                                                color="secondary"
                                                                sx={{ fontWeight: 'bold' }}
                                                            />
                                                        </TableCell>
                                                        <TableCell>
                                                            <Typography variant="body2" color="text.secondary">
                                                                {user.email}
                                                            </Typography>
                                                        </TableCell>
                                                        {renderStats(user)}
                                                        <TableCell>

                                                        </TableCell>
                                                    </AnimatedTableRow>
                                                </Fade>
                                            );
                                        })
                                    )}
                                </TableBody>
                            </Table>
                        </TableContainer>
                    </StyledCard>
                </Zoom>
            </Box>

            {/* Drawer de navegación (menú hamburguesa) */}
            <Drawer
                anchor="left"
                open={mobileDrawerOpen}
                onClose={() => setMobileDrawerOpen(false)}
                sx={{
                    '& .MuiDrawer-paper': {
                        background: 'linear-gradient(145deg, #1a1a2e 0%, #16213e 100%)',
                        color: 'white',
                    },
                }}
            >
                <Box sx={{ width: 300, padding: 3, display: 'flex', flexDirection: 'column', height: '100%' }}>
                    <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
                        <Typography variant="h6" sx={{ color: '#4fc3f7', fontWeight: 'bold' }}>
                            Menú de Administración
                        </Typography>
                        <IconButton onClick={() => setMobileDrawerOpen(false)} sx={{ color: 'white' }}>
                            <CloseIcon />
                        </IconButton>
                    </Box>
                    
                    {/* Gestión de Docentes */}
                    <Typography variant="subtitle2" sx={{ mb: 1, mt: 1, fontWeight: 'bold', color: '#4fc3f7' }}>
                        GESTIÓN DE DOCENTES
                    </Typography>

            <Button
                startIcon={<Assignment />}
                fullWidth
                variant="contained"
                sx={{
                    justifyContent: 'flex-start',
                    mb: 1.5,
                    py: 1.2,
                    background: 'linear-gradient(45deg, #1976d2 30%, #42a5f5 90%)',
                    '&:hover': {
                        background: 'linear-gradient(45deg, #1565c0 30%, #1976d2 90%)',
                    },
                }}
                onClick={handleOpenAsignation}
            >
                Nueva Asignación
            </Button>

            {/* Botón Score Card */}
            <Button
                startIcon={<Assessment />}
                fullWidth
                variant="contained"
                sx={{
                    justifyContent: 'flex-start',
                    mb: 1.5,
                    py: 1.2,
                    background: 'linear-gradient(45deg, #ff9800 30%, #ffc107 90%)',
                    '&:hover': {
                        background: 'linear-gradient(45deg, #ffa726 30%, #ff9800 90%)',
                    },
                }}
                onClick={handleOpenScoreCard}
            >
                Score Card
            </Button>

                    {/* Gestión de Asignaciones */}
                    <Typography variant="subtitle2" sx={{ mb: 1, mt: 2, fontWeight: 'bold', color: '#4fc3f7' }}>
                        GESTIÓN DE ASIGNACIONES
                    </Typography>
                    <Button
                        startIcon={<Assessment />}
                        fullWidth
                        variant="contained"
                        sx={{
                            justifyContent: 'flex-start',
                            mb: 1.5,
                            py: 1.2,
                            background: 'linear-gradient(45deg, #2e7d32 30%, #4caf50 90%)',
                            '&:hover': {
                                background: 'linear-gradient(45deg, #1b5e20 30%, #2e7d32 90%)',
                            },
                        }}
                        onClick={handleOpenAdminAssignments}
                    >
                        Administrar Asignaciones
                    </Button>
                    <Box sx={{ flexGrow: 1 }} />
                </Box>
            </Drawer>

            {/* Diálogo de Asignaciones */}
            <Asignation
                open={asignationOpen}
                onClose={handleCloseAsignation}
                users={users}
            />

            {/* Diálogo de Administración de Asignaciones */}
            <AdminErrorBoundary>
                <AdminAssignments
                    open={adminAssignmentsOpen}
                    onClose={handleCloseAdminAssignments}
                />
            </AdminErrorBoundary>

            {/* Score Card de Docentes */}
            {renderScoreCard()}
        </Box>
    );
}