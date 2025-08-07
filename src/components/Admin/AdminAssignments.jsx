import React, { useState, useEffect, useCallback } from 'react';
import {
    Box,
    Paper,
    Typography,
    Button,
    Card,
    CardContent,
    Chip,
    Grid,
    Alert,
    CircularProgress,
    Dialog,
    DialogTitle,
    DialogContent,
    DialogActions,
    TextField,
    MenuItem,
    IconButton,
    Tooltip,
    Badge,
    Slide,
    Table,
    TableBody,
    TableCell,
    TableHead,
    TableRow,
    TableContainer,
    InputAdornment,
    FormControl,
    InputLabel,
    Select
} from '@mui/material';
import {
    Assignment as AssignmentIcon,
    Schedule,
    CheckCircle,
    Warning,
    Search,
    FilterList,
    Refresh,
    Visibility,
    Done,
    Close,
    CalendarToday,
    FileDownload,
    Person,
    School,
    AdminPanelSettings,
    Edit as EditIcon,
    Assignment,
    AssignmentInd,
    PlaylistAddCheck
} from '@mui/icons-material';
import { motion, AnimatePresence } from 'framer-motion';
import { useTheme } from '@mui/material/styles';
import { 
    getAdminAllAssignments, 
    markAssignmentCompletedByAdmin, 
    getAdminAssignmentStats,
    updateAssignmentByAdmin,
    getTeachersStatusForAssignment,
    updateTeacherStatusInAssignment
} from '../../services/assignmentService';
import EditAssignment from './EditAssignment';
import ScheduledAssignments from './ScheduledAssignmentsSimple';

// Custom animated components
const AnimatedBadge = motion(Badge);

const AdminAssignments = ({ open, onClose }) => {
    const theme = useTheme();
    
    // Estados principales
    const [assignments, setAssignments] = useState([]);
    const [stats, setStats] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const [teachers, setTeachers] = useState([]);
    
    // Estados para filtros
    const [statusFilter, setStatusFilter] = useState('all');
    const [searchTerm, setSearchTerm] = useState('');
    const [sortBy, setSortBy] = useState('-createdAt');
    const [teacherFilter, setTeacherFilter] = useState('all');
    
    // Estados para paginación
    const [page, setPage] = useState(1);
    const [totalPages, setTotalPages] = useState(1);
    
    // Estados para diálogos
    const [selectedAssignment, setSelectedAssignment] = useState(null);
    const [showDetailDialog, setShowDetailDialog] = useState(false);
    const [showEditDialog, setShowEditDialog] = useState(false);
    const [showScheduledDialog, setShowScheduledDialog] = useState(false);
    const [showTeacherStatusDialog, setShowTeacherStatusDialog] = useState(false);
    const [assignmentTeachers, setAssignmentTeachers] = useState([]);
    const [actionLoading, setActionLoading] = useState(false);
    const [isRefreshing, setIsRefreshing] = useState(false);

    const loadStats = useCallback(async () => {
        try {
            const response = await getAdminAssignmentStats();
            if (response.success) {
                setStats(response.data);
            }
        } catch (error) {
            console.error('Error loading admin stats:', error);
        }
    }, []);

    const loadAssignments = useCallback(async () => {
        try {
            setLoading(true);
            setError('');
            
            console.log('🔍 Loading assignments with status filter:', statusFilter);
            
            const params = {
                status: statusFilter,
                search: searchTerm,
                sort: sortBy,
                page: page,
                limit: 10,
                ...(teacherFilter !== 'all' && { teacherId: teacherFilter })
            };

            console.log('📤 Sending API request with params:', params);

            const response = await getAdminAllAssignments(params);
            
            console.log('📥 Admin Assignments Response:', response);
            
            if (response.success) {
                console.log('✅ Assignments received:', response.data?.assignments?.length || 0);
                console.log('✅ Teachers received:', response.data?.teachers?.length || 0);
                
                setAssignments(response.data?.assignments || []);
                setTotalPages(response.data?.pagination?.pages || 1);
                setTeachers(response.data?.teachers || []);
            } else {
                setError('Error en la respuesta del servidor');
            }
        } catch (error) {
            console.error('Error loading assignments:', error);
            setError('Error cargando asignaciones: ' + (error.message || 'Error desconocido'));
        } finally {
            setLoading(false);
            setIsRefreshing(false);
        }
    }, [statusFilter, searchTerm, sortBy, page, teacherFilter]);

    // Cargar datos cuando se abre el diálogo
    useEffect(() => {
        if (open) {
            loadStats();
            loadAssignments();
        }
    }, [open, loadStats, loadAssignments]);

    // Resetear página cuando cambien los filtros
    useEffect(() => {
        setPage(1);
    }, [statusFilter, searchTerm, sortBy, teacherFilter]);

    const handleRefresh = () => {
        setIsRefreshing(true);
        loadAssignments();
        loadStats();
    };

    const handleCompleteAssignment = async (assignmentId) => {
        try {
            setActionLoading(true);
            setError('');
            
            const response = await markAssignmentCompletedByAdmin(assignmentId);
            
            if (response.success) {
                await loadAssignments();
                await loadStats();
                setShowDetailDialog(false);
            } else {
                throw new Error(response.error || 'Error desconocido');
            }
        } catch (error) {
            console.error('Error completing assignment:', error);
            const errorMessage = error.response?.data?.error || error.message || 'Error marcando como completado';
            setError(errorMessage);
        } finally {
            setActionLoading(false);
        }
    };

    const handleEditAssignment = (assignment) => {
        setSelectedAssignment(assignment);
        setShowEditDialog(true);
    };

    // Nueva función para manejar el diálogo de estados de docentes
    const handleManageTeacherStates = async (assignment) => {
        try {
            setActionLoading(true);
            setSelectedAssignment(assignment);
            
            // Usar el servicio en lugar de fetch directo
            const data = await getTeachersStatusForAssignment(assignment._id);
            setAssignmentTeachers(data.teachersStatus || []);
            setShowTeacherStatusDialog(true);
        } catch (error) {
            console.error('Error:', error);
            setError(error.message || 'Error al cargar los estados de los docentes');
        } finally {
            setActionLoading(false);
        }
    };

    // Función para actualizar el estado de un docente específico
    const handleUpdateTeacherStatus = async (teacherId, newStatus) => {
        try {
            setActionLoading(true);
            
            // Usar el servicio en lugar de fetch directo
            await updateTeacherStatusInAssignment(selectedAssignment._id, teacherId, newStatus);
            
            // Recargar los estados actualizados
            await handleManageTeacherStates(selectedAssignment);
            await loadAssignments(); // Recargar la lista principal
        } catch (error) {
            console.error('Error:', error);
            setError(error.message || 'Error al actualizar el estado del docente');
        } finally {
            setActionLoading(false);
        }
    };

    const handleSaveAssignment = async (updatedData) => {
        try {
            setActionLoading(true);
            setError('');
            
            const response = await updateAssignmentByAdmin(updatedData._id, updatedData);
            
            if (response.success) {
                await loadAssignments();
                await loadStats();
                setShowEditDialog(false);
                setSelectedAssignment(null);
                
                // Mostrar mensaje específico según el tipo de operación
                if (response.type === 'specific_assignment_created') {
                    // Podríamos mostrar una notificación especial aquí
                    console.log('✅ Asignación específica creada para el docente seleccionado');
                } else {
                    console.log('✅ Asignación actualizada para todos los docentes');
                }
            } else {
                throw new Error(response.error || 'Error desconocido');
            }
        } catch (error) {
            console.error('Error updating assignment:', error);
            const errorMessage = error.response?.data?.error || error.message || 'Error actualizando asignación';
            setError(errorMessage);
        } finally {
            setActionLoading(false);
        }
    };

    const getStatusColor = (status, dueDate, closeDate) => {
        if (status === 'completed') return 'success';
        
        const now = new Date();
        const due = new Date(dueDate);
        const close = new Date(closeDate);
        
        if (now > close) return 'error';
        if (now > due) return 'warning';
        
        const daysUntilDue = Math.ceil((due - now) / (1000 * 60 * 60 * 24));
        if (daysUntilDue <= 1) return 'error';
        if (daysUntilDue <= 3) return 'warning';
        
        return 'primary';
    };

    const getStatusLabel = (status, dueDate, closeDate) => {
        if (status === 'completed') return 'Completado';
        if (status === 'pending') {
            const now = new Date();
            const due = new Date(dueDate);
            const close = new Date(closeDate);
            
            if (now > close) return 'Cerrado - No entregado';
            if (now > due) return 'Vencido - Puede entregarse';
            
            const daysUntilDue = Math.ceil((due - now) / (1000 * 60 * 60 * 24));
            
            if (daysUntilDue <= 0) {
                return 'Vence hoy';
            } else if (daysUntilDue === 1) {
                return 'Vence mañana';
            } else {
                return `${daysUntilDue} días restantes`;
            }
        }
        return status;
    };

    const formatDate = (dateString) => {
        try {
            if (!dateString || dateString === 'Invalid Date') return 'Fecha inválida';
            const date = new Date(dateString);
            if (isNaN(date.getTime())) return 'Fecha inválida';
            return date.toLocaleDateString('es-ES', {
                year: 'numeric',
                month: 'long',
                day: 'numeric'
            });
        } catch (error) {
            console.error('Error formatting date:', error);
            return 'Fecha inválida';
        }
    };

    const formatDateWithTime = (dateString) => {
        try {
            if (!dateString || dateString === 'Invalid Date') return 'Fecha inválida';
            const date = new Date(dateString);
            if (isNaN(date.getTime())) return 'Fecha inválida';
            return date.toLocaleDateString('es-ES', {
                year: 'numeric',
                month: 'long',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit'
            });
        } catch (error) {
            console.error('Error formatting date with time:', error);
            return 'Fecha inválida';
        }
    };

    // Si no está abierto, no renderizar nada
    if (!open) {
        return null;
    }

    return (
        <Dialog
            open={open}
            onClose={onClose}
            maxWidth="xl"
            fullWidth
            TransitionComponent={Slide}
            transitionDuration={300}
            PaperProps={{
                sx: {
                    borderRadius: 3,
                    background: `linear-gradient(to bottom, ${theme.palette.background.paper}, ${theme.palette.grey[50]})`,
                    minHeight: '90vh'
                }
            }}
        >
            <DialogTitle sx={{ 
                py: 2,
                px: 3,
                background: `linear-gradient(to right, ${theme.palette.primary.dark}, ${theme.palette.primary.main})`,
                color: 'white',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center'
            }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                    <AdminPanelSettings sx={{ fontSize: 28 }} />
                    <Typography variant="h5" sx={{ fontWeight: 'bold' }}>
                        Gestión de Asignaciones
                    </Typography>
                    {/* <Button
                        variant="contained"
                        color="secondary"
                        startIcon={<Schedule />}
                        onClick={() => setShowScheduledDialog(true)}
                        sx={{ ml: 2 }}
                    >
                        Programadas
                    </Button> */}
                </Box>
                <IconButton 
                    onClick={onClose}
                    sx={{ color: 'white' }}
                >
                    <Close />
                </IconButton>
            </DialogTitle>

            <DialogContent sx={{ p: 3 }}>
                {/* Estadísticas con botones interactivos grandes */}
                <Grid container spacing={3} sx={{ mb: 4 }}>
                    <Grid item xs={12} md={3}>
                        <motion.div
                            whileHover={{ scale: 1.05 }}
                            whileTap={{ scale: 0.95 }}
                        >
                            <Paper
                                onClick={() => {
                                    setStatusFilter('all');
                                    handleRefresh();
                                }}
                                sx={{
                                    p: 3,
                                    cursor: 'pointer',
                                    background: `linear-gradient(45deg, ${theme.palette.primary.main}, ${theme.palette.primary.dark})`,
                                    color: 'white',
                                    borderRadius: 4,
                                    minHeight: 160,
                                    display: 'flex',
                                    flexDirection: 'column',
                                    justifyContent: 'center',
                                    alignItems: 'center',
                                    position: 'relative',
                                    overflow: 'hidden',
                                    boxShadow: theme.shadows[5],
                                    '&:hover': {
                                        boxShadow: theme.shadows[15]
                                    }
                                }}
                            >
                                <AssignmentIcon sx={{ fontSize: 40, mb: 2 }} />
                                <Typography variant="h3" sx={{ mb: 1, fontWeight: 'bold' }}>
                                    {stats?.overview?.total || 0}
                                </Typography>
                                <Typography variant="h6">Total Asignaciones</Typography>
                            </Paper>
                        </motion.div>
                    </Grid>

                    <Grid item xs={12} md={3}>
                        <motion.div
                            whileHover={{ scale: 1.05 }}
                            whileTap={{ scale: 0.95 }}
                        >
                            <Paper
                                onClick={() => {
                                    setStatusFilter('completed');
                                    handleRefresh();
                                }}
                                sx={{
                                    p: 3,
                                    cursor: 'pointer',
                                    background: `linear-gradient(45deg, ${theme.palette.success.main}, ${theme.palette.success.dark})`,
                                    color: 'white',
                                    borderRadius: 4,
                                    minHeight: 160,
                                    display: 'flex',
                                    flexDirection: 'column',
                                    justifyContent: 'center',
                                    alignItems: 'center',
                                    position: 'relative',
                                    overflow: 'hidden',
                                    boxShadow: theme.shadows[5],
                                    '&:hover': {
                                        boxShadow: theme.shadows[15]
                                    }
                                }}
                            >
                                <CheckCircle sx={{ fontSize: 40, mb: 2 }} />
                                <Typography variant="h3" sx={{ mb: 1, fontWeight: 'bold' }}>
                                    {stats?.overview?.completed || 0}
                                </Typography>
                                <Typography variant="h6">Completadas</Typography>
                            </Paper>
                        </motion.div>
                    </Grid>

                    <Grid item xs={12} md={3}>
                        <motion.div
                            whileHover={{ scale: 1.05 }}
                            whileTap={{ scale: 0.95 }}
                        >
                            <Paper
                                onClick={() => {
                                    setStatusFilter('pending');
                                    handleRefresh();
                                }}
                                sx={{
                                    p: 3,
                                    cursor: 'pointer',
                                    background: `linear-gradient(45deg, ${theme.palette.warning.main}, ${theme.palette.warning.dark})`,
                                    color: 'white',
                                    borderRadius: 4,
                                    minHeight: 160,
                                    display: 'flex',
                                    flexDirection: 'column',
                                    justifyContent: 'center',
                                    alignItems: 'center',
                                    position: 'relative',
                                    overflow: 'hidden',
                                    boxShadow: theme.shadows[5],
                                    '&:hover': {
                                        boxShadow: theme.shadows[15]
                                    }
                                }}
                            >
                                <Schedule sx={{ fontSize: 40, mb: 2 }} />
                                <Typography variant="h3" sx={{ mb: 1, fontWeight: 'bold' }}>
                                    {stats?.overview?.pending || 0}
                                </Typography>
                                <Typography variant="h6">Pendientes</Typography>
                            </Paper>
                        </motion.div>
                    </Grid>

                    <Grid item xs={12} md={3}>
                        <motion.div
                            whileHover={{ scale: 1.05 }}
                            whileTap={{ scale: 0.95 }}
                        >
                            <Paper
                                onClick={() => {
                                    setStatusFilter('overdue');
                                    handleRefresh();
                                }}
                                sx={{
                                    p: 3,
                                    cursor: 'pointer',
                                    background: `linear-gradient(45deg, ${theme.palette.error.main}, ${theme.palette.error.dark})`,
                                    color: 'white',
                                    borderRadius: 4,
                                    minHeight: 160,
                                    display: 'flex',
                                    flexDirection: 'column',
                                    justifyContent: 'center',
                                    alignItems: 'center',
                                    position: 'relative',
                                    overflow: 'hidden',
                                    boxShadow: theme.shadows[5],
                                    '&:hover': {
                                        boxShadow: theme.shadows[15]
                                    }
                                }}
                            >
                                <Warning sx={{ fontSize: 40, mb: 2 }} />
                                <Typography variant="h3" sx={{ mb: 1, fontWeight: 'bold' }}>
                                    {stats?.overview?.overdue || 0}
                                </Typography>
                                <Typography variant="h6">Vencidas</Typography>
                            </Paper>
                        </motion.div>
                    </Grid>
                </Grid>

                {/* Resto de los controles de filtro */}
                <Paper sx={{ p: 2, mb: 3, borderRadius: 2 }}>
                    <Grid container spacing={2} alignItems="center">
                        <Grid item xs={12} md={4}>
                            <TextField
                                fullWidth
                                size="small"
                                placeholder="Buscar asignaciones..."
                                value={searchTerm}
                                onChange={(e) => setSearchTerm(e.target.value)}
                                InputProps={{
                                    startAdornment: (
                                        <InputAdornment position="start">
                                            <Search color="action" />
                                        </InputAdornment>
                                    ),
                                }}
                            />
                        </Grid>
                        <Grid item xs={12} md={3}>
                            <FormControl fullWidth size="small">
                                <InputLabel>Ordenar por</InputLabel>
                                <Select
                                    value={sortBy}
                                    label="Ordenar por"
                                    onChange={(e) => setSortBy(e.target.value)}
                                >
                                    <MenuItem value="-createdAt">Más recientes</MenuItem>
                                    <MenuItem value="createdAt">Más antiguas</MenuItem>
                                    <MenuItem value="dueDate">Fecha de entrega</MenuItem>
                                    <MenuItem value="-dueDate">Fecha de entrega (desc)</MenuItem>
                                    <MenuItem value="title">Título A-Z</MenuItem>
                                    <MenuItem value="-title">Título Z-A</MenuItem>
                                </Select>
                            </FormControl>
                        </Grid>
                        <Grid item xs={12} md={3}>
                            <FormControl fullWidth size="small">
                                <InputLabel>Docente</InputLabel>
                                <Select
                                    value={teacherFilter}
                                    onChange={(e) => setTeacherFilter(e.target.value)}
                                    label="Docente"
                                >
                                    <MenuItem value="all">Todos los docentes</MenuItem>
                                    {teachers.map((teacher) => (
                                        <MenuItem key={teacher._id} value={teacher._id}>
                                            {`${teacher.nombre} ${teacher.apellidoPaterno} ${teacher.apellidoMaterno}`}
                                        </MenuItem>
                                    ))}
                                </Select>
                            </FormControl>
                        </Grid>
                        <Grid item xs={12} md={2}>
                            <Button
                                fullWidth
                                variant="outlined"
                                onClick={handleRefresh}
                                disabled={isRefreshing}
                                startIcon={<Refresh />}
                            >
                                Actualizar
                            </Button>
                        </Grid>
                    </Grid>
                </Paper>

                {/* Mensajes de error */}
                <AnimatePresence>
                    {error && (
                        <motion.div
                            initial={{ opacity: 0, y: -20 }}
                            animate={{ opacity: 1, y: 0 }}
                            exit={{ opacity: 0, y: -20 }}
                            transition={{ duration: 0.3 }}
                        >
                            <Alert 
                                severity="error" 
                                sx={{ mb: 2 }} 
                                onClose={() => setError('')}
                                variant="filled"
                            >
                                {error}
                            </Alert>
                        </motion.div>
                    )}
                </AnimatePresence>

                {/* Tabla de asignaciones */}
                {loading ? (
                    <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
                        <CircularProgress size={60} />
                    </Box>
                ) : assignments.length === 0 ? (
                    <Paper sx={{ p: 4, textAlign: 'center', borderRadius: 2 }}>
                        <AssignmentIcon sx={{ fontSize: 64, color: 'text.secondary', mb: 2 }} />
                        <Typography variant="h6" color="text.secondary" gutterBottom>
                            No se encontraron asignaciones
                        </Typography>
                        <Typography variant="body2" color="text.secondary">
                            Ajusta los filtros para ver más resultados
                        </Typography>
                    </Paper>
                ) : (
                    <TableContainer component={Paper} sx={{ borderRadius: 2, mb: 3 }}>
                        <Table stickyHeader>
                            <TableHead>
                                <TableRow>
                                    <TableCell sx={{ fontWeight: 'bold' }}>Título</TableCell>
                                    <TableCell sx={{ fontWeight: 'bold' }}>Docente</TableCell>
                                    <TableCell sx={{ fontWeight: 'bold' }}>Estado</TableCell>
                                    <TableCell sx={{ fontWeight: 'bold' }}>Fecha de Entrega</TableCell>
                                    <TableCell sx={{ fontWeight: 'bold' }}>Fecha de Cierre</TableCell>
                                    <TableCell sx={{ fontWeight: 'bold' }}>Acciones</TableCell>
                                </TableRow>
                            </TableHead>
                            <TableBody>
                                {assignments.map((assignment) => {
                                    const isOverdue = assignment.status === 'pending' && new Date(assignment.dueDate) < new Date();
                                    const status = isOverdue ? 'vencido' : assignment.status;
                                    
                                    return (
                                        <TableRow 
                                            key={assignment._id}
                                            hover
                                            sx={{
                                                '&:last-child td, &:last-child th': { border: 0 },
                                                borderLeft: `4px solid ${theme.palette[getStatusColor(status, assignment.dueDate, assignment.closeDate)].main}`
                                            }}
                                        >
                                            <TableCell>
                                                <Typography variant="subtitle2" sx={{ fontWeight: 'medium' }}>
                                                    {assignment.title}
                                                </Typography>
                                                <Typography variant="body2" color="text.secondary" sx={{ 
                                                    display: '-webkit-box',
                                                    WebkitLineClamp: 2,
                                                    WebkitBoxOrient: 'vertical',
                                                    overflow: 'hidden'
                                                }}>
                                                    {assignment.description}
                                                </Typography>
                                            </TableCell>
                                            <TableCell>
                                                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                                    <School sx={{ fontSize: 16, color: 'text.secondary' }} />
                                                    <Box>
                                                        {(() => {
                                                            // Debug logs
                                                            console.log('🔍 TeacherFilter:', teacherFilter);
                                                            console.log('🔍 Assignment assignedTo:', assignment.assignedTo);
                                                            
                                                            // Si hay un filtro de docente específico, mostrar solo ese docente
                                                            if (teacherFilter !== 'all') {
                                                                const selectedTeacher = assignment.assignedTo?.find(teacher => teacher._id === teacherFilter);
                                                                console.log('🔍 Selected teacher found:', selectedTeacher);
                                                                if (selectedTeacher) {
                                                                    return (
                                                                        <>
                                                                            <Typography variant="body2" sx={{ fontWeight: 'medium' }}>
                                                                                {`${selectedTeacher.nombre} ${selectedTeacher.apellidoPaterno} ${selectedTeacher.apellidoMaterno}`}
                                                                            </Typography>
                                                                            <Typography variant="caption" color="text.secondary">
                                                                                {selectedTeacher.email}
                                                                            </Typography>
                                                                        </>
                                                                    );
                                                                }
                                                            }
                                                            
                                                            // Si no hay filtro específico, mostrar el primer docente o todos
                                                            if (assignment.assignedTo && assignment.assignedTo.length > 0) {
                                                                const firstTeacher = assignment.assignedTo[0];
                                                                return (
                                                                    <>
                                                                        <Typography variant="body2" sx={{ fontWeight: 'medium' }}>
                                                                            {`${firstTeacher.nombre} ${firstTeacher.apellidoPaterno} ${firstTeacher.apellidoMaterno}`}
                                                                            {assignment.assignedTo.length > 1 && ` +${assignment.assignedTo.length - 1} más`}
                                                                        </Typography>
                                                                        <Typography variant="caption" color="text.secondary">
                                                                            {firstTeacher.email}
                                                                        </Typography>
                                                                    </>
                                                                );
                                                            }
                                                            
                                                            // Si no hay docentes asignados
                                                            return (
                                                                <>
                                                                    <Typography variant="body2" sx={{ fontWeight: 'medium' }}>
                                                                        Sin asignar
                                                                    </Typography>
                                                                    <Typography variant="caption" color="text.secondary">
                                                                        Sin email
                                                                    </Typography>
                                                                </>
                                                            );
                                                        })()}
                                                    </Box>
                                                </Box>
                                            </TableCell>
                                            <TableCell>
                                                <Chip
                                                    label={getStatusLabel(status, assignment.dueDate, assignment.closeDate)}
                                                    color={getStatusColor(status, assignment.dueDate, assignment.closeDate)}
                                                    size="small"
                                                    sx={{ fontWeight: 'bold' }}
                                                />
                                            </TableCell>
                                            <TableCell>
                                                <Typography variant="body2">
                                                    {formatDateWithTime(assignment.dueDate)}
                                                </Typography>
                                            </TableCell>
                                            <TableCell>
                                                <Typography variant="body2">
                                                    {formatDateWithTime(assignment.closeDate)}
                                                </Typography>
                                            </TableCell>
                                            <TableCell>
                                                <Box sx={{ display: 'flex', gap: 1 }}>
                                                    <Tooltip title="Ver Detalles">
                                                        <IconButton
                                                            size="small"
                                                            onClick={() => {
                                                                setSelectedAssignment(assignment);
                                                                setShowDetailDialog(true);
                                                            }}
                                                            color="primary"
                                                        >
                                                            <Visibility />
                                                        </IconButton>
                                                    </Tooltip>
                                                    
                                                    {assignment.status === 'pending' && (
                                                        <Tooltip title={isOverdue ? "Marcar como Entregado Tarde" : "Marcar como Completado"}>
                                                            <IconButton
                                                                size="small"
                                                                onClick={() => handleCompleteAssignment(assignment._id)}
                                                                color={isOverdue ? "warning" : "success"}
                                                                disabled={actionLoading}
                                                            >
                                                                <Done />
                                                            </IconButton>
                                                        </Tooltip>
                                                    )}
                                                    <Tooltip title="Editar Asignación">
                                                        <IconButton
                                                            size="small"
                                                            onClick={() => handleEditAssignment(assignment)}
                                                            color="info"
                                                        >
                                                            <EditIcon />
                                                        </IconButton>
                                                    </Tooltip>
                                                    
                                                    <Tooltip title="Gestionar Estados de Docentes">
                                                        <IconButton
                                                            size="small"
                                                            onClick={() => handleManageTeacherStates(assignment)}
                                                            color="secondary"
                                                            disabled={actionLoading}
                                                        >
                                                            <PlaylistAddCheck />
                                                        </IconButton>
                                                    </Tooltip>
                                                </Box>
                                            </TableCell>
                                        </TableRow>
                                    );
                                })}
                            </TableBody>
                        </Table>
                    </TableContainer>
                )}

                {/* Paginación */}
                {totalPages > 1 && (
                    <Box display="flex" justifyContent="center" mt={2}>
                        <Button
                            disabled={page === 1}
                            onClick={() => setPage(page - 1)}
                            variant="outlined"
                            sx={{ mr: 2 }}
                        >
                            Anterior
                        </Button>
                        <Typography sx={{ px: 2, py: 1, alignSelf: 'center' }}>
                            Página {page} de {totalPages}
                        </Typography>
                        <Button
                            disabled={page === totalPages}
                            onClick={() => setPage(page + 1)}
                            variant="outlined"
                            sx={{ ml: 2 }}
                        >
                            Siguiente
                        </Button>
                    </Box>
                )}
            </DialogContent>

            {/* Diálogo de detalles de asignación */}
            <Dialog
                open={showDetailDialog}
                onClose={() => setShowDetailDialog(false)}
                maxWidth="md"
                fullWidth
                PaperProps={{
                    sx: {
                        borderRadius: 3,
                        background: `linear-gradient(to bottom, ${theme.palette.background.paper}, ${theme.palette.grey[50]})`
                    }
                }}
            >
                {selectedAssignment && (
                    <>
                        <DialogTitle sx={{ 
                            py: 2,
                            px: 3,
                            background: `linear-gradient(to right, ${theme.palette.primary.dark}, ${theme.palette.primary.main})`,
                            color: 'white',
                            display: 'flex',
                            justifyContent: 'space-between',
                            alignItems: 'center'
                        }}>
                            <Typography variant="h6" sx={{ fontWeight: 'bold' }}>
                                {selectedAssignment.title}
                            </Typography>
                            <IconButton 
                                onClick={() => setShowDetailDialog(false)}
                                sx={{ color: 'white' }}
                            >
                                <Close />
                            </IconButton>
                        </DialogTitle>
                        <DialogContent sx={{ p: 3 }}>
                            <Box mb={2}>
                                <Chip
                                    label={getStatusLabel(selectedAssignment.status, selectedAssignment.dueDate, selectedAssignment.closeDate)}
                                    color={getStatusColor(selectedAssignment.status, selectedAssignment.dueDate, selectedAssignment.closeDate)}
                                    sx={{ 
                                        fontWeight: 'bold',
                                        textTransform: 'uppercase',
                                        letterSpacing: 1
                                    }}
                                />
                            </Box>
                            
                            <Typography variant="body1" paragraph sx={{ 
                                whiteSpace: 'pre-line',
                                lineHeight: 1.6
                            }}>
                                {selectedAssignment.description}
                            </Typography>

                            <Grid container spacing={3}>
                                <Grid item xs={12} md={6}>
                                    <Typography variant="subtitle1" sx={{ 
                                        mb: 2,
                                        fontWeight: 'bold',
                                        color: 'primary.main'
                                    }}>
                                        Información del Docente
                                    </Typography>
                                    <Box sx={{ 
                                        p: 2,
                                        borderRadius: 2,
                                        background: theme.palette.grey[50],
                                        boxShadow: theme.shadows[1]
                                    }}>
                                        <Typography variant="body1" sx={{ mb: 1 }}>
                                            <strong>Docente Asignado:</strong> {selectedAssignment.assignedTo && selectedAssignment.assignedTo.length > 0 ? 
                                                `${selectedAssignment.assignedTo[0].nombre} ${selectedAssignment.assignedTo[0].apellidoPaterno} ${selectedAssignment.assignedTo[0].apellidoMaterno}` :
                                                'Sin asignar'
                                            }
                                        </Typography>
                                        <Typography variant="body1">
                                            <strong>Email:</strong> {selectedAssignment.assignedTo && selectedAssignment.assignedTo.length > 0 ?
                                                selectedAssignment.assignedTo[0].email :
                                                'Sin email'
                                            }
                                        </Typography>
                                    </Box>
                                </Grid>

                                <Grid item xs={12} md={6}>
                                    <Typography variant="subtitle1" sx={{ 
                                        mb: 2,
                                        fontWeight: 'bold',
                                        color: 'primary.main'
                                    }}>
                                        Fechas Importantes
                                    </Typography>
                                    <Box sx={{ 
                                        p: 2,
                                        borderRadius: 2,
                                        background: theme.palette.grey[50],
                                        boxShadow: theme.shadows[1]
                                    }}>
                                        <Typography variant="body2" sx={{ mb: 1 }}>
                                            <strong>Fecha de Entrega:</strong> {formatDateWithTime(selectedAssignment.dueDate)}
                                        </Typography>
                                        <Typography variant="body2" sx={{ mb: 1 }}>
                                            <strong>Fecha de Cierre:</strong> {formatDateWithTime(selectedAssignment.closeDate)}
                                        </Typography>
                                        <Typography variant="body2">
                                            <strong>Creado el:</strong> {formatDate(selectedAssignment.createdAt)}
                                        </Typography>
                                    </Box>
                                </Grid>

                                {selectedAssignment.attachments && selectedAssignment.attachments.length > 0 && (
                                    <Grid item xs={12}>
                                        <Typography variant="subtitle1" sx={{ 
                                            mb: 2,
                                            fontWeight: 'bold',
                                            color: 'primary.main'
                                        }}>
                                            Archivos Adjuntos
                                        </Typography>
                                        <Box sx={{ 
                                            p: 2,
                                            borderRadius: 2,
                                            background: theme.palette.grey[50],
                                            boxShadow: theme.shadows[1]
                                        }}>
                                            <Grid container spacing={1}>
                                                {selectedAssignment.attachments.map((file, index) => (
                                                    <Grid item key={index}>
                                                        <Chip
                                                            icon={<FileDownload />}
                                                            label={file.fileName}
                                                            onClick={() => window.open(`http://localhost:3001/${file.fileUrl}`, '_blank')}
                                                            sx={{ 
                                                                mr: 1, 
                                                                mb: 1,
                                                                cursor: 'pointer',
                                                                '&:hover': {
                                                                    background: theme.palette.primary.light,
                                                                    color: 'white'
                                                                }
                                                            }}
                                                            variant="outlined"
                                                        />
                                                    </Grid>
                                                ))}
                                            </Grid>
                                        </Box>
                                    </Grid>
                                )}
                            </Grid>
                        </DialogContent>
                        <DialogActions sx={{ 
                            p: 2,
                            borderTop: `1px solid ${theme.palette.divider}`
                        }}>
                            {selectedAssignment.status === 'pending' && (
                                <Button
                                    color="success"
                                    variant="contained"
                                    startIcon={<Done />}
                                    onClick={() => handleCompleteAssignment(selectedAssignment._id)}
                                    disabled={actionLoading}
                                    sx={{ mr: 1 }}
                                >
                                    {actionLoading ? 'Completando...' : 'Marcar como Completado'}
                                </Button>
                            )}
                            <Button 
                                onClick={() => setShowDetailDialog(false)}
                                variant="outlined"
                            >
                                Cerrar
                            </Button>
                        </DialogActions>
                    </>
                )}
            </Dialog>

            {/* Diálogo de edición de asignación */}
            <Dialog
                open={showEditDialog}
                onClose={() => setShowEditDialog(false)}
                maxWidth="md"
                fullWidth
                PaperProps={{
                    sx: {
                        borderRadius: 3,
                        background: `linear-gradient(to bottom, ${theme.palette.background.paper}, ${theme.palette.grey[50]})`
                    }
                }}
            >
                {selectedAssignment && (
                    <>
                        <DialogTitle sx={{ 
                            py: 2,
                            px: 3,
                            background: `linear-gradient(to right, ${theme.palette.primary.dark}, ${theme.palette.primary.main})`,
                            color: 'white',
                            display: 'flex',
                            justifyContent: 'space-between',
                            alignItems: 'center'
                        }}>
                            <Typography variant="h6" sx={{ fontWeight: 'bold' }}>
                                Editar Asignación
                            </Typography>
                            <IconButton 
                                onClick={() => setShowEditDialog(false)}
                                sx={{ color: 'white' }}
                            >
                                <Close />
                            </IconButton>
                        </DialogTitle>
                        <DialogContent sx={{ p: 3 }}>
                            <Box mb={2}>
                                <Chip
                                    label={getStatusLabel(selectedAssignment.status, selectedAssignment.dueDate, selectedAssignment.closeDate)}
                                    color={getStatusColor(selectedAssignment.status, selectedAssignment.dueDate, selectedAssignment.closeDate)}
                                    sx={{ 
                                        fontWeight: 'bold',
                                        textTransform: 'uppercase',
                                        letterSpacing: 1
                                    }}
                                />
                            </Box>
                        </DialogContent>
                    </>
                )}
            </Dialog>

            {/* Diálogo de edición de asignación */}
            <EditAssignment 
                open={showEditDialog}
                onClose={() => setShowEditDialog(false)}
                assignment={selectedAssignment}
                onSave={handleSaveAssignment}
                teachers={teachers}
                loading={actionLoading}
            />

            {/* Diálogo de asignaciones programadas */}
            <ScheduledAssignments
                open={showScheduledDialog}
                onClose={() => setShowScheduledDialog(false)}
                teachers={teachers}
            />

            {/* Nuevo diálogo para gestionar estados de docentes */}
            <Dialog
                open={showTeacherStatusDialog}
                onClose={() => setShowTeacherStatusDialog(false)}
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
                    alignItems: 'center'
                }}>
                    <Box display="flex" alignItems="center" gap={1}>
                        <PlaylistAddCheck />
                        <Typography variant="h6">
                            Gestionar Estados de Docentes
                        </Typography>
                    </Box>
                    <IconButton 
                        onClick={() => setShowTeacherStatusDialog(false)}
                        sx={{ color: 'primary.contrastText' }}
                    >
                        <Close />
                    </IconButton>
                </DialogTitle>
                
                <DialogContent sx={{ p: 3 }}>
                    {selectedAssignment && (
                        <>
                            <Typography variant="h6" gutterBottom>
                                {selectedAssignment.title}
                            </Typography>
                            <Typography variant="body2" color="text.secondary" gutterBottom>
                                {selectedAssignment.description}
                            </Typography>
                            
                            <Typography variant="h6" sx={{ mt: 3, mb: 2 }}>
                                Estados de Entrega por Docente
                            </Typography>
                            
                            {assignmentTeachers.length === 0 ? (
                                <Typography variant="body1" color="text.secondary">
                                    {actionLoading ? 'Cargando docentes...' : 'No hay docentes asignados a esta actividad.'}
                                </Typography>
                            ) : (
                                <Grid container spacing={2}>
                                    {assignmentTeachers.map((teacher, index) => (
                                        <Grid item xs={12} key={index}>
                                            <Paper 
                                                elevation={2} 
                                                sx={{ 
                                                    p: 2, 
                                                    borderRadius: 2,
                                                    border: '1px solid',
                                                    borderColor: 'divider'
                                                }}
                                            >
                                                <Box display="flex" justifyContent="space-between" alignItems="center">
                                                    <Box display="flex" alignItems="center" gap={2}>
                                                        <AssignmentInd color="primary" />
                                                        <Box>
                                                            <Typography variant="subtitle1" fontWeight="bold">
                                                                {teacher.nombre} {teacher.apellidoPaterno} {teacher.apellidoMaterno || ''}
                                                            </Typography>
                                                            <Typography variant="body2" color="text.secondary">
                                                                {teacher.email}
                                                            </Typography>
                                                        </Box>
                                                    </Box>
                                                    
                                                    <Box display="flex" alignItems="center" gap={2}>
                                                        <FormControl size="small" sx={{ minWidth: 200 }}>
                                                            <InputLabel>Seleccionar Estado</InputLabel>
                                                            <Select
                                                                value={teacher.status || 'pending'}
                                                                label="Seleccionar Estado"
                                                                onChange={(e) => handleUpdateTeacherStatus(teacher._id || teacher.teacherId, e.target.value)}
                                                                disabled={actionLoading}
                                                            >
                                                                <MenuItem value="completed">
                                                                    <Box display="flex" alignItems="center" gap={1}>
                                                                        <Chip 
                                                                            size="small" 
                                                                            label="Entregado" 
                                                                            sx={{ 
                                                                                backgroundColor: '#4caf50', 
                                                                                color: 'white',
                                                                                minWidth: 80
                                                                            }} 
                                                                        />
                                                                    </Box>
                                                                </MenuItem>
                                                                <MenuItem value="completed-late">
                                                                    <Box display="flex" alignItems="center" gap={1}>
                                                                        <Chip 
                                                                            size="small" 
                                                                            label="Entregado con Retraso" 
                                                                            sx={{ 
                                                                                backgroundColor: '#ff9800', 
                                                                                color: 'white',
                                                                                minWidth: 80
                                                                            }} 
                                                                        />
                                                                    </Box>
                                                                </MenuItem>
                                                                <MenuItem value="not-delivered">
                                                                    <Box display="flex" alignItems="center" gap={1}>
                                                                        <Chip 
                                                                            size="small" 
                                                                            label="No Entregado" 
                                                                            sx={{ 
                                                                                backgroundColor: '#f44336', 
                                                                                color: 'white',
                                                                                minWidth: 80
                                                                            }} 
                                                                        />
                                                                    </Box>
                                                                </MenuItem>
                                                                <MenuItem value="pending">
                                                                    <Box display="flex" alignItems="center" gap={1}>
                                                                        <Chip 
                                                                            size="small" 
                                                                            label="Pendiente" 
                                                                            sx={{ 
                                                                                backgroundColor: '#795548', 
                                                                                color: 'white',
                                                                                minWidth: 80
                                                                            }} 
                                                                        />
                                                                    </Box>
                                                                </MenuItem>
                                                            </Select>
                                                        </FormControl>
                                                        
                                                        {/* Mostrar estado actual */}
                                                        <Box>
                                                            {teacher.status === 'completed' && (
                                                                <Chip 
                                                                    size="small" 
                                                                    label="Entregado" 
                                                                    sx={{ backgroundColor: '#4caf50', color: 'white' }} 
                                                                />
                                                            )}
                                                            {teacher.status === 'completed-late' && (
                                                                <Chip 
                                                                    size="small" 
                                                                    label="Entregado con Retraso" 
                                                                    sx={{ backgroundColor: '#ff9800', color: 'white' }} 
                                                                />
                                                            )}
                                                            {teacher.status === 'not-delivered' && (
                                                                <Chip 
                                                                    size="small" 
                                                                    label="No Entregado" 
                                                                    sx={{ backgroundColor: '#f44336', color: 'white' }} 
                                                                />
                                                            )}
                                                            {(!teacher.status || teacher.status === 'pending') && (
                                                                <Chip 
                                                                    size="small" 
                                                                    label="Pendiente" 
                                                                    sx={{ backgroundColor: '#795548', color: 'white' }} 
                                                                />
                                                            )}
                                                        </Box>
                                                    </Box>
                                                </Box>
                                            </Paper>
                                        </Grid>
                                    ))}
                                </Grid>
                            )}
                        </>
                    )}
                </DialogContent>
                
                <DialogActions sx={{ p: 2 }}>
                    <Button 
                        onClick={() => setShowTeacherStatusDialog(false)}
                        variant="outlined"
                    >
                        Cerrar
                    </Button>
                </DialogActions>
            </Dialog>
        </Dialog>
    );
};
export default AdminAssignments;