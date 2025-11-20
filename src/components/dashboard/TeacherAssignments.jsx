import React, { useState, useEffect } from 'react';
import {
    Box,
    Paper,
    Typography,
    Button,
    Card,
    CardContent,
    CardActions,
    Chip,
    Grid,
    Divider,
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
    Zoom,
    Fade,
    Grow,
    Slide,
    Skeleton,
    Table,
    TableBody,
    TableCell,
    TableHead,
    TableRow,
    TableContainer
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
    Close,
    CalendarToday,
    ExpandMore,
    ExpandLess,
    FileDownload,
    Person
} from '@mui/icons-material';
import { motion, AnimatePresence } from 'framer-motion';
import { useTheme } from '@mui/material/styles';
import { getTeacherAssignmentStats, getTeacherAssignments, getAllTeachersStats } from '../../services/assignmentService';
import { formatDistanceToNow } from 'date-fns';
import { es } from 'date-fns/locale';

// Custom animated components
const AnimatedCard = motion.create(Card);
const AnimatedBadge = motion.create(Badge);
const AnimatedButton = motion.create(Button);

const TeacherAssignments = () => {
    const theme = useTheme();
    // Estados principales
    const [assignments, setAssignments] = useState([]);
    const [stats, setStats] = useState(null);
    const [allTeachersStats, setAllTeachersStats] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    
    // Estados para filtros
    const [statusFilter, setStatusFilter] = useState('all');
    const [searchTerm, setSearchTerm] = useState('');
    const [sortBy, setSortBy] = useState('-createdAt');
    const [expandedFilters, setExpandedFilters] = useState(false);
    
    // Estados para paginación
    const [page, setPage] = useState(1);
    const [totalPages, setTotalPages] = useState(1);
    
    // Estados para diálogos
    const [selectedAssignment, setSelectedAssignment] = useState(null);
    const [showDetailDialog, setShowDetailDialog] = useState(false);
    const [isRefreshing, setIsRefreshing] = useState(false);

    // Load stats on mount - optimized
    useEffect(() => {
        const loadInitialData = async () => {
            try {
                await Promise.all([
                    loadStats(),
                    loadAssignments(),
                    // loadAllTeachersStats() // Comentado temporalmente para mejorar rendimiento
                ]);
            } catch (error) {
                console.error('Error loading initial data:', error);
            }
        };
        loadInitialData();
    }, []);

    // Load assignments when filters change (debounced)
    useEffect(() => {
        const delayedLoad = setTimeout(() => {
            loadAssignments();
        }, 300); // 300ms delay para evitar múltiples requests

        return () => clearTimeout(delayedLoad);
    }, [statusFilter, searchTerm, sortBy, page]);

    const loadStats = async () => {
        try {
            const response = await getTeacherAssignmentStats();
            if (response.success) {
                setStats(response.stats);
            }
        } catch (error) {
            console.error('Error loading stats:', error);
        }
    };

    const loadAssignments = async () => {
        try {
            setLoading(true);
            setError('');
            
            const params = {
                status: statusFilter,
                search: searchTerm,
                sort: sortBy,
                page: page,
                limit: 6
            };

            const response = await getTeacherAssignments(params);
            
            if (response.success) {
                setAssignments(response.assignments || []);
                setTotalPages(response.pagination?.totalPages || 1);
            } else {
                setError('Server response was not successful');
            }
        } catch (error) {
            console.error('Error loading assignments:', error);
            setError('Error loading assignments: ' + (error.message || 'Unknown error'));
        } finally {
            setLoading(false);
            setIsRefreshing(false);
        }
    };

    const loadAllTeachersStats = async () => {
        try {
            const response = await getAllTeachersStats();
            if (response.success) {
                setAllTeachersStats(response.stats);
            }
        } catch (error) {
            console.error('Error loading all teachers stats:', error);
        }
    };

    const handleRefresh = () => {
        setIsRefreshing(true);
        loadAssignments();
        loadStats();
        loadAllTeachersStats();
    };

    const getStatusColor = (assignment) => {
        // Si el admin ha actualizado el estado específico del docente, usar esa información
        if (assignment.teacherStatus && assignment.teacherStatus.adminUpdated) {
            const { submissionStatus } = assignment.teacherStatus;
            switch (submissionStatus) {
                case 'on-time':
                    return 'success';  // Verde - Entregado a tiempo
                case 'late':
                    return 'warning';  // Naranja - Entregado con retraso
                case 'closed':
                    return 'error';    // Rojo - No entregado
                default:
                    return 'default';  // Gris/Marrón - Pendiente
            }
        }
        
        // Lógica original si no hay estado específico del admin
        const { status, dueDate, closeDate } = assignment;
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

    const getStatusLabel = (assignment) => {
        // Si el admin ha actualizado el estado específico del docente, usar esa información
        if (assignment.teacherStatus && assignment.teacherStatus.adminUpdated) {
            const { submissionStatus } = assignment.teacherStatus;
            switch (submissionStatus) {
                case 'on-time':
                    return 'Entregado';
                case 'late':
                    return 'Entregado con Retraso';
                case 'closed':
                    return 'No Entregado';
                default:
                    return 'Pendiente';
            }
        }
        
        // Lógica original si no hay estado específico del admin
        const { status, dueDate, closeDate } = assignment;
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

    const formatTimeRemaining = (dueDate, closeDate) => {
        try {
            if (!dueDate || !closeDate) return 'Fechas inválidas';
            
            const now = new Date();
            const due = new Date(dueDate);
            const close = new Date(closeDate);
            
            if (isNaN(due.getTime())) return 'Fecha inválida';
            
            if (now > close) return 'Cerrado - No se puede entregar';
            if (now > due) {
                const diffTime = close - now;
                const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
                if (diffDays < 0) return 'Cerrado';
                if (diffDays === 0) return 'Cierra hoy - Entrega tarde!';
                return `${diffDays} días hasta el cierre - Entrega tarde`;
            }
            
            return formatDistanceToNow(due, { 
                addSuffix: true, 
                locale: es 
            });
        } catch (error) {
            console.error('Error calculating time remaining:', error);
            return 'Error de fecha';
        }
    };

    // Animation variants
    const cardVariants = {
        hidden: { opacity: 0, y: 20 },
        visible: { 
            opacity: 1, 
            y: 0,
            transition: {
                duration: 0.4,
                ease: "easeOut"
            }
        }
    };

    const statsVariants = {
        hover: {
            y: -5,
            transition: {
                duration: 0.2,
                ease: "easeOut"
            }
        }
    };

    if (loading && assignments.length === 0) {
        return (
            <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
                <motion.div
                    animate={{ rotate: 360 }}
                    transition={{ duration: 2, repeat: Infinity, ease: "linear" }}
                >
                    <CircularProgress thickness={3} size={60} />
                </motion.div>
            </Box>
        );
    }

    return (
        <Box sx={{ p: 3 }}>
            {/* Estadísticas de todos los profesores - Temporalmente comentado para mejorar rendimiento */}
            {allTeachersStats.length > 0 && (
                <Paper sx={{ mb: 3, p: 2 }}>
                    <Typography variant="h6" gutterBottom>
                        Estadísticas de Docentes
                    </Typography>
                    <TableContainer>
                        <Table>
                            <TableHead>
                                <TableRow>
                                    <TableCell>Docente</TableCell>
                                    <TableCell align="center">Completadas</TableCell>
                                    <TableCell align="center">Pendientes</TableCell>
                                    <TableCell align="center">Vencidas</TableCell>
                                    <TableCell align="center">Total</TableCell>
                                    <TableCell align="center">Última Actualización</TableCell>
                                </TableRow>
                            </TableHead>
                            <TableBody>
                                {allTeachersStats.map((teacherStat) => (
                                    <TableRow key={teacherStat.teacherId}>
                                        <TableCell>
                                            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                                <Person />
                                                <Typography>{teacherStat.teacherName}</Typography>
                                            </Box>
                                        </TableCell>
                                        <TableCell align="center">
                                            <Chip 
                                                label={teacherStat.stats?.completed || 0}
                                                color="success"
                                                size="small"
                                            />
                                        </TableCell>
                                        <TableCell align="center">
                                            <Chip 
                                                label={teacherStat.stats?.pending || 0}
                                                color="primary"
                                                size="small"
                                            />
                                        </TableCell>
                                        <TableCell align="center">
                                            <Chip 
                                                label={teacherStat.stats?.overdue || 0}
                                                color="error"
                                                size="small"
                                            />
                                        </TableCell>
                                        <TableCell align="center">
                                            <Chip 
                                                label={teacherStat.stats?.total || 0}
                                                color="default"
                                                size="small"
                                            />
                                        </TableCell>
                                        <TableCell align="center">
                                            {teacherStat.lastUpdated ? new Date(teacherStat.lastUpdated).toLocaleString() : 'N/A'}
                                        </TableCell>
                                    </TableRow>
                                ))}
                            </TableBody>
                        </Table>
                    </TableContainer>
                </Paper>
            )}

            {/* Stats cards with animations */}
            {stats && (
                <Grid container spacing={2} sx={{ mb: 3 }}>
                    {[
                        {
                            icon: <AssignmentIcon sx={{ fontSize: 40 }} />,
                            value: stats.total,
                            label: 'Total',
                            color: 'primary',
                            filterValue: 'all'
                        },
                        {
                            icon: <Schedule sx={{ fontSize: 40 }} />,
                            value: stats.pending,
                            label: 'Pendiente',
                            color: 'warning',
                            filterValue: 'pending'
                        },
                        {
                            icon: <CheckCircle sx={{ fontSize: 40 }} />,
                            value: stats.completed,
                            label: 'Completado',
                            color: 'success',
                            filterValue: 'completed'
                        },
                        {
                            icon: <Warning sx={{ fontSize: 40 }} />,
                            value: stats.overdue,
                            label: 'No Entregado',
                            color: 'error',
                            filterValue: 'not-delivered'
                        }
                    ].map((stat, index) => (
                        <Grid item xs={6} sm={3} key={index}>
                            <motion.div
                                initial="hidden"
                                animate="visible"
                                variants={{
                                    hidden: { opacity: 0, y: 20 },
                                    visible: { 
                                        opacity: 1, 
                                        y: 0,
                                        transition: {
                                            delay: index * 0.1,
                                            duration: 0.5
                                        }
                                    },
                                    hover: {
                                        y: -5,
                                        transition: {
                                            duration: 0.2,
                                            ease: "easeOut"
                                        }
                                    }
                                }}
                                whileHover="hover"
                            >
                                <Card 
                                    onClick={() => {
                                        setStatusFilter(stat.filterValue);
                                        setPage(1);
                                    }}
                                    sx={{ 
                                        height: '100%', 
                                        borderRadius: 3,
                                        boxShadow: theme.shadows[4],
                                        background: `linear-gradient(135deg, ${theme.palette.background.paper} 0%, ${theme.palette.grey[100]} 100%)`,
                                        cursor: 'pointer',
                                        border: statusFilter === stat.filterValue ? `2px solid ${theme.palette[stat.color].main}` : 'none'
                                    }}
                                >
                                    <CardContent sx={{ 
                                        textAlign: 'center', 
                                        py: 3,
                                        position: 'relative',
                                        overflow: 'hidden'
                                    }}>
                                        <Box sx={{
                                            position: 'absolute',
                                            top: -20,
                                            right: -20,
                                            width: 80,
                                            height: 80,
                                            borderRadius: '50%',
                                            background: theme.palette[stat.color].light,
                                            opacity: 0.2
                                        }} />
                                        <AnimatedBadge 
                                            badgeContent={stat.value} 
                                            color={stat.color} 
                                            max={999}
                                            animate={{
                                                scale: [1, 1.1, 1]
                                            }}
                                            transition={{
                                                duration: 1.5,
                                                repeat: Infinity,
                                                repeatType: "reverse"
                                            }}
                                        >
                                            {React.cloneElement(stat.icon, { 
                                                color: stat.color,
                                                sx: { 
                                                    fontSize: 40,
                                                    filter: `drop-shadow(0 2px 4px ${theme.palette[stat.color].light})`
                                                }
                                            })}
                                        </AnimatedBadge>
                                        <Typography variant="h4" sx={{ 
                                            mt: 1,
                                            fontWeight: 'bold',
                                            background: `linear-gradient(to right, ${theme.palette[stat.color].main}, ${theme.palette[stat.color].dark})`,
                                            WebkitBackgroundClip: 'text',
                                            WebkitTextFillColor: 'transparent'
                                        }}>
                                            {stat.value}
                                        </Typography>
                                        <Typography variant="body2" color="text.secondary" sx={{ 
                                            mt: 1,
                                            textTransform: 'uppercase',
                                            letterSpacing: 1,
                                            fontWeight: 'medium'
                                        }}>
                                            {stat.label}
                                        </Typography>
                                    </CardContent>
                                </Card>
                            </motion.div>
                        </Grid>
                    ))}
                </Grid>
            )}

            {/* Error message with animation */}
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

            {/* Assignments table */}
            {assignments.length === 0 ? (
                <motion.div
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ duration: 0.5 }}
                >
                    <Paper sx={{ 
                        p: 4, 
                        textAlign: 'center',
                        borderRadius: 3,
                        background: `linear-gradient(to bottom right, ${theme.palette.background.paper}, ${theme.palette.grey[50]})`
                    }}>
                        <motion.div
                            animate={{
                                y: [0, -10, 0],
                            }}
                            transition={{
                                duration: 3,
                                repeat: Infinity,
                                ease: "easeInOut"
                            }}
                        >
                            <AssignmentIcon sx={{ 
                                fontSize: 64, 
                                color: 'text.secondary', 
                                mb: 2,
                                filter: 'drop-shadow(0 4px 8px rgba(0,0,0,0.1))'
                            }} />
                        </motion.div>
                        <Typography variant="h5" color="text.secondary" gutterBottom>
                            No se encontraron asignaciones
                        </Typography>
                        <Typography variant="body1" color="text.secondary">
                            Cuando tengas asignaciones, aparecerán aquí
                        </Typography>
                        <Button 
                            variant="outlined" 
                            sx={{ mt: 2 }}
                            onClick={handleRefresh}
                            startIcon={<Refresh />}
                        >
                            Actualizar
                        </Button>
                    </Paper>
                </motion.div>
            ) : (
                <Paper sx={{ width: '100%', overflow: 'hidden', borderRadius: 2, mb: 3 }}>
                    <Table stickyHeader>
                        <TableHead>
                            <TableRow>
                                <TableCell sx={{ fontWeight: 'bold' }}>Título</TableCell>
                                <TableCell sx={{ fontWeight: 'bold' }}>Estado</TableCell>
                                <TableCell sx={{ fontWeight: 'bold' }}>Fecha de Entrega</TableCell>
                                <TableCell sx={{ fontWeight: 'bold' }}>Fecha de Cierre</TableCell>
                                <TableCell sx={{ fontWeight: 'bold' }}>Creado por</TableCell>
                                <TableCell sx={{ fontWeight: 'bold' }}>Acciones</TableCell>
                            </TableRow>
                        </TableHead>
                        <TableBody>
                            {assignments.map((assignment) => {
                                const isOverdue = assignment.status === 'pending' && new Date(assignment.dueDate) < new Date();
                                
                                return (
                                    <TableRow 
                                        key={assignment._id}
                                        hover
                                        sx={{
                                            '&:last-child td, &:last-child th': { border: 0 },
                                            borderLeft: `4px solid ${theme.palette[getStatusColor(assignment)].main}`
                                        }}
                                    >
                                        <TableCell>
                                            <Typography variant="subtitle1" sx={{ fontWeight: 'medium' }}>
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
                                            <Chip
                                                label={getStatusLabel(assignment)}
                                                color={getStatusColor(assignment)}
                                                size="small"
                                                sx={{ fontWeight: 'bold' }}
                                            />
                                        </TableCell>
                                        <TableCell>
                                            <Box>
                                                <Typography variant="body2">
                                                    {formatDateWithTime(assignment.dueDate)}
                                                </Typography>
                                                {assignment.status === 'pending' && (
                                                    <Typography variant="caption" color={isOverdue ? 'error' : 'warning.main'}>
                                                        {formatTimeRemaining(assignment.dueDate, assignment.closeDate)}
                                                    </Typography>
                                                )}
                                            </Box>
                                        </TableCell>
                                        <TableCell>
                                            {formatDateWithTime(assignment.closeDate)}
                                        </TableCell>
                                        <TableCell>
                                            {assignment.createdBy?.nombre} {assignment.createdBy?.apellidoPaterno} {assignment.createdBy?.apellidoMaterno}
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
                                            </Box>
                                        </TableCell>
                                    </TableRow>
                                );
                            })}
                        </TableBody>
                    </Table>
                </Paper>
            )}

            {/* Pagination with animation */}
            {totalPages > 1 && (
                <motion.div
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ delay: 0.3 }}
                >
                    <Box display="flex" justifyContent="center" mt={4} mb={2}>
                        <AnimatedButton
                            disabled={page === 1}
                            onClick={() => setPage(page - 1)}
                            variant="outlined"
                            sx={{ mr: 2 }}
                            whileHover={{ 
                                backgroundColor: theme.palette.primary.light,
                                color: theme.palette.primary.contrastText
                            }}
                        >
                            Anterior
                        </AnimatedButton>
                        <Box sx={{ 
                            display: 'flex', 
                            alignItems: 'center',
                            mx: 2 
                        }}>
                            {Array.from({ length: totalPages }, (_, i) => i + 1).map((pageNum) => (
                                <motion.div
                                    key={pageNum}
                                    whileHover={{ scale: 1.1 }}
                                    whileTap={{ scale: 0.9 }}
                                >
                                    <Button
                                        onClick={() => setPage(pageNum)}
                                        variant={pageNum === page ? "contained" : "text"}
                                        sx={{ 
                                            minWidth: 36,
                                            height: 36,
                                            borderRadius: '50%',
                                            mx: 0.5,
                                            ...(pageNum === page && {
                                                background: `linear-gradient(45deg, ${theme.palette.primary.main} 0%, ${theme.palette.primary.dark} 100%)`,
                                                color: 'white'
                                            })
                                        }}
                                    >
                                        {pageNum}
                                    </Button>
                                </motion.div>
                            ))}
                        </Box>
                        <AnimatedButton
                            disabled={page === totalPages}
                            onClick={() => setPage(page + 1)}
                            variant="outlined"
                            sx={{ ml: 2 }}
                            whileHover={{ 
                                backgroundColor: theme.palette.primary.light,
                                color: theme.palette.primary.contrastText
                            }}
                        >
                            Siguiente
                        </AnimatedButton>
                    </Box>
                </motion.div>
            )}

            {/* Assignment detail dialog with animations */}
            <Dialog
                open={showDetailDialog}
                onClose={() => setShowDetailDialog(false)}
                maxWidth="md"
                fullWidth
                TransitionComponent={Slide}
                transitionDuration={300}
                PaperProps={{
                    sx: {
                        borderRadius: 3,
                        background: `linear-gradient(to bottom, ${theme.palette.background.paper}, ${theme.palette.grey[50]})`
                    }
                }}
            >
                {selectedAssignment && (
                    <motion.div
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        transition={{ duration: 0.3 }}
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
                            <Typography variant="h5" sx={{ fontWeight: 'bold' }}>
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
                                <motion.div whileHover={{ scale: 1.05 }}>
                                    <Chip
                                        label={getStatusLabel(selectedAssignment)}
                                        color={getStatusColor(selectedAssignment)}
                                        sx={{ 
                                            fontWeight: 'bold',
                                            textTransform: 'uppercase',
                                            letterSpacing: 1
                                        }}
                                    />
                                </motion.div>
                            </Box>
                            
                            <Typography variant="body1" paragraph sx={{ 
                                whiteSpace: 'pre-line',
                                lineHeight: 1.6
                            }}>
                                {selectedAssignment.description}
                            </Typography>

                            <Divider sx={{ my: 3 }} />

                            <Grid container spacing={3}>
                                <Grid item xs={12} md={6}>
                                    <Typography variant="subtitle1" sx={{ 
                                        mb: 2,
                                        fontWeight: 'bold',
                                        color: 'primary.main'
                                    }}>
                                        Detalles de la Asignación
                                    </Typography>
                                    
                                    <Box sx={{ 
                                        p: 2,
                                        borderRadius: 2,
                                        background: theme.palette.grey[50],
                                        boxShadow: theme.shadows[1]
                                    }}>
                                        <Box display="flex" alignItems="center" mb={2}>
                                            <CalendarToday sx={{ 
                                                mr: 2,
                                                color: 'text.secondary' 
                                            }} />
                                            <Box>
                                                <Typography variant="caption" color="text.secondary">
                                                    Fecha de Entrega
                                                </Typography>
                                                <Typography variant="body1">
                                                    {formatDateWithTime(selectedAssignment.dueDate)}
                                                </Typography>
                                            </Box>
                                        </Box>
                                        
                                        <Box display="flex" alignItems="center" mb={2}>
                                            <CalendarToday sx={{ 
                                                mr: 2,
                                                color: 'error.main' 
                                            }} />
                                            <Box>
                                                <Typography variant="caption" color="text.secondary">
                                                    Fecha de Cierre
                                                </Typography>
                                                <Typography variant="body1">
                                                    {formatDateWithTime(selectedAssignment.closeDate)}
                                                </Typography>
                                            </Box>
                                        </Box>
                                        
                                        <Box display="flex" alignItems="center">
                                            <AssignmentIcon sx={{ 
                                                mr: 2,
                                                color: 'text.secondary' 
                                            }} />
                                            <Box>
                                                <Typography variant="caption" color="text.secondary">
                                                    Creado el
                                                </Typography>
                                                <Typography variant="body1">
                                                    {formatDate(selectedAssignment.createdAt)}
                                                </Typography>
                                            </Box>
                                        </Box>
                                    </Box>
                                </Grid>
                                
                                <Grid item xs={12} md={6}>
                                    <Typography variant="subtitle1" sx={{ 
                                        mb: 2,
                                        fontWeight: 'bold',
                                        color: 'primary.main'
                                    }}>
                                        Información del Creador
                                    </Typography>
                                    
                                    <Box sx={{ 
                                        p: 2,
                                        borderRadius: 2,
                                        background: theme.palette.grey[50],
                                        boxShadow: theme.shadows[1]
                                    }}>
                                        <Typography variant="body1" sx={{ mb: 1 }}>
                                            <strong>Nombre:</strong> {selectedAssignment.createdBy?.nombre} {selectedAssignment.createdBy?.apellidoPaterno} {selectedAssignment.createdBy?.apellidoMaterno}
                                        </Typography>
                                        
                                        {selectedAssignment.completedAt && (
                                            <Box sx={{ 
                                                mt: 2,
                                                p: 1.5,
                                                borderRadius: 1,
                                                background: theme.palette.success.light,
                                                borderLeft: `4px solid ${theme.palette.success.main}`
                                            }}>
                                                <Typography variant="body2" sx={{ 
                                                    display: 'flex',
                                                    alignItems: 'center',
                                                    color: 'success.dark'
                                                }}>
                                                    <CheckCircle sx={{ mr: 1 }} />
                                                    <strong>Completado el:</strong> {formatDate(selectedAssignment.completedAt)}
                                                </Typography>
                                            </Box>
                                        )}
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
                                                        <motion.div whileHover={{ scale: 1.05 }}>
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
                                                        </motion.div>
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
                            <AnimatedButton 
                                onClick={() => setShowDetailDialog(false)}
                                variant="outlined"
                                whileHover={{ 
                                    backgroundColor: theme.palette.grey[300],
                                }}
                            >
                                Cerrar
                            </AnimatedButton>
                        </DialogActions>
                    </motion.div>
                )}
            </Dialog>
        </Box>
    );
};

export default TeacherAssignments;