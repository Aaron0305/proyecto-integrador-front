import React from 'react';
import Calendar from 'react-calendar';
import 'react-calendar/dist/Calendar.css';
import {
  Box,
  Paper,
  Typography,
  Grid,
  Card,
  CardContent,
  IconButton,
  Button,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Fade,
  Grow,
  styled,
  Modal,
  Chip,
  Divider,
  useTheme
} from '@mui/material';
import {
import { 
  ArrowBack, 
  Event, 
  Description, 
  AttachFile,
  PlayCircleFilled,
  CheckCircle,
  Today
} from '@mui/icons-material';
import { getAssetUrl } from '../../config/api';

// Estilos personalizados
const StyledCalendarContainer = styled(Paper)(() => ({
  padding: '16px',
  borderRadius: '16px',
  boxShadow: '0 4px 20px rgba(0,0,0,0.1)',
  '.react-calendar': {
    border: 'none',
    width: '100%',
    background: 'transparent',
    fontFamily: '"Segoe UI", "Roboto", "Helvetica", "Arial", sans-serif',
    borderRadius: '8px',
    '& button': {
      margin: '4px',
      borderRadius: '8px',
      transition: 'all 0.2s ease',
      '&:hover': {
        background: '#e3f2fd',
        color: '#1976d2',
      }
    }
  }
}));

// Estilos personalizados para la tabla
const StyledTableContainer = styled(TableContainer)(({ theme }) => ({
  marginTop: theme.spacing(3),
  borderRadius: '16px',
  boxShadow: '0 4px 20px rgba(0,0,0,0.1)',
  '& .MuiTable-root': {
    borderCollapse: 'separate',
    borderSpacing: '0 8px'
  }
}));

const StyledTableCell = styled(TableCell)(({ theme }) => ({
  borderBottom: 'none',
  padding: theme.spacing(2),
  '&.header': {
    backgroundColor: theme.palette.primary.main,
    color: theme.palette.common.white,
    fontWeight: 600,
    fontSize: '0.95rem'
  }
}));

const StyledTableRow = styled(TableRow)(({ theme }) => ({
  backgroundColor: theme.palette.background.paper,
  '&:hover': {
    backgroundColor: theme.palette.action.hover,
    transform: 'scale(1.005)',
    transition: 'transform 0.2s ease'
  },
  '& > td': {
    borderBottom: `1px solid ${theme.palette.divider}`,
    '&:first-of-type': {
      borderTopLeftRadius: '8px',
      borderBottomLeftRadius: '8px'
    },
    '&:last-of-type': {
      borderTopRightRadius: '8px',
      borderBottomRightRadius: '8px'
    }
  }
}));

const EvidenceCard = styled(Card)(() => ({
  transition: 'all 0.3s ease',
  '&:hover': {
    transform: 'translateY(-4px)',
    boxShadow: '0 8px 24px rgba(0,0,0,0.15)',
  }
}));

const ActivityCard = styled(Box)(({ theme }) => ({
  padding: theme.spacing(2),
  borderRadius: '12px',
  backgroundColor: theme.palette.background.default,
  border: `1px solid ${theme.palette.divider}`,
  '&:hover': {
    boxShadow: theme.shadows[4],
    borderColor: theme.palette.primary.light
  }
}));

const StyledModal = styled('div')(({ theme }) => ({
  position: 'absolute',
  top: '50%',
  left: '50%',
  transform: 'translate(-50%, -50%)',
  width: '90%',
  maxWidth: 800,
  maxHeight: '90vh',
  overflow: 'auto',
  backgroundColor: theme.palette.background.paper,
  borderRadius: '16px',
  boxShadow: theme.shadows[5],
  padding: theme.spacing(4),
  outline: 'none'
}));

const DetailHeader = styled(Box)(({ theme }) => ({
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'space-between',
  marginBottom: theme.spacing(3),
  padding: theme.spacing(2),
  borderRadius: '12px',
  backgroundColor: theme.palette.primary.main,
  color: theme.palette.common.white,
  position: 'sticky',
  top: 0,
  zIndex: 1
}));

const DetailContent = styled(Box)(({ theme }) => ({
  padding: theme.spacing(2),
  backgroundColor: theme.palette.background.default,
  borderRadius: '12px',
  '& > *:not(:last-child)': {
    marginBottom: theme.spacing(3)
  }
}));

const ActivityDetails = ({ registro }) => {
  return (
    <ActivityCard>
      <Typography variant="subtitle1" fontWeight="bold" gutterBottom>
        Título de la Actividad
      </Typography>
      <Typography variant="body2" sx={{ whiteSpace: 'pre-wrap', mb: 2 }}>
        {registro.titulo}
      </Typography>
      <Box sx={{ mb: 2 }}>
        <Typography variant="subtitle1" fontWeight="bold" gutterBottom>
          Actividades Realizadas
        </Typography>
        <Typography variant="body2" sx={{ whiteSpace: 'pre-wrap' }}>
          {registro.descripcion?.split('\n').map((linea, index) => (
            <Box key={index} sx={{ mb: 1 }}>
              • {linea}
            </Box>
          ))}
        </Typography>
      </Box>

      {registro.observaciones && (
        <Box sx={{ mb: 2 }}>
          <Typography variant="subtitle1" fontWeight="bold" color="secondary" gutterBottom>
            Observaciones
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ whiteSpace: 'pre-wrap' }}>
            {registro.observaciones?.split('\n').map((linea, index) => (
              <Box key={index} sx={{ mb: 1 }}>
                ◦ {linea}
              </Box>
            ))}
          </Typography>
        </Box>
      )}

      {registro.evidencias?.length > 0 && (
        <Box>
          <Typography variant="subtitle1" fontWeight="bold" gutterBottom>
            Evidencias Adjuntas
          </Typography>
          <Grid container spacing={1}>
            {registro.evidencias.map((evidencia, index) => (
              <Grid item key={index}>
                <Button
                  variant="outlined"
                  size="small"
                  startIcon={<AttachFile />}
                  href={getAssetUrl(evidencia.url)}
                  target="_blank"
                  sx={{
                    borderRadius: '20px',
                    textTransform: 'none',
                    '&:hover': {
                      backgroundColor: 'rgba(25, 118, 210, 0.08)'
                    }
                  }}
                >
                  {evidencia.nombre}
                </Button>
              </Grid>
            ))}
          </Grid>
        </Box>
      )}
    </ActivityCard>
  );
};

const SessionHistory = ({
  handleFechaSeleccionada,
  fechaSeleccionada,
  tileClassName,
  mostrarTabla,
  registrosHistorial,
  totalHoras,
  mostrarDetalle,
  volverATabla,
  formatearFecha,
  registroSeleccionado,
  getFileIcon
}) => {
  return (
    <Box sx={{ p: 3 }}>
      <Fade in={mostrarTabla}>
        <Box sx={{ display: mostrarTabla ? 'block' : 'none' }}>
          <StyledCalendarContainer elevation={3}>
            <Calendar
              onChange={handleFechaSeleccionada}
              value={fechaSeleccionada}
              locale="es"
              formatShortWeekday={(locale, date) => 
                ['D', 'L', 'M', 'M', 'J', 'V', 'S'][date.getDay()]
              }
              formatMonthYear={(locale, date) => {
                const months = [
                  'Enero', 'Febrero', 'Marzo', 'Abril', 'Mayo', 'Junio',
                  'Julio', 'Agosto', 'Septiembre', 'Octubre', 'Noviembre', 'Diciembre'
                ];
                return `${months[date.getMonth()]} ${date.getFullYear()}`;
              }}
              tileClassName={tileClassName}
            />
              <div className="calendar-legend">
                <div className="legend-item">
                  <div className="legend-marker registro">
                    <Today sx={{ color: '#1976d2', fontSize: 20 }} />
                  </div>
                  <span>Días con registro</span>
                </div>
                <div className="legend-item">
                  <div className="legend-marker inicio">
                    <PlayCircleFilled sx={{ color: '#4caf50', fontSize: 20 }} />
                  </div>
                  <span>Inicio del servicio</span>
                </div>
                <div className="legend-item">
                  <div className="legend-marker fin">
                    <CheckCircle sx={{ color: '#e91e63', fontSize: 20 }} />
                  </div>
                  <span>Fin del servicio (500 horas)</span>
                </div>
              </div>
          </StyledCalendarContainer>

          {registrosHistorial.length > 0 ? (
            <Grow in timeout={500}>
              <StyledTableContainer component={Paper} sx={{ width: '100%', overflowX: 'auto' }}>
                <Table sx={{ minWidth: 650 }} size="small" aria-label="tabla de historial">
                  <TableHead>
                    <TableRow sx={{
                      background: 'linear-gradient(45deg, #2196F3 30%, #21CBF3 90%)',
                      '& th': {
                        color: 'white',
                        fontWeight: 'bold',
                        fontSize: '1rem'
                      }
                    }}>
                      <StyledTableCell className="header">Fecha</StyledTableCell>
                      <StyledTableCell className="header">Horario</StyledTableCell>
                      <StyledTableCell className="header">Tiempo</StyledTableCell>
                      <StyledTableCell className="header">Título</StyledTableCell>
                      <StyledTableCell className="header">Detalles</StyledTableCell>
                      <StyledTableCell className="header">Observaciones</StyledTableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {registrosHistorial.map((registro, index) => (
                      <StyledTableRow 
                        key={index} 
                        hover
                      >
                        <TableCell>
                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                            <Event color="primary" />
                            <Typography>{registro.fecha}</Typography>
                          </Box>
                        </TableCell>
                        <TableCell>
                          <Box sx={{ display: 'flex', flexDirection: 'column' }}>
                            <Typography variant="body2" color="primary">
                              Entrada: {registro.horaEntrada}
                            </Typography>
                            <Typography variant="body2" color="secondary">
                              Salida: {registro.horaSalida}
                            </Typography>
                          </Box>
                        </TableCell>
                        <TableCell>
                          {(() => {
                            const horas = parseFloat(registro.horasRealizadas);
                            const horasEnteras = Math.floor(horas);
                            const minutosDecimal = (horas - horasEnteras) * 60;
                            const minutos = Math.round(minutosDecimal);
                            return `${horasEnteras} horas y ${minutos} minutos`;
                          })()}
                        </TableCell>
                        <TableCell>{registro.titulo}</TableCell>
                        <TableCell sx={{ maxWidth: 220, whiteSpace: 'pre-line', overflow: 'hidden', textOverflow: 'ellipsis', wordBreak: 'break-word' }}>
                          {registro.descripcion}
                        </TableCell>
                        <TableCell sx={{ maxWidth: 220, whiteSpace: 'pre-line', overflow: 'hidden', textOverflow: 'ellipsis', wordBreak: 'break-word' }}>
                          {registro.observaciones}
                        </TableCell>
                      </StyledTableRow>
                    ))}
                    <TableRow>
                      <TableCell colSpan={3}>
                        <Typography variant="subtitle1" fontWeight="bold">
                          Total de horas:
                        </Typography>
                      </TableCell>
                      <TableCell>                          <Typography variant="subtitle1" fontWeight="bold">
                          {totalHoras()}
                        </Typography>
                      </TableCell>
                      <TableCell />
                      <TableCell />
                    </TableRow>
                  </TableBody>
                </Table>
              </StyledTableContainer>
            </Grow>
          ) : (
            <Typography variant="subtitle1" textAlign="center" sx={{ mt: 3 }}>
              No hay registros disponibles. Inicia tu primer registro para comenzar.
            </Typography>
          )}
        </Box>
      </Fade>

      <Fade in={mostrarDetalle}>
        <Box sx={{ display: mostrarDetalle ? 'block' : 'none' }}>
          <Paper sx={{ p: 3, borderRadius: 2 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', mb: 3 }}>
              <IconButton onClick={volverATabla} sx={{ mr: 2 }}>
                <ArrowBack />
              </IconButton>
              <Typography variant="h5">
                {formatearFecha(fechaSeleccionada)}
              </Typography>
            </Box>

            {registroSeleccionado ? (
              <Grow in timeout={500}>
                <Box>
                  <Grid container spacing={3}>
                    <Grid item xs={12} md={4}>
                      <Card>
                        <CardContent>
                          <Typography variant="subtitle2" color="textSecondary">
                            Hora de entrada
                          </Typography>
                          <Typography variant="h6">
                            {registroSeleccionado.horaEntrada}
                          </Typography>
                        </CardContent>
                      </Card>
                    </Grid>
                    <Grid item xs={12} md={4}>
                      <Card>
                        <CardContent>
                          <Typography variant="subtitle2" color="textSecondary">
                            Hora de salida
                          </Typography>
                          <Typography variant="h6">
                            {registroSeleccionado.horaSalida}
                          </Typography>
                        </CardContent>
                      </Card>
                    </Grid>
                    <Grid item xs={12} md={4}>
                      <Card>
                        <CardContent>
                          <Typography variant="subtitle2" color="textSecondary">
                            Horas realizadas
                          </Typography>
                          <Typography variant="h6">                            {(() => {
                              const horas = parseFloat(registroSeleccionado.horasRealizadas);
                              const horasEnteras = Math.floor(horas);
                              const minutosDecimal = (horas - horasEnteras) * 60;
                              const minutos = Math.round(minutosDecimal);
                              return `${horasEnteras} horas y ${minutos} minutos`;
                            })()}
                          </Typography>
                        </CardContent>
                      </Card>
                    </Grid>
                  </Grid>

                  {/* Detalles de actividades */}
                  <ActivityDetails registro={registroSeleccionado} />
                </Box>
              </Grow>
            ) : (
              <Typography variant="subtitle1">
                No hay registros para esta fecha
              </Typography>
            )}
          </Paper>
        </Box>
      </Fade>
    </Box>
  );
};

export default SessionHistory;
