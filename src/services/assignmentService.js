import axios from 'axios';
import API_CONFIG from '../config/api';

const API_URL = `${API_CONFIG.baseURL}/assignments`;

// Configurar token de autorización
const getAuthHeaders = () => {
    const token = localStorage.getItem('token');
    return {
        headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json'
        }
    };
};

// Funciones para el admin
export const getAdminAllAssignments = async (params = {}) => {
    try {
        const queryParams = new URLSearchParams();
        
        // Agregar parámetros de filtrado y paginación
        Object.keys(params).forEach(key => {
            if (params[key] !== undefined && params[key] !== null && params[key] !== '') {
                queryParams.append(key, params[key]);
            }
        });
        
        const queryString = queryParams.toString();
        const url = queryString ? `${API_URL}/admin/all?${queryString}` : `${API_URL}/admin/all`;
        
        console.log('🔍 Making API request to:', url);
        console.log('📋 Query params:', params);
        
        const response = await axios.get(url, getAuthHeaders());
        return response.data;
    } catch (error) {
        throw error.response?.data || { message: 'Error al obtener las asignaciones' };
    }
};

export const getAdminAssignmentStats = async () => {
    try {
        const response = await axios.get(`${API_URL}/admin/stats`, getAuthHeaders());
        return response.data;
    } catch (error) {
        throw error.response?.data || { message: 'Error al obtener las estadísticas' };
    }
};

export const markAssignmentCompletedByAdmin = async (assignmentId) => {
    try {
        const response = await axios.patch(
            `${API_URL}/admin/${assignmentId}/complete`,
            {},
            getAuthHeaders()
        );
        return response.data;
    } catch (error) {
        throw error.response?.data || { message: 'Error al marcar como completada' };
    }
};

export const updateAssignmentByAdmin = async (assignmentId, assignmentData) => {
    try {
        const response = await axios.put(
            `${API_URL}/admin/${assignmentId}`,
            assignmentData,
            getAuthHeaders()
        );
        return response.data;
    } catch (error) {
        throw error.response?.data || { message: 'Error al actualizar la asignación' };
    }
};

// Nuevas funciones para gestión de estados de docentes
export const getTeachersStatusForAssignment = async (assignmentId) => {
    try {
        const response = await axios.get(
            `${API_URL}/${assignmentId}/teachers-status`,
            getAuthHeaders()
        );
        return response.data;
    } catch (error) {
        throw error.response?.data || { message: 'Error al obtener los estados de los docentes' };
    }
};

export const updateTeacherStatusInAssignment = async (assignmentId, teacherId, status) => {
    try {
        const response = await axios.patch(
            `${API_URL}/${assignmentId}/teacher-status`,
            { teacherId, status },
            getAuthHeaders()
        );
        return response.data;
    } catch (error) {
        throw error.response?.data || { message: 'Error al actualizar el estado del docente' };
    }
};

// Funciones para usuarios generales
export const getAllAssignments = async () => {
    try {
        const response = await axios.get(`${API_URL}/all`, getAuthHeaders());
        return response.data;
    } catch (error) {
        throw error.response?.data || { message: 'Error al obtener las asignaciones' };
    }
};

export const getUserAssignments = async () => {
    try {
        const response = await axios.get(`${API_URL}/my-assignments`, getAuthHeaders());
        return response.data;
    } catch (error) {
        throw error.response?.data || { message: 'Error al obtener mis asignaciones' };
    }
};

export const updateAssignmentStatus = async (assignmentId, status) => {
    try {
        const response = await axios.patch(
            `${API_URL}/${assignmentId}/status`,
            { status },
            getAuthHeaders()
        );
        return response.data;
    } catch (error) {
        throw error.response?.data || { message: 'Error al actualizar el estado' };
    }
};

export const getAssignmentById = async (assignmentId) => {
    try {
        const response = await axios.get(`${API_URL}/${assignmentId}`, getAuthHeaders());
        return response.data;
    } catch (error) {
        throw error.response?.data || { message: 'Error al obtener la asignación' };
    }
};

export const getUserDashboardStats = async () => {
    try {
        const response = await axios.get(`${API_URL}/dashboard-stats`, getAuthHeaders());
        return response.data;
    } catch (error) {
        throw error.response?.data || { message: 'Error al obtener las estadísticas del dashboard' };
    }
};

export const getFilteredAssignments = async (filters) => {
    try {
        const queryParams = new URLSearchParams(filters).toString();
        const response = await axios.get(`${API_URL}/filtered?${queryParams}`, getAuthHeaders());
        return response.data;
    } catch (error) {
        throw error.response?.data || { message: 'Error al obtener las asignaciones filtradas' };
    }
};

// Funciones para docentes
export const getTeacherAssignmentStats = async () => {
    try {
        const response = await axios.get(`${API_URL}/teacher/stats`, getAuthHeaders());
        return response.data;
    } catch (error) {
        throw error.response?.data || { message: 'Error al obtener las estadísticas del docente' };
    }
};

export const getTeacherFilteredAssignments = async (filters) => {
    try {
        const queryParams = new URLSearchParams(filters).toString();
        const response = await axios.get(`${API_URL}/teacher/assignments?${queryParams}`, getAuthHeaders());
        return response.data;
    } catch (error) {
        throw error.response?.data || { message: 'Error al obtener las asignaciones del docente' };
    }
};

// Alias para compatibilidad
export const getTeacherAssignments = getTeacherFilteredAssignments;

// Función para obtener estadísticas de todos los docentes
export const getAllTeachersStats = async () => {
    try {
        // Intentar obtener las estadísticas desde el backend
        const response = await axios.get(`${API_URL}/admin/teachers-stats`, getAuthHeaders());
        return response.data;
    } catch {
        console.log('Stats endpoint not available, returning empty data');
        // Si la ruta no existe, devolvemos datos vacíos sin errores
        return { success: true, stats: [] };
    }
};

export const markAssignmentCompleted = async (assignmentId) => {
    try {
        const response = await axios.patch(
            `${API_URL}/teacher/${assignmentId}/complete`,
            {},
            getAuthHeaders()
        );
        return response.data;
    } catch (error) {
        throw error.response?.data || { message: 'Error al marcar como completada' };
    }
};

// Función para crear asignaciones
export const createAssignment = async (assignmentData) => {
    try {
        const response = await axios.post(`${API_URL}/`, assignmentData, getAuthHeaders());
        return response.data;
    } catch (error) {
        throw error.response?.data || { message: 'Error al crear la asignación' };
    }
};

export default {
    getAdminAllAssignments,
    getAdminAssignmentStats,
    markAssignmentCompletedByAdmin,
    updateAssignmentByAdmin,
    getTeachersStatusForAssignment,
    updateTeacherStatusInAssignment,
    getAllAssignments,
    getUserAssignments,
    updateAssignmentStatus,
    getAssignmentById,
    getUserDashboardStats,
    getFilteredAssignments,
    getTeacherAssignmentStats,
    getTeacherFilteredAssignments,
    getTeacherAssignments,
    getAllTeachersStats,
    markAssignmentCompleted,
    createAssignment
};
