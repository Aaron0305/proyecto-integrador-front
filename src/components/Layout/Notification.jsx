import React, { useState, useEffect, useContext } from 'react';
import { IconButton, Badge, Menu, MenuItem, Typography } from '@mui/material';
import NotificationsIcon from '@mui/icons-material/Notifications';
import { useNavigate } from 'react-router-dom';
import { io } from 'socket.io-client';
import useSound from 'use-sound';
import { AuthContext } from '../../contexts/AuthContext';
import notificationSound from '../../assets/notification.mp3';
import { API_ENV } from '../../config/api';

const Notification = () => {
    const { user } = useContext(AuthContext);
    const navigate = useNavigate();
    const [anchorEl, setAnchorEl] = useState(null);
    const [notifications, setNotifications] = useState([]);
    const [unreadCount, setUnreadCount] = useState(0);
    const [playNotification] = useSound(notificationSound);

    useEffect(() => {
        if (!user) return;

        // Conectar al servidor de Socket.IO
        const socket = io(API_ENV.SOCKET_URL);

        // Autenticar el socket con el ID del usuario
        socket.emit('authenticate', user._id);

        // Escuchar notificaciones
        socket.on('notification', (notification) => {
            setNotifications(prev => [notification, ...prev]);
            setUnreadCount(prev => prev + 1);
            playNotification(); // Reproducir sonido
        });

        return () => {
            socket.disconnect();
        };
    }, [user, playNotification]);

    const handleClick = (event) => {
        setAnchorEl(event.currentTarget);
        setUnreadCount(0); // Marcar como leídas al abrir
    };

    const handleClose = () => {
        setAnchorEl(null);
    };

    const handleNotificationClick = (notification) => {
        if (notification.type === 'NEW_ASSIGNMENT') {
            navigate(`/dashboard/assignments/${notification.data.assignmentId}`);
        }
        handleClose();
    };

    return (
        <>
            <IconButton
                size="large"
                color="inherit"
                onClick={handleClick}
                sx={{ mr: 1 }}
            >
                <Badge badgeContent={unreadCount} color="error">
                    <NotificationsIcon />
                </Badge>
            </IconButton>

            <Menu
                anchorEl={anchorEl}
                open={Boolean(anchorEl)}
                onClose={handleClose}
                PaperProps={{
                    style: {
                        maxHeight: 300,
                        width: 320,
                    },
                }}
            >
                {notifications.length === 0 ? (
                    <MenuItem disabled>
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
                                py: 1
                            }}
                        >
                            <Typography variant="subtitle2" fontWeight="bold">
                                {notification.title}
                            </Typography>
                            <Typography variant="body2">
                                {notification.message}
                            </Typography>
                            <Typography variant="caption" color="text.secondary">
                                {new Date(notification.timestamp).toLocaleString()}
                            </Typography>
                        </MenuItem>
                    ))
                )}
            </Menu>
        </>
    );
};

export default Notification; 